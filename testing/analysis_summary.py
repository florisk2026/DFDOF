"""Print a structured data summary for thesis conclusions analysis."""
import json, math, statistics
from pathlib import Path

FORMAL_OUTPUT = Path('testing/formal_output')
ID_FIELDS = ['drone_serial','drone_name','device_name','device_platform',
             'firmware_version','account_email','dji_app_version','installed_dji_apps']
DIM_KEYS  = ['src_ratio','art_ratio','flt_ratio','tol_ratio',
             'gps_ratio','norm_ratio','corr_ratio']
PHASES    = ['p1_provenance','p2_image_parsing','p3_artefact_extraction',
             'p4_decision_and_orchestration','p5_normalisation_and_anomaly_checking',
             'p6_multisource_correlation','p7_analysis_and_validation','p8_automated_reporting']

def id_val(ada, key):
    e = ada.get(key, {})
    if isinstance(e, dict):
        v = e.get('value', '')
        return '; '.join(str(x) for x in v) if isinstance(v, list) else str(v) if v else ''
    return ''

def classify(input_ev):
    t = set()
    for e in input_ev:
        s = (e.get('source_identification') or '').lower()
        if s.startswith('drone_sd'): t.add('sd')
        elif 'ios' in s or 'android' in s: t.add('ctrl')
        elif 'flight' in s: t.add('flt')
    hc,hs,hf = 'ctrl' in t,'sd' in t,'flt' in t
    if not hc and hs and not hf: return 'SD only'
    if hc and not hs and not hf: return 'Ctrl only'
    if hc and hs and not hf:     return 'Ctrl+SD'
    if hc and not hs and hf:     return 'Ctrl+Flt'
    if hc and hs and hf:         return 'Ctrl+SD+Flt'
    return 'Other'

cases = []
for d in sorted(FORMAL_OUTPUT.iterdir()):
    if not d.name.startswith('ft-') or d.name.endswith('-2'): continue
    sj = d/'state.json'
    if not sj.exists(): continue
    state  = json.loads(sj.read_text('utf-8'))
    tf     = list(d.glob('timing_*.json'))
    timing = json.loads(tf[0].read_text('utf-8')) if tf else {}
    po = state.get('phase_outputs',{})
    p7 = po.get('p7_analysis_and_validation',{})
    p6 = po.get('p6_multisource_correlation',{})
    p3 = po.get('p3_artefact_extraction',{}).get('extracted_artefacts',[])
    p5 = po.get('p5_normalisation_and_anomaly_checking',{})
    cs = p7.get('coverage_score',{})
    ada= p7.get('account_and_drone_analysis',{})
    flights = p6.get('flights',[])
    matched = [f for f in flights if f.get('correlation',{}).get('matched',False)]
    pdur = {ph: timing.get('phases',{}).get(ph,{}).get('duration_s',0.0) for ph in PHASES}
    auto_s = timing.get('automated_seconds',0.0)
    total_s= timing.get('total_seconds',0.0)
    src_det= cs.get('evidence_sources_detected',{})
    art_det= cs.get('artefact_categories_with_data',{})
    flt_det= cs.get('flights_with_primary_correlation',{})
    tol_det= cs.get('tools_succeeded',{})
    mc = sum(1 for a in p3 if a.get('artefact_category') in {'images','videos'})
    mgps = mnorm = 0
    for entry in p5.get('derived_anomalies',[]):
        if entry.get('evidence_category') not in {'images','videos'}: continue
        for obs in entry.get('observations',[]):
            if obs.get('gps_latitude') is not None: mgps += 1
            if obs.get('norm_date') is not None: mnorm += 1
    uncorr = len(p7.get('uncorrelated_artefacts',[]))
    total_art = len(p3)
    id_found  = sum(bool(id_val(ada,f)) for f in ID_FIELDS)
    # confidence distribution
    conf_dist = {'high':0,'medium':0,'low':0}
    for f in matched:
        conf_dist[f.get('correlation',{}).get('confidence','low')] = \
            conf_dist.get(f.get('correlation',{}).get('confidence','low'),0)+1
    flt_total = flt_det.get('total',0)
    flt_corr  = flt_det.get('value',0)
    dims = [
        src_det.get('value',0)/max(src_det.get('total',4),1),
        art_det.get('value',0)/max(art_det.get('total',7),1),
        (flt_corr/flt_total) if flt_total>0 else 0.0,
        tol_det.get('value',0)/max(tol_det.get('total',1),1),
        (mgps/mc) if mc>0 else 0.0,
        (mnorm/mc) if mc>0 else 0.0,
        (total_art-uncorr)/total_art if total_art>0 else 0.0,
    ]
    weighted_avg = sum(dims)/len(dims)
    cases.append(dict(
        name=d.name.replace('ft-',''), combo=classify(state.get('input_evidence',[])),
        auto_s=auto_s, total_s=total_s, pdur=pdur,
        total_art=total_art, corr_art=total_art-uncorr,
        id_found=id_found, media_count=mc, mgps=mgps, mnorm=mnorm,
        flt_total=flt_total, flt_corr=flt_corr,
        matched_count=len(matched), conf_dist=conf_dist,
        weighted_avg=weighted_avg, dims=dims,
        src_v=src_det.get('value',0), src_t=src_det.get('total',4),
        art_v=art_det.get('value',0), art_t=art_det.get('total',7),
        tol_v=tol_det.get('value',0), tol_t=tol_det.get('total',0),
        anomalies=len(state.get('anomaly_flags',[])),
        tool_log=state.get('tool_invocation_log',[]),
    ))

cases.sort(key=lambda c: c['name'])
n = len(cases)

print("="*70)
print(f"DATASET: {n} cases\n")

print("── PER-CASE OVERVIEW ──────────────────────────────────────────────────")
print(f"{'Case':<26} {'Combo':<12} {'auto_s':>7} {'art':>4} {'corr':>5} "
      f"{'id':>3} {'flt':>7} {'wAvg':>6} {'anom':>5}")
for c in cases:
    flt_str = f"{c['flt_corr']}/{c['flt_total']}"
    print(f"{c['name']:<26} {c['combo']:<12} {c['auto_s']:>7.1f} "
          f"{c['total_art']:>4} {c['corr_art']:>5} {c['id_found']:>3} "
          f"{flt_str:>7} {c['weighted_avg']:>6.1%} {c['anomalies']:>5}")

print("\n── TIMING ─────────────────────────────────────────────────────────────")
auto_times = [c['auto_s'] for c in cases]
print(f"Automated time (seconds): min={min(auto_times):.1f}  max={max(auto_times):.1f}  "
      f"mean={statistics.mean(auto_times):.1f}  median={statistics.median(auto_times):.1f}")
auto_mins = [t/60 for t in auto_times]
print(f"Automated time (minutes): min={min(auto_mins):.1f}  max={max(auto_mins):.1f}  "
      f"mean={statistics.mean(auto_mins):.1f}  median={statistics.median(auto_mins):.1f}")
print("\nPhase mean durations (seconds):")
for ph in PHASES:
    vals = [c['pdur'][ph] for c in cases if c['pdur'][ph]>0]
    label = ph.replace('p','P').split('_')[0]
    if vals:
        print(f"  {label}: mean={statistics.mean(vals):.1f}  max={max(vals):.1f}  "
              f"(n={len(vals)} cases with >0s)")

print("\n── COVERAGE DIMENSIONS ────────────────────────────────────────────────")
dim_labels = ['Sources','Artefacts','Flights','Tools','GPS','NormTime','CorrArt']
for j,lbl in enumerate(dim_labels):
    vals = [c['dims'][j] for c in cases]
    print(f"  {lbl:<10}: mean={statistics.mean(vals):.1%}  "
          f"min={min(vals):.1%}  max={max(vals):.1%}")
wavgs = [c['weighted_avg'] for c in cases]
print(f"  {'WeightedAvg':<10}: mean={statistics.mean(wavgs):.1%}  "
      f"min={min(wavgs):.1%}  max={max(wavgs):.1%}")

print("\n── FLIGHT CORRELATION ─────────────────────────────────────────────────")
cases_with_flt = [c for c in cases if c['flt_total']>0]
print(f"Cases with ≥1 flight: {len(cases_with_flt)}/{n}")
total_flt   = sum(c['flt_total'] for c in cases)
total_corr  = sum(c['flt_corr']  for c in cases)
total_match = sum(c['matched_count'] for c in cases)
print(f"Flights total: {total_flt}  |  primary-correlated: {total_corr}  "
      f"|  any-matched: {total_match}")
high = sum(c['conf_dist']['high']   for c in cases)
med  = sum(c['conf_dist']['medium'] for c in cases)
low  = sum(c['conf_dist']['low']    for c in cases)
print(f"Confidence: high={high}  medium={med}  low={low}")
if total_match>0:
    print(f"High-confidence rate: {high/total_match:.1%}")

print("\n── ARTEFACT & IDENTITY ────────────────────────────────────────────────")
print(f"Total artefacts across all cases: {sum(c['total_art'] for c in cases)}")
print(f"Mean per case: {statistics.mean(c['total_art'] for c in cases):.1f}  "
      f"range {min(c['total_art'] for c in cases)}–{max(c['total_art'] for c in cases)}")
corr_rates = [c['corr_art']/c['total_art'] for c in cases if c['total_art']>0]
print(f"Correlated artefact ratio: mean={statistics.mean(corr_rates):.1%}  "
      f"min={min(corr_rates):.1%}  max={max(corr_rates):.1%}")
id_counts = [c['id_found'] for c in cases]
print(f"Identity fields found (of 8): mean={statistics.mean(id_counts):.1f}  "
      f"min={min(id_counts)}  max={max(id_counts)}")
all_8 = sum(1 for c in cases if c['id_found']==8)
zero  = sum(1 for c in cases if c['id_found']==0)
print(f"Cases with all 8 fields: {all_8}  |  cases with 0 fields: {zero}")

print("\n── MEDIA EXIF ─────────────────────────────────────────────────────────")
media_cases = [c for c in cases if c['media_count']>0]
print(f"Cases with media: {len(media_cases)}/{n}")
total_media = sum(c['media_count'] for c in cases)
total_gps   = sum(c['mgps']        for c in cases)
total_norm  = sum(c['mnorm']       for c in cases)
print(f"Total media files: {total_media}  "
      f"|  with GPS: {total_gps} ({total_gps/total_media:.1%})  "
      f"|  with norm timestamp: {total_norm} ({total_norm/total_media:.1%})")

print("\n── SOURCE COMBINATION BREAKDOWN ───────────────────────────────────────")
from collections import defaultdict
by_combo = defaultdict(list)
for c in cases: by_combo[c['combo']].append(c)
for combo, grp in sorted(by_combo.items()):
    wavg_m = statistics.mean(c['weighted_avg'] for c in grp)
    auto_m = statistics.mean(c['auto_s'] for c in grp)/60
    id_m   = statistics.mean(c['id_found'] for c in grp)
    print(f"  {combo:<12} n={len(grp)}  wAvg={wavg_m:.1%}  "
          f"auto={auto_m:.1f}min  id={id_m:.1f}/8")

print("\n── ANOMALIES ──────────────────────────────────────────────────────────")
anom_counts = [c['anomalies'] for c in cases]
print(f"Anomaly flags: min={min(anom_counts)}  max={max(anom_counts)}  "
      f"mean={statistics.mean(anom_counts):.1f}  total={sum(anom_counts)}")
