#!/usr/bin/env python3
"""Generate all formal evaluation plots for DFDOF thesis §6.

Usage:  python testing/generate_formal_plots.py
Reads:  testing/formal_output/   — state.json + timing_*.json per case
Writes: testing/formal_plots/    — PNG figures (9 plots)
"""
from __future__ import annotations

import json
import math
from pathlib import Path

import matplotlib
matplotlib.use('Agg')
import matplotlib.patches as mpatches
import matplotlib.colors as mcolors
import matplotlib.pyplot as plt
import numpy as np

# ── paths ─────────────────────────────────────────────────────────────────────
ROOT          = Path(r'C:\Users\Floris\Documents\DFDOF')
FORMAL_OUTPUT = ROOT / 'testing' / 'formal_output'
FORMAL_PLOTS  = ROOT / 'testing' / 'formal_plots'
FORMAL_PLOTS.mkdir(exist_ok=True)

# ── constants ─────────────────────────────────────────────────────────────────
PHASES = [
    'p1_provenance', 'p2_image_parsing', 'p3_artefact_extraction',
    'p4_decision_and_orchestration', 'p5_normalisation_and_anomaly_checking',
    'p6_multisource_correlation', 'p7_analysis_and_validation',
    'p8_automated_reporting',
]
P_LABELS = ['P1', 'P2', 'P3', 'P4', 'P5', 'P6', 'P7', 'P8']

ART_CATS   = ['account_data', 'databases', 'device_and_backup_info', 'drone_logs',
              'flight_logs', 'flight_records', 'images', 'videos']
ART_LABELS = ['Account\nData', 'Databases', 'Device &\nBackup', 'Drone\nLogs',
              'Flight\nLogs', 'Flight\nRecords', 'Images', 'Videos']
ART_COLORS = ['#4C72B0', '#DD8452', '#55A868', '#C44E52',
              '#8172B3', '#937860', '#DA8BC3', '#8C8C8C']

TOOLS_ORDER = ['sleuthkit', 'datcon', 'extractdji', 'exiftool', 'txtlogtocsv']
TOOL_LABELS = ['Sleuth Kit\n(mmls/fls/icat)', 'DatCon', 'ExtractDJI', 'ExifTool', 'TXTlogToCSV']
TSK_NAMES   = {'mmls', 'fls', 'icat'}
KNOWN_TOOLS = {'datcon', 'extractdji', 'exiftool', 'txtlogtocsv'}
# tool_name values in state.json that differ from the bucket key
_TOOL_NAME_ALIASES = {'txtlogtocsvtool': 'txtlogtocsv'}

ID_FIELDS  = ['drone_serial', 'drone_name', 'device_name', 'device_platform',
              'firmware_version', 'account_email', 'dji_app_version', 'installed_dji_apps']
ID_LABELS  = ['Drone\nSerial', 'Drone\nName', 'Device\nName', 'Device\nPlatform',
              'Firmware\nVersion', 'Account\nEmail', 'App\nVersion', 'Installed\nApps']

SHORT = {
    'ft-df002-2017-android':      'df002-android',
    'ft-df002-2017-ios':          'df002-ios',
    'ft-df003-2017-ios':          'df003-ios',
    'ft-df004-2017-sd-only':      'df004-sd',
    'ft-df006-2017-android':      'df006-android',
    'ft-df006-2017-ios':          'df006-ios',
    'ft-df019-2017-android-only': 'df019-android',
    'ft-df019-2017-ios':          'df019-ios+sd',
    'ft-df019-2017-ios-only':     'df019-ios-only',
    'ft-df019-2018-ios':          'df019-18-ios',
    'ft-df020-2017-android':      'df020-17-and',
    'ft-df020-2017-ios':          'df020-17-ios',
    'ft-df020-2018-android':      'df020-18-and',
    'ft-df049-2018-apr-android':  'df049-android',
    'ft-df049-2018-apr-ios':      'df049-ios',
    'ft-df050-2018-android':      'df050-android',
}

COMBO_ORDER = {
    'Drone SD only':           0,
    'Controller only':         1,
    'Controller + SD':         2,
    'Controller + Flight':     3,
    'Controller + SD + Flight':4,
}
COMBO_COLORS = {
    'Drone SD only':           '#E9724C',
    'Controller only':         '#C5283D',
    'Controller + SD':         '#255F85',
    'Controller + Flight':     '#6A0572',
    'Controller + SD + Flight':'#1B998B',
}

DPI = 180

# ── helpers ───────────────────────────────────────────────────────────────────

def fmt_mmss(s: float) -> str:
    return f'{int(s) // 60}:{int(s) % 60:02d}'


def classify_src(input_evidence: list[dict]) -> str:
    types: set[str] = set()
    for e in input_evidence:
        s = (e.get('source_identification') or '').lower()
        if s.startswith('drone_sd'):
            types.add('sd')
        elif 'ios' in s or 'android' in s:
            types.add('ctrl')
        elif 'flight' in s:
            types.add('flight')
    has_ctrl  = 'ctrl'   in types
    has_sd    = 'sd'     in types
    has_flt   = 'flight' in types
    if not has_ctrl and has_sd  and not has_flt: return 'Drone SD only'
    if has_ctrl     and not has_sd and not has_flt: return 'Controller only'
    if has_ctrl     and has_sd  and not has_flt: return 'Controller + SD'
    if has_ctrl     and not has_sd and has_flt:  return 'Controller + Flight'
    if has_ctrl     and has_sd  and has_flt:     return 'Controller + SD + Flight'
    return 'Other'


def id_val(ada: dict, key: str) -> str:
    entry = ada.get(key, {})
    if isinstance(entry, dict):
        v = entry.get('value', '')
        if isinstance(v, list):
            return '; '.join(str(x) for x in v) if v else ''
        return str(v) if v else ''
    return ''


def count_tools(log: list[dict]) -> dict[str, int]:
    c: dict[str, int] = {t: 0 for t in TOOLS_ORDER}
    for e in log:
        n = e.get('tool_name', '')
        n = _TOOL_NAME_ALIASES.get(n, n)   # normalise e.g. txtlogtocsvtool → txtlogtocsv
        if n in TSK_NAMES:
            c['sleuthkit'] += 1
        elif n in KNOWN_TOOLS:
            c[n] += 1
    return c


def cat_counts_p7(artefact_coverage: list[dict]) -> dict[str, int]:
    c = {cat: 0 for cat in ART_CATS}
    for entry in artefact_coverage:
        cat = entry.get('category', '')
        if cat in c:
            c[cat] = entry.get('count', 0)
    return c


def media_counts(p3: list[dict], p5: list[dict]) -> tuple[int, int, int]:
    mc = sum(1 for a in p3 if a.get('artefact_category') in {'images', 'videos'})
    gps = norm = 0
    for entry in p5:
        if entry.get('evidence_category') not in {'images', 'videos'}:
            continue
        for obs in entry.get('observations', []):
            if obs.get('gps_latitude') is not None:
                gps += 1
            if obs.get('norm_date') is not None:
                norm += 1
    return mc, gps, norm


def save(fig: plt.Figure, fname: str) -> None:
    out = FORMAL_PLOTS / fname
    fig.savefig(out, dpi=DPI, bbox_inches='tight')
    plt.close(fig)
    print(f'  saved  {fname}')

# ── data loading ──────────────────────────────────────────────────────────────

def load_cases() -> list[dict]:
    cases = []
    for d in sorted(FORMAL_OUTPUT.iterdir()):
        name = d.name
        if not name.startswith('ft-') or name.endswith('-2'):
            continue
        sj = d / 'state.json'
        if not sj.exists():
            continue

        state  = json.loads(sj.read_text('utf-8'))
        tf     = list(d.glob('timing_*.json'))
        timing = json.loads(tf[0].read_text('utf-8')) if tf else {}

        po = state.get('phase_outputs', {})
        p7 = po.get('p7_analysis_and_validation', {})
        p6 = po.get('p6_multisource_correlation', {})
        p3 = po.get('p3_artefact_extraction', {}).get('extracted_artefacts', [])
        p5 = po.get('p5_normalisation_and_anomaly_checking', {}).get('derived_anomalies', [])

        cs      = p7.get('coverage_score', {})
        src_det = cs.get('evidence_sources_detected', {})
        art_det = cs.get('artefact_categories_with_data', {})
        flt_det = cs.get('flights_with_primary_correlation', {})
        tol_det = cs.get('tools_succeeded', {})

        raw_phases = timing.get('phases', {})
        pdur = {ph: raw_phases.get(ph, {}).get('duration_s', 0.0) for ph in PHASES}

        fbc: dict[str, int] = {'high': 0, 'medium': 0, 'low': 0, 'unmatched': 0}
        for f in p6.get('flights', []):
            corr = f.get('correlation', {})
            if corr.get('matched', False):
                conf = corr.get('confidence', 'low')
                fbc[conf] = fbc.get(conf, 0) + 1
            else:
                fbc['unmatched'] += 1

        mc, mgps, mnorm = media_counts(p3, p5)
        ada      = p7.get('account_and_drone_analysis', {})
        identity = {f: bool(id_val(ada, f)) for f in ID_FIELDS}

        total_art = len(p3)
        uncorr    = len(p7.get('uncorrelated_artefacts', []))
        corr_art  = total_art - uncorr

        ft = flt_det.get('total', 0)
        fv = flt_det.get('value', 0)
        tt = tol_det.get('total', 0)
        tv = tol_det.get('value', 0)

        cases.append({
            'name':       name,
            'short':      SHORT.get(name, name),
            'combo':      classify_src(state.get('input_evidence', [])),
            'pdur':       pdur,
            'total_s':    timing.get('total_seconds', 0.0),
            'auto_s':     timing.get('automated_seconds', 0.0),
            'src_ratio':  src_det.get('value', 0) / max(src_det.get('total', 4), 1),
            'art_ratio':  art_det.get('value', 0) / max(art_det.get('total', 7), 1),
            'flt_ratio':  fv / ft if ft > 0 else float('nan'),
            'tol_ratio':  tv / tt if tt > 0 else 1.0,
            'gps_ratio':  mgps / mc if mc > 0 else float('nan'),
            'norm_ratio': mnorm / mc if mc > 0 else float('nan'),
            'corr_ratio': corr_art / total_art if total_art > 0 else 0.0,
            'flights_by_conf': fbc,
            'flights_total':   ft,
            'media_count': mc,
            'identity':    identity,
            'id_count':    sum(identity.values()),
            'total_art':   total_art,
            'corr_art':    corr_art,
            'tool_counts': count_tools(state.get('tool_invocation_log', [])),
            'cat_counts':  cat_counts_p7(p7.get('artefact_coverage', [])),
        })

    cases.sort(key=lambda c: (COMBO_ORDER.get(c['combo'], 9), c['name']))
    return cases

# ── plots ─────────────────────────────────────────────────────────────────────

def _combo_strip(ax: plt.Axes, cases: list[dict]) -> None:
    """Draw coloured source-combination strip on the left of a heatmap row axis."""
    for i, c in enumerate(cases):
        ax.add_patch(mpatches.FancyBboxPatch(
            (-0.47, i - 0.45), 0.37, 0.90,
            boxstyle='round,pad=0', color=COMBO_COLORS.get(c['combo'], '#888'),
        ))


def _combo_legend(fig: plt.Figure) -> None:
    handles = [mpatches.Patch(color=v, label=k) for k, v in COMBO_COLORS.items()]
    fig.legend(handles=handles, title='Source combination', loc='lower center',
               ncol=3, bbox_to_anchor=(0.5, -0.03), fontsize=8, title_fontsize=8,
               framealpha=0.9)


# ── Plot 01: Phase timing heatmap ─────────────────────────────────────────────

def plot_01_phase_heatmap(cases: list[dict]) -> None:
    labels   = [c['short'] for c in cases]
    data     = np.array([[c['pdur'].get(ph, 0.0) for ph in PHASES] for c in cases])
    log_data = np.log1p(data)

    fig, ax = plt.subplots(figsize=(13, 9.5))
    im = ax.imshow(log_data, aspect='auto', cmap='Blues', vmin=0, vmax=log_data.max())

    ax.set_xticks(range(len(PHASES)))
    ax.set_xticklabels(P_LABELS, fontsize=11, fontweight='bold')
    ax.set_yticks(range(len(cases)))
    ax.set_yticklabels(labels, fontsize=8.5)

    for i, case in enumerate(cases):
        for j, ph in enumerate(PHASES):
            s = case['pdur'].get(ph, 0.0)
            if s < 0.5:
                txt, col = '—', '#aaaaaa'
            else:
                txt = fmt_mmss(s)
                col = 'white' if log_data[i, j] > log_data.max() * 0.52 else 'black'
            ax.text(j, i, txt, ha='center', va='center', fontsize=7.5, color=col)

    _combo_strip(ax, cases)
    ax.set_xlim(-0.5, len(PHASES) - 0.5)

    cbar = fig.colorbar(im, ax=ax, fraction=0.025, pad=0.01)
    cbar.set_label('log(seconds + 1)', fontsize=8)
    cbar.ax.tick_params(labelsize=7)

    ax.set_title('Pipeline Phase Duration per Case  (mm:ss · log-scaled colour)', fontsize=12, pad=10)
    ax.set_xlabel('Pipeline Phase', fontsize=10)
    _combo_legend(fig)
    fig.tight_layout()
    fig.subplots_adjust(bottom=0.065)
    save(fig, '01_phase_timing_heatmap.png')


# ── Plot 02: Automated time by source combination ─────────────────────────────

def plot_02_auto_time_by_combo(cases: list[dict]) -> None:
    combos = [k for k in COMBO_ORDER if any(c['combo'] == k for c in cases)]
    groups = {k: [c for c in cases if c['combo'] == k] for k in combos}

    # Two-panel layout: chart left, legend right
    fig = plt.figure(figsize=(15, 6.5), layout='constrained')
    gs  = fig.add_gridspec(1, 2, width_ratios=[3, 1], wspace=0.04)
    ax     = fig.add_subplot(gs[0])
    ax_leg = fig.add_subplot(gs[1])

    global_n = 0
    legend_entries: list[tuple[int, str, str, str]] = []  # (n, short, color, combo)

    for xi, combo in enumerate(combos):
        grp    = groups[combo]
        times  = [c['auto_s'] / 60 for c in grp]
        mean_t = np.mean(times)
        color  = COMBO_COLORS[combo]

        ax.bar(xi, mean_t, color=color, alpha=0.30, width=0.55, zorder=1)
        ax.plot([xi - 0.27, xi + 0.27], [mean_t, mean_t], color=color, lw=2.5, zorder=3)
        ax.text(xi, mean_t + 0.05, f'{mean_t:.1f} min', ha='center',
                va='bottom', fontsize=8, fontweight='bold', color=color)

        for i, (t, case) in enumerate(zip(times, grp)):
            global_n += 1
            jitter = (i - (len(times) - 1) / 2) * 0.08
            ax.scatter(xi + jitter, t, color=color, s=120, zorder=4,
                       edgecolors='white', linewidths=0.9)
            # Number inside the dot
            ax.text(xi + jitter, t, str(global_n), ha='center', va='center',
                    fontsize=7, fontweight='bold', color='white', zorder=5)
            legend_entries.append((global_n, case['short'], color, combo))

    ax.set_xticks(range(len(combos)))
    ax.set_xticklabels([c.replace(' + ', '\n+ ') for c in combos], fontsize=9)
    ax.set_ylabel('Automated pipeline time (minutes, P4 excluded)', fontsize=10)
    ax.set_title('Automated Pipeline Time by Evidence Source Combination', fontsize=12)
    ax.set_ylim(bottom=0)
    ax.grid(axis='y', alpha=0.3)

    # ── Legend panel ──
    ax_leg.set_xlim(0, 1)
    ax_leg.set_ylim(0, 1)
    ax_leg.axis('off')

    STEP        = 0.041   # vertical step between case rows
    HEADER_GAP  = 0.016   # extra gap above each combo header
    y           = 0.98
    prev_combo  = None

    for n, short, color, combo in legend_entries:
        if combo != prev_combo:
            if prev_combo is not None:
                y -= HEADER_GAP
            # Combo header
            ax_leg.text(0.03, y, combo, fontsize=7.5, fontweight='bold',
                        color=color, va='top')
            y -= (STEP + 0.006)
            prev_combo = combo

        # Dot with number
        ax_leg.scatter([0.07], [y], color=color, s=80, zorder=4,
                       edgecolors='white', linewidths=0.6)
        ax_leg.text(0.07, y, str(n), ha='center', va='center',
                    fontsize=6.5, fontweight='bold', color='white', zorder=5)
        # Case name
        ax_leg.text(0.17, y, short, fontsize=8, va='center', color='#333')
        y -= STEP

    save(fig, '02_auto_time_by_source_combination.png')


# ── Plot 03: Time-to-Insight ──────────────────────────────────────────────────

def plot_03_time_to_insight(cases: list[dict]) -> None:
    bench = next((c for c in cases if c['name'] == 'ft-df019-2017-ios'), None)
    if bench is None:
        print('  [skip] benchmark case ft-df019-2017-ios not found')
        return

    auto_min   = bench['total_s'] / 60   # full pipeline including P4 (no DatCon here)
    manual_mid = 360.0                   # 6 h midpoint in minutes
    manual_lo  = 240.0                   # 4 h lower bound
    manual_hi  = 480.0                   # 8 h upper bound
    factor     = manual_mid / auto_min

    fig, ax = plt.subplots(figsize=(10, 3.5))

    # Manual bar
    ax.barh(1, manual_mid, color='#C44E52', alpha=0.75, height=0.38, zorder=2)
    ax.barh(1, manual_hi - manual_lo, left=manual_lo,
            color='#C44E52', alpha=0.20, height=0.38, zorder=1)
    ax.plot([manual_lo, manual_lo], [0.81, 1.19], color='#C44E52', lw=1.5)
    ax.plot([manual_hi, manual_hi], [0.81, 1.19], color='#C44E52', lw=1.5)
    ax.annotate(f'~{manual_mid / 60:.0f} h  (range 4–8 h)',
                xy=(manual_mid, 1), xytext=(8, 0), textcoords='offset points',
                fontsize=10, va='center', color='#C44E52')

    # Automated bar
    ax.barh(0, auto_min, color='#255F85', alpha=0.85, height=0.38, zorder=2)
    ax.annotate(f'{auto_min:.1f} min  ({bench["total_s"]:.0f} s total)',
                xy=(auto_min, 0), xytext=(8, 0), textcoords='offset points',
                fontsize=10, va='center', color='#255F85')

    ax.set_xscale('log')
    ax.set_xlim(0.8, 1200)
    ax.set_yticks([0, 1])
    ax.set_yticklabels(['DFDOF\n(automated)', 'Manual\n(estimated)'], fontsize=11)
    ax.set_xlabel('Duration (minutes, log scale)', fontsize=10)
    ax.set_title(
        f'Time-to-Insight: DFDOF vs Manual Investigation  '
        f'(benchmark: df019-2017-ios  ·  ×{factor:.0f} efficiency gain)',
        fontsize=11,
    )
    ax.grid(axis='x', alpha=0.3, which='both')
    for v, lbl in [(1, '1 min'), (60, '1 h'), (480, '8 h')]:
        ax.axvline(v, color='grey', lw=0.7, linestyle='--', alpha=0.45)
        ax.text(v, -0.62, lbl, fontsize=7.5, ha='center', color='grey')

    fig.tight_layout()
    save(fig, '03_time_to_insight.png')


# ── Plot 04: Extended coverage heatmap ────────────────────────────────────────

def _cell_color(val: float) -> str:
    """White text for high scores, black otherwise."""
    return 'white' if val >= 0.7 else 'black'


def plot_04_coverage_heatmap(cases: list[dict]) -> None:
    DIM_KEYS   = ['src_ratio', 'art_ratio', 'flt_ratio', 'tol_ratio',
                  'gps_ratio', 'norm_ratio', 'corr_ratio']
    DIM_LABELS = ['Sources\nDetected', 'Artefact\nCategories', 'Flights\nCorrelated',
                  'Tools\nSuccessful', 'Media\nwith GPS', 'Media\nNorm.\nTimestamp',
                  'Artefacts\nCorrelated', 'Weighted\nAverage']

    labels = [c['short'] for c in cases]
    data   = np.array([[c.get(k, float('nan')) for k in DIM_KEYS] for c in cases])  # 16×7

    # Per-case weighted score: mean across all 7 dims, NaN → 0
    case_scores = np.nan_to_num(data, nan=0.0).mean(axis=1)   # shape (16,)

    # Summary row: mean per dimension across all cases, NaN → 0
    summary = np.nan_to_num(data, nan=0.0).mean(axis=0)        # shape (7,)
    overall = case_scores.mean()                                # scalar corner cell

    # Build full 17×8 matrix
    data_full  = np.vstack([data, summary[np.newaxis, :]])                      # 17×7
    score_col  = np.append(case_scores, overall)[:, np.newaxis]                 # 17×1
    data_ws    = np.hstack([data_full, score_col])                              # 17×8

    cmap = plt.get_cmap('RdYlGn').copy()
    cmap.set_bad('#cccccc')
    masked = np.ma.masked_invalid(data_ws)

    n_rows   = len(cases) + 1    # 17
    n_dims   = len(DIM_KEYS)     # 7  — dimension columns
    n_cols   = len(DIM_LABELS)   # 8  — 7 dims + 1 score column
    score_j  = n_cols - 1        # index 7 — weighted average column

    fig, ax = plt.subplots(figsize=(14.0, 10.5))
    im = ax.imshow(masked, aspect='auto', cmap=cmap, vmin=0, vmax=1)

    ax.set_xticks(range(n_cols))
    ax.set_xticklabels(DIM_LABELS, fontsize=9)
    ax.set_yticks(range(n_rows))
    ax.set_yticklabels(labels + ['Mean\n(all cases)'], fontsize=8.5)
    ax.get_yticklabels()[-1].set_fontweight('bold')
    ax.get_xticklabels()[-1].set_fontweight('bold')

    # Case rows — dimension cells (cols 0–6)
    for i, case in enumerate(cases):
        for j, key in enumerate(DIM_KEYS):   # 7 dims → cols 0–6
            val = case.get(key, float('nan'))
            if math.isnan(val):
                txt, col = 'n/a', '#666666'
            else:
                txt = f'{val:.0%}'
                col = _cell_color(val)
            ax.text(j, i, txt, ha='center', va='center', fontsize=8.5, color=col)
        # Weighted average column (col 7), bold
        v = case_scores[i]
        ax.text(score_j, i, f'{v:.0%}', ha='center', va='center',
                fontsize=9, color=_cell_color(v), fontweight='bold')

    # Summary row (row 16) — dimension cells
    for j, v in enumerate(summary):
        ax.text(j, n_rows - 1, f'{v:.0%}', ha='center', va='center',
                fontsize=9, color=_cell_color(v), fontweight='bold')
    # Corner cell: overall weighted average
    ax.text(score_j, n_rows - 1, f'{overall:.0%}', ha='center', va='center',
            fontsize=9, color=_cell_color(overall), fontweight='bold')

    # Separators: horizontal (before summary row) + vertical (before score col)
    ax.axhline(len(cases) - 0.5, color='white', lw=3, zorder=5)
    ax.axvline(score_j - 0.5,    color='white', lw=3, zorder=5)

    _combo_strip(ax, cases)
    ax.set_xlim(-0.5, n_cols - 0.5)

    cbar = fig.colorbar(im, ax=ax, fraction=0.022, pad=0.01)
    cbar.set_label('0 = none  →  1 = complete', fontsize=8)
    cbar.ax.tick_params(labelsize=7)
    ax.set_title('Extended Coverage Dimensions per Case  (grey = not applicable)',
                 fontsize=12, pad=10)
    _combo_legend(fig)
    fig.tight_layout()
    fig.subplots_adjust(bottom=0.1)
    save(fig, '04_extended_coverage_heatmap.png')


# ── Plot 05: Source combination outcome matrix ────────────────────────────────

def plot_05_combo_outcome_matrix(cases: list[dict]) -> None:
    combos = [k for k in COMBO_ORDER if any(c['combo'] == k for c in cases)]
    METRICS  = ['total_art', 'corr_art', 'id_count', 'flights_total']
    M_LABELS = ['Mean Total\nArtefacts', 'Mean Correlated\nArtefacts',
                'Mean Identity\nFields (of 8)', 'Mean Flights\n(total)']

    # Means per combo
    matrix: list[list[float]] = []
    counts: list[int] = []
    for combo in combos:
        grp = [c for c in cases if c['combo'] == combo]
        matrix.append([float(np.mean([c[m] for c in grp])) for m in METRICS])
        counts.append(len(grp))

    mat = np.array(matrix)
    col_max = np.nanmax(mat, axis=0)
    col_max[col_max == 0] = 1
    norm_mat = mat / col_max

    fig, ax = plt.subplots(figsize=(10, max(3, len(combos) * 0.9 + 1.2)))
    im = ax.imshow(norm_mat, aspect='auto', cmap='YlGnBu', vmin=0, vmax=1)

    ax.set_xticks(range(len(METRICS)))
    ax.set_xticklabels(M_LABELS, fontsize=9)
    ax.set_yticks(range(len(combos)))
    ax.set_yticklabels([f'{c}  (n={counts[i]})' for i, c in enumerate(combos)], fontsize=9)

    for i in range(len(combos)):
        for j, m in enumerate(METRICS):
            val = mat[i, j]
            txt = f'{val:.1f}/8' if m == 'id_count' else f'{val:.1f}'
            col = 'white' if norm_mat[i, j] > 0.55 else 'black'
            ax.text(j, i, txt, ha='center', va='center', fontsize=9.5, color=col)

    cbar = fig.colorbar(im, ax=ax, fraction=0.03, pad=0.01)
    cbar.set_label('Relative to column maximum', fontsize=8)
    cbar.ax.tick_params(labelsize=7)
    ax.set_title('Average Forensic Outcomes by Evidence Source Combination', fontsize=12)
    fig.tight_layout()
    save(fig, '05_source_combination_outcome_matrix.png')


# ── Plot 06: Flight correlation bar ──────────────────────────────────────────

def plot_06_flight_correlation(cases: list[dict]) -> None:
    flight_cases = [c for c in cases if sum(c['flights_by_conf'].values()) > 0]
    if not flight_cases:
        print('  [skip] no cases with flights')
        return

    labels = [c['short'] for c in flight_cases]
    high   = np.array([c['flights_by_conf']['high']      for c in flight_cases])
    medium = np.array([c['flights_by_conf']['medium']    for c in flight_cases])
    low    = np.array([c['flights_by_conf']['low']       for c in flight_cases])
    unmatch= np.array([c['flights_by_conf']['unmatched'] for c in flight_cases])

    x = np.arange(len(flight_cases))
    w = 0.55
    fig, ax = plt.subplots(figsize=(max(10, len(flight_cases) * 1.0), 5.5))

    b1 = ax.bar(x, high,   width=w, color='#2ca02c', label='Matched — High confidence')
    b2 = ax.bar(x, medium, width=w, bottom=high, color='#ff7f0e', label='Matched — Medium confidence')
    b3 = ax.bar(x, low,    width=w, bottom=high + medium, color='#ffdd57', label='Matched — Low confidence')
    b4 = ax.bar(x, unmatch,width=w, bottom=high + medium + low,
                color='#d62728', alpha=0.55, label='Unmatched')

    # Annotate counts inside bars
    for bars, vals, bottoms in [
        (b1, high, np.zeros(len(x))),
        (b2, medium, high),
        (b3, low, high + medium),
        (b4, unmatch, high + medium + low),
    ]:
        for xi, (v, b) in enumerate(zip(vals, bottoms)):
            if v > 0:
                ax.text(xi, b + v / 2, str(int(v)), ha='center', va='center',
                        fontsize=9, fontweight='bold', color='white')

    ax.set_xticks(x)
    ax.set_xticklabels(labels, rotation=35, ha='right', fontsize=9)
    ax.set_ylabel('Number of Flights', fontsize=10)
    ax.set_title('Multi-Source Flight Correlation Results per Case', fontsize=12)
    ax.legend(fontsize=9, loc='upper right')
    ax.yaxis.set_major_locator(plt.MaxNLocator(integer=True))
    ax.grid(axis='y', alpha=0.3)
    fig.tight_layout()
    save(fig, '06_flight_correlation.png')


# ── Plot 07: Stacked artefact bar ─────────────────────────────────────────────

def plot_07_artefact_bar(cases: list[dict]) -> None:
    labels = [c['short'] for c in cases]
    x      = np.arange(len(cases))
    w      = 0.65

    fig, ax = plt.subplots(figsize=(14, 6.5))
    bottoms = np.zeros(len(cases))

    for cat, color, label in zip(ART_CATS, ART_COLORS, ART_LABELS):
        vals = np.array([c['cat_counts'].get(cat, 0) for c in cases], dtype=float)
        ax.bar(x, vals, bottom=bottoms, width=w, color=color,
               label=label.replace('\n', ' '))
        for xi, (v, b) in enumerate(zip(vals, bottoms)):
            if v >= 2:
                ax.text(xi, b + v / 2, str(int(v)), ha='center', va='center',
                        fontsize=7, color='white', fontweight='bold')
        bottoms += vals

    # Total label on top
    for xi, total in enumerate(bottoms):
        ax.text(xi, total + 0.4, str(int(total)), ha='center', va='bottom',
                fontsize=7.5, color='#333')

    ax.set_xticks(x)
    ax.set_xticklabels(labels, rotation=38, ha='right', fontsize=8)
    ax.set_ylabel('Artefact Count (P3 extracted)', fontsize=10)
    ax.set_title('Extracted Artefacts by Category per Case', fontsize=12)
    ax.legend(loc='upper right', fontsize=8, ncol=2, framealpha=0.9)
    ax.grid(axis='y', alpha=0.25)
    fig.tight_layout()
    save(fig, '07_artefact_stacked_bar.png')


# ── Plot 08: Tool invocation heatmap ─────────────────────────────────────────

def plot_08_tool_heatmap(cases: list[dict]) -> None:
    labels   = [c['short'] for c in cases]
    data     = np.array([[c['tool_counts'].get(t, 0) for t in TOOLS_ORDER]
                         for c in cases], dtype=float)
    log_data = np.log1p(data)

    fig, ax = plt.subplots(figsize=(11, 10))
    im = ax.imshow(log_data, aspect='auto', cmap='Blues',
                   vmin=0, vmax=log_data.max())

    ax.set_xticks(range(len(TOOLS_ORDER)))
    ax.set_xticklabels(TOOL_LABELS, fontsize=9)
    ax.set_yticks(range(len(cases)))
    ax.set_yticklabels(labels, fontsize=8.5)

    for i, case in enumerate(cases):
        for j, tool in enumerate(TOOLS_ORDER):
            v = case['tool_counts'].get(tool, 0)
            txt = str(v) if v > 0 else '—'
            col = 'white' if log_data[i, j] > log_data.max() * 0.52 else (
                  '#aaaaaa' if v == 0 else 'black')
            ax.text(j, i, txt, ha='center', va='center', fontsize=8.5, color=col)

    _combo_strip(ax, cases)
    ax.set_xlim(-0.5, len(TOOLS_ORDER) - 0.5)

    cbar = fig.colorbar(im, ax=ax, fraction=0.025, pad=0.01)
    cbar.set_label('log(count + 1)', fontsize=8)
    cbar.ax.tick_params(labelsize=7)
    ax.set_title('Forensic Tool Invocation Count per Case  (log-scaled colour)', fontsize=12, pad=10)
    _combo_legend(fig)
    fig.tight_layout()
    fig.subplots_adjust(bottom=0.065)
    save(fig, '08_tool_invocation_heatmap.png')


# ── Plot 09: Identity field extraction heatmap ────────────────────────────────

def plot_09_identity_heatmap(cases: list[dict]) -> None:
    labels = [c['short'] for c in cases]
    data   = np.array([[1.0 if c['identity'].get(f, False) else 0.0 for f in ID_FIELDS]
                       for c in cases])

    cmap  = mcolors.ListedColormap(['#e0e0e0', '#2ca02c'])
    norm  = mcolors.BoundaryNorm([-0.5, 0.5, 1.5], cmap.N)

    fig, ax = plt.subplots(figsize=(13, 8.5))
    ax.imshow(data, aspect='auto', cmap=cmap, norm=norm)

    ax.set_xticks(range(len(ID_FIELDS)))
    ax.set_xticklabels(ID_LABELS, fontsize=9, rotation=20, ha='right')
    ax.set_yticks(range(len(cases)))
    ax.set_yticklabels(labels, fontsize=8.5)

    for i, case in enumerate(cases):
        for j, field in enumerate(ID_FIELDS):
            found = case['identity'].get(field, False)
            ax.text(j, i, '✓' if found else '✗',
                    ha='center', va='center', fontsize=10,
                    color='white' if found else '#999999')

    # Total count column to the right
    for i, case in enumerate(cases):
        ax.text(len(ID_FIELDS) + 0.15, i, f'{case["id_count"]}/8',
                va='center', fontsize=8.5, color='#333')
    ax.text(len(ID_FIELDS) + 0.15, -0.75, 'Total',
            va='center', fontsize=8.5, fontweight='bold', color='#333')
    ax.set_xlim(-0.5, len(ID_FIELDS) + 0.65)

    _combo_strip(ax, cases)

    handles = [
        mpatches.Patch(color='#2ca02c', label='Field extracted'),
        mpatches.Patch(color='#e0e0e0', label='Not found / N/A'),
    ] + [mpatches.Patch(color=v, label=k) for k, v in COMBO_COLORS.items()]
    fig.legend(handles=handles, loc='lower center', ncol=4,
               bbox_to_anchor=(0.5, -0.04), fontsize=8, framealpha=0.9)

    ax.set_title('Device and Drone Identity Field Extraction per Case', fontsize=12, pad=10)
    fig.tight_layout()
    save(fig, '09_identity_field_heatmap.png')


# ── main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    print('Loading cases...')
    cases = load_cases()
    print(f'  {len(cases)} cases loaded (sorted by source combination complexity)\n')
    for c in cases:
        print(f'  {c["short"]:<22}  {c["combo"]}')

    print('\nGenerating plots...')
    plot_01_phase_heatmap(cases)
    plot_02_auto_time_by_combo(cases)
    plot_03_time_to_insight(cases)
    plot_04_coverage_heatmap(cases)
    plot_05_combo_outcome_matrix(cases)
    plot_06_flight_correlation(cases)
    plot_07_artefact_bar(cases)
    plot_08_tool_heatmap(cases)
    plot_09_identity_heatmap(cases)

    print(f'\nDone. All plots written to:\n  {FORMAL_PLOTS}')


if __name__ == '__main__':
    main()
