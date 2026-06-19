import json
from pathlib import Path

FORMAL_OUTPUT = Path('testing/formal_output')
ID_FIELDS = ['drone_serial','drone_name','device_name','device_platform',
             'firmware_version','account_email','dji_app_version','installed_dji_apps']

def id_val(ada, key):
    entry = ada.get(key, {})
    if isinstance(entry, dict):
        v = entry.get('value', '')
        if isinstance(v, list):
            return '; '.join(str(x) for x in v) if v else ''
        return str(v) if v else ''
    return ''

print(f"{'Case':<24}  {'auto_s':>7}  {'total':>6}  {'corr':>6}  {'id':>3}  {'flights':>7}")
for d in sorted(FORMAL_OUTPUT.iterdir()):
    if not d.name.startswith('ft-') or d.name.endswith('-2'):
        continue
    sj = d / 'state.json'
    if not sj.exists():
        continue
    state = json.loads(sj.read_text('utf-8'))
    tf = list(d.glob('timing_*.json'))
    timing = json.loads(tf[0].read_text('utf-8')) if tf else {}
    po = state.get('phase_outputs', {})
    p3 = po.get('p3_artefact_extraction', {}).get('extracted_artefacts', [])
    p7 = po.get('p7_analysis_and_validation', {})
    p6 = po.get('p6_multisource_correlation', {})
    ada = p7.get('account_and_drone_analysis', {})
    id_found = sum(bool(id_val(ada, f)) for f in ID_FIELDS)
    uncorr = len(p7.get('uncorrelated_artefacts', []))
    corr = len(p3) - uncorr
    flights = p6.get('flight_count', 0)
    auto_s = timing.get('automated_seconds', 0.0)
    name = d.name.replace('ft-', '')
    print(f"{name:<24}  {auto_s:>7.1f}  {len(p3):>6}  {corr:>6}  {id_found:>3}  {flights:>7}")
