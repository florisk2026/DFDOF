import matplotlib; matplotlib.use('Agg')
import sys; sys.path.insert(0, '.')
from testing.generate_formal_plots import load_cases, plot_08_tool_heatmap
cases = load_cases()
plot_08_tool_heatmap(cases)
for c in cases:
    tcsv = c['tool_counts'].get('txtlogtocsv', 0)
    if tcsv > 0:
        print(f"  {c['short']}: txtlogtocsv={tcsv}")
print('done')
