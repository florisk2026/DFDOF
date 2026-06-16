"""NT8 -- Pipeline Efficiency (no pass/fail)
Wall-clock timing per phase + DatCon interaction count estimate.

No automated pass/fail. Results are stored for analysis in §6 of the thesis.

Usage
-----
Run after all pipeline cases are complete.  Pass the timing JSON files produced by
PipelineTimer (saved as timing_<case_id>.json in each case output directory):

    python testing/validate_teff_timing.py timing_*.json

    # Or point to the dfdof_output root and let the script find all timing files:
    python testing/validate_teff_timing.py --output-dir ~/Documents/dfdof_output

    # Write summary CSV for §6 tables:
    python testing/validate_teff_timing.py timing_*.json --csv teff_timing.csv

Notes on manual data to add
----------------------------
DatCon interactions cannot be timed automatically (GUI tool, supervised invocation).
After each pipeline run, note:
  - Number of DatCon invocations (readable from state.json tool_invocation_log)
  - Your estimated time per interaction (~2-3 min each)

The script reads DatCon invocation count from state.json if passed alongside timing files.
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path

_PHASES_AUTOMATED = [
    "p1_provenance",
    "p2_image_parsing",
    "p3_artefact_extraction",
    "p5_normalisation_and_anomaly_checking",
    "p6_multisource_correlation",
    "p7_analysis_and_validation",
    "p8_automated_reporting",
]
_P4 = "p4_decision_and_orchestration"

_PHASE_SHORT = {
    "p1_provenance": "P1",
    "p2_image_parsing": "P2",
    "p3_artefact_extraction": "P3",
    "p4_decision_and_orchestration": "P4",
    "p5_normalisation_and_anomaly_checking": "P5",
    "p6_multisource_correlation": "P6",
    "p7_analysis_and_validation": "P7",
    "p8_automated_reporting": "P8",
}


def _load(path: str) -> dict:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def _find_timing_files(output_dir: str) -> list[Path]:
    root = Path(output_dir)
    return sorted(root.glob("*/timing_*.json"))


def _find_state_sibling(timing_path: Path) -> Path | None:
    """Look for state.json next to or inside the same case directory."""
    candidates = [
        timing_path.parent / "state.json",
        timing_path.parent.parent / "state.json",
    ]
    for c in candidates:
        if c.exists():
            return c
    return None


def _datcon_count_from_state(state_path: Path) -> int:
    try:
        state = _load(str(state_path))
        return sum(
            1 for e in state.get("tool_invocation_log", [])
            if e.get("tool_name") == "datcon"
        )
    except Exception:
        return 0


def _parse_timing(timing_path: Path) -> dict:
    data = _load(str(timing_path))
    phases = data.get("phases", {})

    automated_s = sum(
        phases[p]["duration_s"]
        for p in _PHASES_AUTOMATED
        if p in phases
    )
    p4_s = phases.get(_P4, {}).get("duration_s", 0.0)
    total_s = data.get("total_seconds", sum(p["duration_s"] for p in phases.values()))

    state_path = _find_state_sibling(timing_path)
    datcon_count = _datcon_count_from_state(state_path) if state_path else 0

    return {
        "case_id": data.get("case_id", timing_path.stem),
        "operator": data.get("operator", "-"),
        "total_s": round(total_s, 1),
        "automated_s": round(automated_s, 1),
        "p4_s": round(p4_s, 1),
        "datcon_invocations": datcon_count,
        "estimated_datcon_min": round(datcon_count * 2.5, 1),  # ~2.5 min per interaction
        "phases": {_PHASE_SHORT.get(k, k): round(v["duration_s"], 1)
                   for k, v in phases.items()},
        "timing_path": str(timing_path),
    }


def _fmt_min(seconds: float) -> str:
    mins = int(seconds // 60)
    secs = int(seconds % 60)
    return f"{mins}m{secs:02d}s"


def _print_results(results: list[dict]) -> None:
    if not results:
        print("No timing files found.")
        return

    # Header
    all_phases = sorted({p for r in results for p in r["phases"]})
    print(f"\n{'='*80}")
    print(f"  {'Case':<25} {'Total':>8} {'Auto':>8} {'P4(DatCon)':>12}"
          f"  {'DatCon#':>8}  {'Est.DatCon':>11}")
    print(f"  {'-'*25} {'-'*8} {'-'*8} {'-'*12}  {'-'*8}  {'-'*11}")

    for r in results:
        print(f"  {r['case_id']:<25} {_fmt_min(r['total_s']):>8}"
              f" {_fmt_min(r['automated_s']):>8} {_fmt_min(r['p4_s']):>12}"
              f"  {r['datcon_invocations']:>8}  {_fmt_min(r['estimated_datcon_min'] * 60):>11}")

    if len(results) > 1:
        avg_auto = sum(r["automated_s"] for r in results) / len(results)
        avg_total = sum(r["total_s"] for r in results) / len(results)
        total_datcon = sum(r["datcon_invocations"] for r in results)
        print(f"\n  Mean automated time (P4 excluded): {_fmt_min(avg_auto)}")
        print(f"  Mean total time:                   {_fmt_min(avg_total)}")
        print(f"  Total DatCon invocations:          {total_datcon}")
        print(f"  Estimated DatCon operator time:    {_fmt_min(total_datcon * 2.5 * 60)}")

    print(f"\n  Per-phase breakdown:")
    print(f"  {'Case':<25} " + "  ".join(f"{p:>5}" for p in all_phases))
    print(f"  {'-'*25} " + "  ".join("-" * 5 for _ in all_phases))
    for r in results:
        phases_str = "  ".join(
            f"{_fmt_min(r['phases'].get(p, 0)):>5}" for p in all_phases
        )
        print(f"  {r['case_id']:<25} {phases_str}")


def main() -> int:
    ap = argparse.ArgumentParser(description="NT8 -- Pipeline efficiency timing")
    ap.add_argument("timing_files", nargs="*", metavar="timing_*.json",
                    help="Timing JSON files produced by PipelineTimer")
    ap.add_argument("--output-dir", metavar="DIR",
                    help="Root output directory to scan for timing_*.json files")
    ap.add_argument("--csv", metavar="OUTPUT.csv",
                    help="Write summary to CSV")
    args = ap.parse_args()

    paths: list[Path] = []
    if args.output_dir:
        paths = _find_timing_files(args.output_dir)
        if not paths:
            print(f"No timing_*.json files found under {args.output_dir}", file=sys.stderr)
    for f in args.timing_files:
        paths.append(Path(f))

    if not paths:
        print("No timing files provided. Use positional args or --output-dir.", file=sys.stderr)
        return 2

    results = []
    for p in paths:
        try:
            results.append(_parse_timing(p))
        except Exception as exc:
            print(f"ERROR reading {p}: {exc}", file=sys.stderr)

    _print_results(results)

    if args.csv and results:
        all_phases = sorted({p for r in results for p in r["phases"]})
        fieldnames = (["case_id", "operator", "total_s", "automated_s", "p4_s",
                       "datcon_invocations", "estimated_datcon_min"]
                      + [f"phase_{p}" for p in all_phases])
        rows = []
        for r in results:
            row = {k: r[k] for k in ["case_id", "operator", "total_s", "automated_s",
                                      "p4_s", "datcon_invocations", "estimated_datcon_min"]}
            for p in all_phases:
                row[f"phase_{p}"] = r["phases"].get(p, 0.0)
            rows.append(row)

        with open(args.csv, "w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)
        print(f"\nCSV written to {args.csv}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
