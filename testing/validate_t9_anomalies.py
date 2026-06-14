"""T9 — Anomaly Assessment.

Usage
-----
    python testing/validate_t9_anomalies.py state.json [state.json ...]

    # Write cross-case summary CSV:
    python testing/validate_t9_anomalies.py *.json --csv t9_anomaly_summary.csv

Pass criteria (R7a, R7b)
-------------------------
- Every case with artefact data has at least one derived_anomaly entry
- database_empty anomalies correspond to artefacts actually in P3 extracted_artefacts
- Anomaly counts are reported per case per category for cross-case comparison
- state.anomaly_flags records pipeline-level issues (printed for review)
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import defaultdict

# Informational keys stored alongside anomaly observations — not anomalies themselves
_INFO_KEYS = {"norm_date", "norm_time", "gps_latitude", "gps_longitude", "offset_time"}

# All recognised anomaly check keys (from P5)
_ANOMALY_KEYS = {
    "database_empty",
    "timestamp_regression", "timestamp_gap", "zero_coordinate", "missing_gps",
    "coordinate_jump", "altitude_negative", "altitude_spike", "motor_airborne_off",
    "gps_poor_fix", "gps_accuracy_poor", "quaternion_invalid", "attitude_out_of_bounds",
    "battery_cell_voltage_out_of_range", "battery_cell_imbalance",
    "battery_temperature_out_of_range", "motor_on_empty_battery",
    "contains_no_value", "contains_constant_value",
    "exif_contains_no_norm_time", "exif_contains_no_gps",
    "format", "entries", "non_readable",
}


def _load(path: str) -> dict:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def _validate(state_path: str) -> dict:
    state = _load(state_path)
    case_id = state.get("case_id", "unknown")
    anomaly_flags = state.get("anomaly_flags", [])

    p3_shas = {
        a["sha256"]
        for a in state.get("phase_outputs", {})
                       .get("p3_artefact_extraction", {})
                       .get("extracted_artefacts", [])
        if a.get("sha256")
    }

    derived = (state.get("phase_outputs", {})
                    .get("p5_normalisation_and_anomaly_checking", {})
                    .get("derived_anomalies", []))

    # Count anomaly types per category
    cat_counts: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    db_empty_issues = []

    for entry in derived:
        cat = entry.get("evidence_category", "unknown")
        obs_list = entry.get("observations", [])
        sha = entry.get("evidence_sha256", "")
        for obs in obs_list:
            if not isinstance(obs, dict):
                continue
            for key, val in obs.items():
                if key in _INFO_KEYS:
                    continue
                if isinstance(val, list):
                    if val:  # non-empty list means check fired
                        cat_counts[cat][key] += 1
                elif isinstance(val, bool):
                    if val:
                        cat_counts[cat][key] += 1
                elif val is not None:
                    cat_counts[cat][key] += 1

                # Cross-check: database_empty sha must be in P3
                if key == "database_empty" and val is True:
                    if sha and sha not in p3_shas:
                        db_empty_issues.append(
                            f"database_empty SHA {sha[:12]} not in P3 artefacts"
                        )

    has_any_anomaly = bool(derived)
    p3_has_data = bool(p3_shas)
    data_but_no_anomaly = p3_has_data and not has_any_anomaly

    issues = []
    if data_but_no_anomaly:
        issues.append("P3 has artefacts but derived_anomalies is empty")
    issues.extend(db_empty_issues[:5])

    return {
        "case_id": case_id,
        "derived_anomaly_count": len(derived),
        "anomaly_flag_count": len(anomaly_flags),
        "anomaly_flags_sample": anomaly_flags[:5],
        "cat_counts": {k: dict(v) for k, v in cat_counts.items()},
        "db_empty_issues": db_empty_issues,
        "issues": issues,
        "pass": not issues,
    }


def _print_result(r: dict) -> None:
    status = "PASS" if r["pass"] else "FAIL"
    print(f"\n{'='*60}")
    print(f"  Case: {r['case_id']}  -> {status}")
    print(f"  Derived anomaly entries: {r['derived_anomaly_count']}")
    print(f"  Pipeline anomaly flags: {r['anomaly_flag_count']}")
    if r["anomaly_flags_sample"]:
        for f in r["anomaly_flags_sample"]:
            print(f"    {f}")

    print("  Anomaly counts by category:")
    for cat in sorted(r["cat_counts"]):
        checks = r["cat_counts"][cat]
        checks_str = "  ".join(f"{k}:{v}" for k, v in sorted(checks.items()))
        print(f"    {cat}: {checks_str}")

    for issue in r["issues"]:
        print(f"  ISSUE: {issue}")


def _build_cross_case_table(results: list[dict]) -> tuple[list[str], list[dict]]:
    """Build a flat table: one row per case, one column per (category, check_key)."""
    all_cols: dict[str, None] = {}
    for r in results:
        for cat, checks in r["cat_counts"].items():
            for key in checks:
                all_cols[f"{cat}:{key}"] = None

    fieldnames = ["case_id", "derived_anomaly_count"] + sorted(all_cols)
    rows = []
    for r in results:
        row: dict = {"case_id": r["case_id"],
                     "derived_anomaly_count": r["derived_anomaly_count"]}
        for col in sorted(all_cols):
            cat, key = col.split(":", 1)
            row[col] = r["cat_counts"].get(cat, {}).get(key, 0)
        rows.append(row)
    return fieldnames, rows


def main() -> int:
    ap = argparse.ArgumentParser(description="T9 — Anomaly assessment")
    ap.add_argument("state_files", nargs="+", metavar="state.json")
    ap.add_argument("--csv", metavar="OUTPUT.csv",
                    help="Write cross-case anomaly summary to CSV")
    args = ap.parse_args()

    results = []
    all_pass = True
    for path in args.state_files:
        try:
            r = _validate(path)
            _print_result(r)
            results.append(r)
            if not r["pass"]:
                all_pass = False
        except Exception as exc:
            print(f"ERROR reading {path}: {exc}", file=sys.stderr)
            all_pass = False

    if args.csv and results:
        fieldnames, rows = _build_cross_case_table(results)
        with open(args.csv, "w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)
        print(f"\nCross-case anomaly summary written to {args.csv}")

    print(f"\n{'='*60}")
    print(f"T9 RESULT: {'PASS' if all_pass else 'FAIL'}")
    print("Manual step: for 3 cases open the normalised CSV in Excel and verify")
    print("  that flagged row indices contain the reported data quality issue.")
    return 0 if all_pass else 1


if __name__ == "__main__":
    sys.exit(main())
