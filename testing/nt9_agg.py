"""Aggregate Results — produce §6 coverage table from all state.json files.

Usage
-----
    python testing/aggregate_results.py state.json [state.json ...]

    # Scan a root output directory for all state.json files:
    python testing/aggregate_results.py --output-dir ~/Documents/dfdof_output

    # Write to CSV (primary deliverable for §6 tables):
    python testing/aggregate_results.py --output-dir ~/Documents/dfdof_output \\
        --csv aggregate_results.csv

Output columns
--------------
case_id, operator, start_time,
sources_detected, sources_total,
artefact_categories_with_data, artefact_categories_total,
flights_with_primary_correlation, flights_total,
tools_succeeded, tools_total,
coverage_score_pct,
source_combination,             (e.g. "ios+drone_sd")
flight_count,
matched_count,
unmatched_count,
median_distances,               (comma-separated, one per matched flight)
confidences,                    (comma-separated, one per matched flight)
drone_serial,
drone_name,
account_email,
dji_app_version,
anomaly_flag_count,
tool_invocation_count
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path

_SOURCE_LABELS = {
    "controller_ios": "ios",
    "controller_android": "android",
    "drone_sd": "drone_sd",
    "drone_flight_storage": "drone_flight",
}


def _load(path: str) -> dict:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def _find_state_files(output_dir: str) -> list[Path]:
    root = Path(output_dir)
    return sorted(root.glob("*/state.json"))


def _source_combination(input_evidence: list[dict]) -> str:
    seen: dict[str, None] = {}
    for e in input_evidence:
        src = e.get("source_identification", "")
        # Normalise drone_sd_1, drone_sd_2 -> drone_sd
        if src.startswith("drone_sd"):
            src = "drone_sd"
        label = _SOURCE_LABELS.get(src, src)
        if label:
            seen[label] = None
    return "+".join(seen)


def _safe_str(val) -> str:
    if val is None:
        return ""
    if isinstance(val, list):
        return "; ".join(str(v) for v in val)
    return str(val)


def _identity_value(ada: dict, key: str) -> str:
    entry = ada.get(key, {})
    if isinstance(entry, dict):
        val = entry.get("value", "")
        return _safe_str(val)
    return ""


def _aggregate(state_path: str) -> dict:
    state = _load(state_path)
    case_id = state.get("case_id", Path(state_path).parent.name)
    operator = state.get("operator", "")
    start_time = state.get("start_time", "")
    input_ev = state.get("input_evidence", [])
    anomaly_flags = state.get("anomaly_flags", [])
    tool_log = state.get("tool_invocation_log", [])

    p7 = state.get("phase_outputs", {}).get("p7_analysis_and_validation", {})
    p6 = state.get("phase_outputs", {}).get("p6_multisource_correlation", {})

    # Coverage score dimensions
    cs = p7.get("coverage_score", {})
    src_det = cs.get("evidence_sources_detected", {})
    art_det = cs.get("artefact_categories_with_data", {})
    flt_det = cs.get("flights_with_primary_correlation", {})
    tol_det = cs.get("tools_succeeded", {})

    sources_detected = src_det.get("value", 0)
    sources_total = src_det.get("total", 4)
    artefact_cats = art_det.get("value", 0)
    artefact_total = art_det.get("total", 7)
    flights_corr = flt_det.get("value", 0)
    flights_total_cs = flt_det.get("total", 0)
    tools_ok = tol_det.get("value", 0)
    tools_total = tol_det.get("total", 0)

    # Weighted coverage score (each dimension 0-1, average)
    dims = [
        sources_detected / sources_total if sources_total else 0,
        artefact_cats / artefact_total if artefact_total else 0,
        flights_corr / flights_total_cs if flights_total_cs else 1,
        tools_ok / tools_total if tools_total else 1,
    ]
    coverage_pct = round(sum(dims) / len(dims) * 100, 1)

    # Flight details
    p6_flights = p6.get("flights", [])
    matched = [f for f in p6_flights if f.get("correlation", {}).get("matched", False)]
    unmatched = [f for f in p6_flights if not f.get("correlation", {}).get("matched", True)]

    median_distances = [
        str(round(f["correlation"].get("median_distance_m", 0), 1))
        for f in matched
    ]
    confidences = [
        f["correlation"].get("confidence", "-")
        for f in matched
    ]

    # Identity
    ada = p7.get("account_and_drone_analysis", {})
    drone_serial = _identity_value(ada, "drone_serial")
    drone_name = _identity_value(ada, "drone_name")
    account_email = _identity_value(ada, "account_email")
    dji_app_version = _identity_value(ada, "dji_app_version")

    return {
        "case_id": case_id,
        "operator": operator,
        "start_time": start_time[:10] if start_time else "",
        "sources_detected": sources_detected,
        "sources_total": sources_total,
        "artefact_categories_with_data": artefact_cats,
        "artefact_categories_total": artefact_total,
        "flights_with_primary_correlation": flights_corr,
        "flights_total": flights_total_cs,
        "tools_succeeded": tools_ok,
        "tools_total": tools_total,
        "coverage_score_pct": coverage_pct,
        "source_combination": _source_combination(input_ev),
        "flight_count": len(p6_flights),
        "matched_count": len(matched),
        "unmatched_count": len(unmatched),
        "median_distances": ", ".join(median_distances),
        "confidences": ", ".join(confidences),
        "drone_serial": drone_serial,
        "drone_name": drone_name,
        "account_email": account_email,
        "dji_app_version": dji_app_version,
        "anomaly_flag_count": len(anomaly_flags),
        "tool_invocation_count": len(tool_log),
    }


_FIELDNAMES = [
    "case_id", "operator", "start_time",
    "sources_detected", "sources_total",
    "artefact_categories_with_data", "artefact_categories_total",
    "flights_with_primary_correlation", "flights_total",
    "tools_succeeded", "tools_total",
    "coverage_score_pct",
    "source_combination",
    "flight_count", "matched_count", "unmatched_count",
    "median_distances", "confidences",
    "drone_serial", "drone_name", "account_email", "dji_app_version",
    "anomaly_flag_count", "tool_invocation_count",
]


def _print_table(results: list[dict]) -> None:
    print(f"\n{'='*80}")
    print(f"  {'Case':<28} {'Sources':>8} {'Cats':>5} {'Flights':>8}"
          f" {'Tools':>7} {'Score':>7}  Source combination")
    print(f"  {'-'*28} {'-'*8} {'-'*5} {'-'*8} {'-'*7} {'-'*7}  {'-'*20}")
    for r in results:
        print(
            f"  {r['case_id']:<28}"
            f" {r['sources_detected']}/{r['sources_total']:>2}"
            f" {r['artefact_categories_with_data']}/{r['artefact_categories_total']:>2}"
            f"  {r['matched_count']}/{r['flights_total']:>2}"
            f"  {r['tools_succeeded']}/{r['tools_total']:>2}"
            f"  {r['coverage_score_pct']:>5.1f}%"
            f"  {r['source_combination']}"
        )
    print(f"\n  {len(results)} case(s) aggregated.")


def main() -> int:
    ap = argparse.ArgumentParser(description="NT9 -- Aggregate coverage results across all cases")
    ap.add_argument("state_files", nargs="*", metavar="state.json")
    ap.add_argument("--output-dir", metavar="DIR",
                    help="Root dfdof_output directory to scan for state.json files")
    ap.add_argument("--csv", metavar="OUTPUT.csv",
                    help="Write results to CSV (primary §6 table deliverable)")
    args = ap.parse_args()

    paths: list[Path] = []
    if args.output_dir:
        paths = _find_state_files(args.output_dir)
        if not paths:
            print(f"No state.json files found under {args.output_dir}", file=sys.stderr)
    for f in args.state_files:
        paths.append(Path(f))

    if not paths:
        print("No state files provided. Use positional args or --output-dir.", file=sys.stderr)
        return 2

    results = []
    for p in paths:
        try:
            results.append(_aggregate(str(p)))
        except Exception as exc:
            print(f"ERROR reading {p}: {exc}", file=sys.stderr)

    _print_table(results)

    if args.csv and results:
        with open(args.csv, "w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=_FIELDNAMES, extrasaction="ignore")
            writer.writeheader()
            writer.writerows(results)
        print(f"\nCSV written to {args.csv}")
        print("This table maps directly to Table X (coverage scores) in §6 of the thesis.")

    return 0


if __name__ == "__main__":
    sys.exit(main())
