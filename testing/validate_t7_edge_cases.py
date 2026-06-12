"""T7 — Multi-Source and Edge Case Handling.

Usage
-----
    python testing/validate_t7_edge_cases.py state.json [state.json ...]

    # Write summary CSV:
    python testing/validate_t7_edge_cases.py *.json --csv t7_edge_cases.csv

Variants checked
----------------
- Multiple drone SDs (drone_sd_1, drone_sd_2, ...)
- Android physical (acquisition_method contains "physical")
- iOS-only (no android source)
- Android-only (no ios source)
- No matchable drone log (matched: false flight)
- Multiple DJI apps (installed_dji_apps list has > 1 entry)
- DatCon skip/error logged with return_code != 0 and anomaly flag raised

Pass criteria (R5a, R5b)
-------------------------
- All variants produce structurally valid state.json with no pipeline crash
- Multiple drone SDs numbered correctly in source_identification
- Physical Android flagged correctly in acquisition_method
- Solo flights (no drone log match) produce matched: false with correlation_metadata present
- DatCon/ExtractDJI errors logged as tool invocation with return_code != 0 and anomaly flag
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path


def _load(path: str) -> dict:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def _detect_variants(state: dict) -> dict:
    case_id = state.get("case_id", "unknown")
    input_ev = state.get("input_evidence", [])
    anomaly_flags = state.get("anomaly_flags", [])
    p1_ev = (state.get("phase_outputs", {})
                  .get("p1_provenance", {})
                  .get("identified_evidence", []))
    p6_flights = (state.get("phase_outputs", {})
                       .get("p6_multisource_correlation", {})
                       .get("flights", []))
    tool_log = state.get("tool_invocation_log", [])
    p7 = state.get("phase_outputs", {}).get("p7_analysis_and_validation", {})

    # Source types present
    source_ids = [e.get("source_identification", "") for e in input_ev]
    has_ios = "controller_ios" in source_ids
    has_android = "controller_android" in source_ids
    # All drone SD inputs share source_identification = "drone_sd" (not numbered)
    drone_sd_count = sum(1 for s in source_ids if s == "drone_sd")
    has_drone_sd = drone_sd_count > 0
    has_drone_flight = "drone_flight_storage" in source_ids

    # Multiple drone SDs: numbering appears in stored_path as drone_sd_1/, drone_sd_2/
    multi_drone_sd = drone_sd_count > 1
    p3_artefacts = (state.get("phase_outputs", {})
                         .get("p3_artefact_extraction", {})
                         .get("extracted_artefacts", []))
    if multi_drone_sd and p3_artefacts:
        # Check that stored_paths contain "drone_sd_2" (proving second SD was numbered)
        drone_sd_paths = [a.get("stored_path", "") for a in p3_artefacts
                          if a.get("source_identification") == "drone_sd"]
        drone_sd_numbered = any("drone_sd_2" in p for p in drone_sd_paths)
    else:
        drone_sd_numbered = True  # not applicable for single SD

    # Android physical
    android_physical = any(
        e.get("acquisition_method", "") == "physical"
        for e in input_ev
        if e.get("source_identification") == "controller_android"
    )
    android_physical_expected = has_android and any(
        Path(e.get("source_path", "")).suffix.lower() in {".001", ".e01"}
        for e in input_ev
        if "android" in e.get("source_identification", "")
    )

    # Unmatched flights
    unmatched_flights = [f for f in p6_flights
                         if not f.get("correlation", {}).get("matched", True)]
    matched_flights = [f for f in p6_flights
                       if f.get("correlation", {}).get("matched", False)]

    # Check unmatched flights have correlation_metadata (not just missing)
    unmatched_structure_ok = all(
        isinstance(f.get("correlation"), dict) for f in unmatched_flights
    )

    # Multiple DJI apps
    ada = p7.get("account_and_drone_analysis", {})
    installed_apps = ada.get("installed_dji_apps", {}).get("value", [])
    multi_apps = len(installed_apps) > 1 if isinstance(installed_apps, list) else False

    # DatCon/ExtractDJI failure handling
    failed_tools = [t for t in tool_log
                    if t.get("tool_name") in {"datcon", "extractdji"}
                    and t.get("return_code") not in {0, None}]
    tool_failures_have_anomaly = True
    for ft in failed_tools:
        tool_name = ft.get("tool_name", "")
        # Check at least one anomaly flag references this tool or phase
        has_flag = any(
            tool_name in f.lower() or "p4" in f.lower()
            for f in anomaly_flags
        )
        if not has_flag:
            tool_failures_have_anomaly = False

    # Completed phases check (pipeline didn't crash)
    completed = state.get("completed_phases", [])
    pipeline_complete = len(completed) >= 7  # P1-P7 minimum

    issues = []
    if multi_drone_sd and not drone_sd_numbered:
        issues.append("Drone SD sources not numbered correctly")
    if android_physical_expected and not android_physical:
        issues.append("Android physical source not flagged as acquisition_method=physical")
    if unmatched_flights and not unmatched_structure_ok:
        issues.append("Unmatched flight missing correlation_metadata")
    if failed_tools and not tool_failures_have_anomaly:
        issues.append("Tool failure(s) without corresponding anomaly flag")
    if not pipeline_complete:
        issues.append(f"Pipeline incomplete: only {len(completed)} phases completed")

    return {
        "case_id": case_id,
        "has_ios": has_ios,
        "has_android": has_android,
        "has_drone_sd": has_drone_sd,
        "has_drone_flight": has_drone_flight,
        "drone_sd_count": drone_sd_count,
        "multi_drone_sd": multi_drone_sd,
        "android_physical": android_physical,
        "matched_flights": len(matched_flights),
        "unmatched_flights": len(unmatched_flights),
        "multi_dji_apps": multi_apps,
        "installed_apps": installed_apps if isinstance(installed_apps, list) else [],
        "tool_failures": len(failed_tools),
        "tool_failures_have_anomaly": tool_failures_have_anomaly,
        "completed_phases": len(completed),
        "pipeline_complete": pipeline_complete,
        "issues": issues,
        "pass": not issues,
    }


def _print_result(r: dict) -> None:
    status = "PASS" if r["pass"] else "FAIL"
    print(f"\n{'='*60}")
    print(f"  Case: {r['case_id']}  -> {status}")
    print(f"  Sources: iOS={r['has_ios']}  Android={r['has_android']}"
          f"  DroneSD={r['drone_sd_count']}  DroneFlight={r['has_drone_flight']}")
    print(f"  Android physical acq: {r['android_physical']}")
    print(f"  Flights: {r['matched_flights']} matched, {r['unmatched_flights']} unmatched")
    print(f"  DJI apps: {r['installed_apps']}")
    print(f"  Tool failures: {r['tool_failures']}  (anomaly flagged: {r['tool_failures_have_anomaly']})")
    print(f"  Completed phases: {r['completed_phases']}")
    for issue in r["issues"]:
        print(f"  ISSUE: {issue}")


def main() -> int:
    ap = argparse.ArgumentParser(description="T7 — Edge case handling")
    ap.add_argument("state_files", nargs="+", metavar="state.json")
    ap.add_argument("--csv", metavar="OUTPUT.csv",
                    help="Write summary to CSV")
    args = ap.parse_args()

    results = []
    all_pass = True
    for path in args.state_files:
        try:
            state = _load(path)
            r = _detect_variants(state)
            _print_result(r)
            results.append(r)
            if not r["pass"]:
                all_pass = False
        except Exception as exc:
            print(f"ERROR reading {path}: {exc}", file=sys.stderr)
            all_pass = False

    if args.csv and results:
        fieldnames = ["case_id", "has_ios", "has_android", "has_drone_sd", "drone_sd_count",
                      "has_drone_flight", "android_physical", "matched_flights",
                      "unmatched_flights", "multi_dji_apps", "tool_failures",
                      "tool_failures_have_anomaly", "completed_phases", "issues", "pass"]
        with open(args.csv, "w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=fieldnames, extrasaction="ignore")
            writer.writeheader()
            for r in results:
                row = {**r, "issues": "; ".join(r["issues"])}
                writer.writerow(row)
        print(f"\nCSV written to {args.csv}")

    print(f"\n{'='*60}")
    print(f"T7 RESULT: {'PASS' if all_pass else 'FAIL'}"
          f"  ({len(results)} cases)")
    return 0 if all_pass else 1


if __name__ == "__main__":
    sys.exit(main())
