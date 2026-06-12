"""T8 — Tool Invocation Logging.

Usage
-----
    python testing/validate_t8_tool_log.py state.json [state.json ...]

Pass criteria (R6, R2a)
-----------------------
- Every tool_invocation_log entry has: tool_name, version, return_code, timestamp
- For each artefact category with artefacts, at least one tool log entry exists
- DatCon/ExtractDJI failures have return_code != 0 and a corresponding anomaly flag
- Appendix C entry count matches len(tool_invocation_log) (printed for manual check)
"""

from __future__ import annotations

import argparse
import json
import sys

# Category -> expected tool name(s) in tool_invocation_log
_CATEGORY_TOOLS: dict[str, list[str]] = {
    "drone_logs":     ["datcon"],
    "flight_records": ["txtlogtocsv", "txtlogtocsvtool"],
    "images":         ["exiftool"],
    "videos":         ["exiftool"],
}

# These sources trigger ExtractDJI before DatCon (flight_logs from drone_flight_storage)
_EXTRACTDJI_SOURCES = {"drone_flight_storage"}

_REQUIRED_FIELDS = {"tool_name", "version", "return_code", "timestamp"}


def _load(path: str) -> dict:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def _validate(state_path: str) -> dict:
    state = _load(state_path)
    case_id = state.get("case_id", "unknown")
    tool_log = state.get("tool_invocation_log", [])
    anomaly_flags = state.get("anomaly_flags", [])

    p3 = (state.get("phase_outputs", {})
               .get("p3_artefact_extraction", {})
               .get("extracted_artefacts", []))

    # --- Check 1: required fields present in every log entry ---
    field_issues = []
    for i, entry in enumerate(tool_log):
        missing = _REQUIRED_FIELDS - set(entry.keys())
        if missing:
            field_issues.append(f"entry[{i}] tool={entry.get('tool_name','?')} missing: {missing}")

    # --- Check 2: categories with artefacts have tool log entries ---
    cats_with_artefacts: set[str] = set()
    sources_with_drone_flight: set[str] = set()
    for a in p3:
        cat = a.get("artefact_category", "")
        src = a.get("source_identification", "")
        cats_with_artefacts.add(cat)
        if src in _EXTRACTDJI_SOURCES:
            sources_with_drone_flight.add(src)

    # Tool names logged
    logged_tools: set[str] = {e.get("tool_name", "").lower() for e in tool_log}

    coverage_issues = []
    for cat, expected_tools in _CATEGORY_TOOLS.items():
        if cat not in cats_with_artefacts:
            continue
        if not any(t in logged_tools for t in expected_tools):
            coverage_issues.append(
                f"Category '{cat}' has artefacts but no tool log entry"
                f" (expected one of: {expected_tools})"
            )

    if sources_with_drone_flight and "extractdji" not in logged_tools:
        coverage_issues.append(
            "drone_flight_storage source present but no ExtractDJI tool log entry"
        )

    # --- Check 3: failure entries have return_code != 0 and anomaly flag ---
    failure_entries = [e for e in tool_log
                       if e.get("tool_name") in {"datcon", "extractdji"}
                       and e.get("return_code") not in {0, None}]

    failure_issues = []
    for fe in failure_entries:
        tool_name = fe.get("tool_name", "")
        rc = fe.get("return_code")
        has_anomaly = any(
            "p4" in f.lower() or tool_name in f.lower()
            for f in anomaly_flags
        )
        if not has_anomaly:
            failure_issues.append(
                f"{tool_name} failure (rc={rc}) has no corresponding anomaly flag"
            )

    # --- Check 4: version field is non-empty ---
    missing_version = [e.get("tool_name", "?") for e in tool_log
                       if not e.get("version")]

    overall = not field_issues and not coverage_issues and not failure_issues

    return {
        "case_id": case_id,
        "tool_log_count": len(tool_log),
        "tool_names_logged": sorted(logged_tools - {""}),
        "field_issues": field_issues,
        "coverage_issues": coverage_issues,
        "failure_entries": len(failure_entries),
        "failure_issues": failure_issues,
        "missing_version": missing_version,
        "pass": overall,
    }


def _print_result(r: dict) -> None:
    status = "PASS" if r["pass"] else "FAIL"
    print(f"\n{'='*60}")
    print(f"  Case: {r['case_id']}  -> {status}")
    print(f"  Tool log entries: {r['tool_log_count']}")
    print(f"  Tools logged: {r['tool_names_logged']}")

    if r["field_issues"]:
        print(f"  Required field issues: {len(r['field_issues'])} -> FAIL")
        for i in r["field_issues"][:5]:
            print(f"    {i}")
    else:
        print("  Required fields: all present -> PASS")

    if r["coverage_issues"]:
        print(f"  Category coverage: -> FAIL")
        for i in r["coverage_issues"]:
            print(f"    {i}")
    else:
        print("  Category coverage: -> PASS")

    if r["missing_version"]:
        print(f"  Missing version field: {r['missing_version']} -> WARN")

    print(f"  DatCon/ExtractDJI failures: {r['failure_entries']}"
          f"  issues: {len(r['failure_issues'])}"
          f" -> {'PASS' if not r['failure_issues'] else 'FAIL'}")
    for i in r["failure_issues"]:
        print(f"    {i}")

    print(f"\n  NOTE: Verify Appendix C in PDF has exactly {r['tool_log_count']}"
          " tool entries (manual check).")


def main() -> int:
    ap = argparse.ArgumentParser(description="T8 — Tool invocation logging")
    ap.add_argument("state_files", nargs="+", metavar="state.json")
    args = ap.parse_args()

    all_pass = True
    for path in args.state_files:
        try:
            r = _validate(path)
            _print_result(r)
            if not r["pass"]:
                all_pass = False
        except Exception as exc:
            print(f"ERROR reading {path}: {exc}", file=sys.stderr)
            all_pass = False

    print(f"\n{'='*60}")
    print(f"T8 RESULT: {'PASS' if all_pass else 'FAIL'}")
    return 0 if all_pass else 1


if __name__ == "__main__":
    sys.exit(main())
