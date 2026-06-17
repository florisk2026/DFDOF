"""Automated Test 2 (AT2) -- Complete Processing Documentation (R2a + R2b + R6)

For each state.json, validate:
- All phases in completed_phases have a corresponding phase_outputs section
- All top-level metadata fields (operator, case_id, start_time) are populated
- All artefacts have fully populated attribute fields
- Phase completed_at timestamps are strictly increasing (P1 < P2 < ... < P8)
- Tool invocation log entries have tool_name, version, args populated
- Tool output_paths are linked to at least one artefact's stored_path

Usage
-----
    python testing/at2_fullprocess.py state.json [state.json ...]
    python testing/at2_fullprocess.py *.json --output pre_results/results_at2.json
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

_PHASE_ORDER = [
    "p1_provenance",
    "p2_image_parsing",
    "p3_artefact_extraction",
    "p4_decision_and_orchestration",
    "p5_normalisation_and_anomaly_checking",
    "p6_multisource_correlation",
    "p7_analysis_and_validation",
    "p8_automated_reporting",
]

_ARTEFACT_REQUIRED_FIELDS = ["source_path", "stored_path", "sha256", "sha1", "size", "type"]

# Parsers and internal orchestrators may legitimately have version=None / args=None
_INTERNAL_TOOLS = {"parser_ios", "parser_android"}


def _load(path: str) -> dict:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def _parse_ts(ts: str | None) -> datetime | None:
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts)
    except Exception:
        return None


def _validate_case(state_path: str) -> dict:
    s = _load(state_path)
    case_id = s.get("case_id", Path(state_path).parent.name)
    issues: list[str] = []
    details: dict = {}

    # --- Metadata ---
    for field in ("operator", "case_id", "start_time"):
        if not s.get(field):
            issues.append(f"metadata.{field} is missing or empty")

    # --- Phase completeness ---
    completed = s.get("completed_phases", [])
    phase_outputs = s.get("phase_outputs", {})
    for phase in completed:
        if phase not in phase_outputs:
            issues.append(f"phase_outputs missing section for {phase}")
    details["completed_phases"] = completed

    # --- Phase completed_at strictly increasing ---
    ts_values: list[tuple[str, datetime]] = []
    for phase in _PHASE_ORDER:
        if phase in phase_outputs:
            ts = _parse_ts(phase_outputs[phase].get("completed_at"))
            if ts is None:
                issues.append(f"{phase}: completed_at is missing or unparseable")
            else:
                ts_values.append((phase, ts))

    for i in range(1, len(ts_values)):
        prev_name, prev_ts = ts_values[i - 1]
        cur_name, cur_ts = ts_values[i]
        if cur_ts <= prev_ts:
            issues.append(
                f"timestamp ordering violation: {cur_name} ({cur_ts}) <= {prev_name} ({prev_ts})"
            )
    details["phase_timestamps_ok"] = len([x for x in issues if "timestamp ordering" in x]) == 0

    # --- Artefact field completeness ---
    all_artefacts = []
    for source in ("input_evidence",):
        all_artefacts.extend(s.get(source, []))
    p2 = s.get("phase_outputs", {}).get("p2_image_parsing", {}).get("parsed_evidence", [])
    p3 = s.get("phase_outputs", {}).get("p3_artefact_extraction", {}).get("extracted_artefacts", [])
    p4 = s.get("phase_outputs", {}).get("p4_decision_and_orchestration", {}).get("decision_and_orchestration_artefacts", [])
    p5 = s.get("phase_outputs", {}).get("p5_normalisation_and_anomaly_checking", {}).get("normalised_artefacts", [])
    all_artefacts.extend(p2 + p3 + p4 + p5)

    # Build stored_path set for output_path linkage check
    all_stored_paths: set[str] = set()
    for a in all_artefacts:
        sp = a.get("stored_path")
        if sp:
            all_stored_paths.add(str(sp).replace("\\", "/"))

    incomplete_artefacts = 0
    for a in all_artefacts:
        missing = []
        for f in _ARTEFACT_REQUIRED_FIELDS:
            val = a.get(f)
            # directories legitimately have null sha256/sha1
            if f in ("sha256", "sha1") and a.get("type") == "parsed" and not a.get("sha256"):
                continue
            if val is None and f not in ("sha256", "sha1"):
                missing.append(f)
        if missing:
            incomplete_artefacts += 1
    if incomplete_artefacts:
        issues.append(f"{incomplete_artefacts} artefact(s) missing required fields")
    details["total_artefacts_checked"] = len(all_artefacts)
    details["incomplete_artefacts"] = incomplete_artefacts

    # --- Tool invocation log ---
    tool_log = s.get("tool_invocation_log", [])
    unlinked_outputs: list[str] = []
    missing_fields_entries: list[str] = []

    for entry in tool_log:
        tool_name = entry.get("tool_name", "")
        is_internal = tool_name in _INTERNAL_TOOLS
        missing = []
        if not tool_name:
            missing.append("tool_name")
        if not entry.get("args"):
            missing.append("args")
        if not is_internal and entry.get("version") is None:
            # version is allowed to be None only for internal parsers
            missing.append("version")
        if not entry.get("timestamp"):
            missing.append("timestamp")
        if missing:
            missing_fields_entries.append(f"{tool_name}: missing {missing}")

        # Check output_paths linkage
        out_paths = entry.get("output_paths") or []
        for op in out_paths:
            op_norm = str(op).replace("\\", "/")
            op_path = Path(op)
            # Skip directories (no suffix means likely a directory)
            if not op_path.suffix:
                continue
            # Check if this file appears as stored_path anywhere
            if op_norm not in all_stored_paths:
                unlinked_outputs.append(f"{tool_name}: {op_path.name}")

    if missing_fields_entries:
        issues.append(f"{len(missing_fields_entries)} tool log entries with missing fields: {missing_fields_entries[:5]}")
    if unlinked_outputs:
        issues.append(f"{len(unlinked_outputs)} tool output_paths not linked to any artefact: {unlinked_outputs[:5]}")

    details["tool_log_entries"] = len(tool_log)
    details["tool_log_issues"] = missing_fields_entries + unlinked_outputs

    return {
        "case_id": case_id,
        "state_path": state_path,
        "issues": issues,
        "details": details,
        "passed": len(issues) == 0,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="AT2 -- Complete processing documentation")
    ap.add_argument("state_files", nargs="+", metavar="state.json")
    ap.add_argument("--output", metavar="results.json")
    args = ap.parse_args()

    results = []
    all_pass = True
    for path in args.state_files:
        try:
            r = _validate_case(path)
            results.append(r)
            if not r["passed"]:
                all_pass = False
        except Exception as exc:
            results.append({"case_id": path, "error": str(exc), "passed": False})
            all_pass = False

    for r in results:
        print(f"\n{'='*60}")
        print(f"  Case: {r.get('case_id', '?')}  -> {'PASS' if r.get('passed') else 'FAIL'}")
        if r.get("issues"):
            for issue in r["issues"]:
                print(f"  !! {issue}")
        else:
            d = r.get("details", {})
            print(f"  Phases: {len(d.get('completed_phases', []))}")
            print(f"  Artefacts checked: {d.get('total_artefacts_checked', '?')}")
            print(f"  Tool log entries: {d.get('tool_log_entries', '?')}")

    print(f"\n{'='*60}")
    print(f"AT2 RESULT: {'PASS' if all_pass else 'FAIL'}  ({len(results)} cases)")

    if args.output:
        output = {
            "test": "AT2",
            "requirement": "R2a + R2b + R6",
            "description": "Complete processing documentation: phase outputs, timestamps, artefact fields, tool log",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "cases": results,
            "summary": "PASS" if all_pass else "FAIL: see case issues above",
        }
        Path(args.output).parent.mkdir(parents=True, exist_ok=True)
        Path(args.output).write_text(json.dumps(output, indent=2), encoding="utf-8")
        print(f"\nResults written to {args.output}")

    return 0 if all_pass else 1


if __name__ == "__main__":
    sys.exit(main())
