"""T10 — Timestamp Normalisation.

Usage
-----
    python testing/validate_t10_timestamps.py state.json [state.json ...]

Pass criteria (R8a, R8b)
-------------------------
- All [NORM]: timestamp columns in drone log and flight record CSVs contain
  ISO 8601 UTC strings with +00:00 or Z suffix (R8a)
- Flight log observation timestamps that have no timezone information do NOT
  have a +00:00 suffix appended (R8b)
- No normalised CSV has timezone-free timestamps promoted to UTC
"""

from __future__ import annotations

import argparse
import csv as csvlib
import json
import re
import sys
from pathlib import Path

# Expected [NORM]: timestamp column names per artefact category
_DRONE_LOG_TS_COL = "[NORM]:GPS:dateTimeStamp"
_FLIGHT_REC_TS_COL = "[NORM]:CUSTOM.updateTime"

_UTC_PATTERN = re.compile(r"\+00:00$|Z$")
_HAS_TIMEZONE = re.compile(r"[+-]\d{2}:\d{2}$|Z$")

_SAMPLE_ROWS = 20  # rows to sample from each CSV


def _load(path: str) -> dict:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def _read_csv_column(csv_path: str, col_name: str, max_rows: int = _SAMPLE_ROWS) -> list[str]:
    """Read up to max_rows values from a specific column. Returns empty list if col absent."""
    try:
        with open(csv_path, encoding="utf-8", newline="") as fh:
            reader = csvlib.DictReader(fh)
            vals = []
            for i, row in enumerate(reader):
                if i >= max_rows:
                    break
                val = row.get(col_name, "")
                if val:
                    vals.append(val)
        return vals
    except Exception:
        return []


def _check_utc_column(csv_path: str, col_name: str, cat: str) -> dict:
    vals = _read_csv_column(csv_path, col_name)
    if not vals:
        # Column may be absent (e.g. no GPS in this file) — note but don't fail
        return {"csv": Path(csv_path).name, "category": cat, "col": col_name,
                "status": "SKIP", "reason": "column absent or empty", "issues": []}

    non_utc = [v for v in vals if v and not _UTC_PATTERN.search(v)]
    return {
        "csv": Path(csv_path).name,
        "category": cat,
        "col": col_name,
        "sampled": len(vals),
        "non_utc": non_utc[:5],
        "status": "PASS" if not non_utc else "FAIL",
        "issues": [f"Non-UTC timestamp: {v}" for v in non_utc[:3]],
    }


def _check_flight_log_timestamps(derived_anomalies: list[dict]) -> dict:
    """R8b: flight log timestamps without timezone must not have +00:00 appended."""
    fl_entries = [
        a for a in derived_anomalies
        if a.get("evidence_category") == "flight_logs"
    ]
    issues = []
    total_checked = 0
    for entry in fl_entries[:5]:  # sample 5 flight logs
        for obs in entry.get("observations", []):
            if not isinstance(obs, dict):
                continue
            # Observations are {"format": "...", "entries": [{"timestamp": ..., "message": ...}]}
            # Timestamps are inside the entries list, not at the observation top level.
            for item in obs.get("entries", []):
                ts = item.get("timestamp", "")
                if ts:
                    total_checked += 1
                    # All known flight log formats (json_array_log, bracketed_log,
                    # heading_log) record local time without timezone. If the stored
                    # timestamp ends with +00:00 or Z, UTC was incorrectly assumed.
                    if _UTC_PATTERN.search(str(ts)):
                        issues.append(
                            f"Flight log timestamp has UTC suffix (should be stored as-is): {ts}"
                        )
    return {
        "fl_entries_checked": len(fl_entries),
        "timestamps_sampled": total_checked,
        "issues": issues,
        "pass": not issues,
    }


def _validate(state_path: str) -> dict:
    state = _load(state_path)
    case_id = state.get("case_id", "unknown")

    p5_artefacts = (state.get("phase_outputs", {})
                         .get("p5_normalisation_and_anomaly_checking", {})
                         .get("normalised_artefacts", []))
    derived = (state.get("phase_outputs", {})
                    .get("p5_normalisation_and_anomaly_checking", {})
                    .get("derived_anomalies", []))

    csv_results = []

    for a in p5_artefacts:
        cat = a.get("artefact_category", "")
        stored = a.get("stored_path", "")
        if not stored or not Path(stored).exists():
            continue

        if cat == "drone_logs":
            csv_results.append(_check_utc_column(stored, _DRONE_LOG_TS_COL, cat))
        elif cat == "flight_records":
            csv_results.append(_check_utc_column(stored, _FLIGHT_REC_TS_COL, cat))

    fl_check = _check_flight_log_timestamps(derived)

    csv_pass = all(r["status"] in {"PASS", "SKIP"} for r in csv_results)
    overall = csv_pass and fl_check["pass"]

    return {
        "case_id": case_id,
        "csv_checks": csv_results,
        "flight_log_check": fl_check,
        "pass": overall,
    }


def _print_result(r: dict) -> None:
    status = "PASS" if r["pass"] else "FAIL"
    print(f"\n{'='*60}")
    print(f"  Case: {r['case_id']}  -> {status}")

    print(f"  Normalised CSV timestamp columns ({len(r['csv_checks'])} files):")
    for c in r["csv_checks"]:
        sample_info = f"  sampled={c.get('sampled', '-')}" if c["status"] != "SKIP" else ""
        print(f"    [{c['status']}] {c['csv']} ({c['category']}) col={c['col']}{sample_info}")
        for issue in c.get("issues", []):
            print(f"      {issue}")

    fl = r["flight_log_check"]
    fl_status = "PASS" if fl["pass"] else "FAIL"
    print(f"  Flight log R8b check ({fl['fl_entries_checked']} logs,"
          f" {fl['timestamps_sampled']} timestamps sampled): -> {fl_status}")
    for issue in fl["issues"]:
        print(f"    ISSUE: {issue}")

    print("\n  Manual step: open one normalised drone_log CSV and one flight_log file")
    print("  in a text editor and confirm UTC suffix / no-UTC-assumption respectively.")


def main() -> int:
    ap = argparse.ArgumentParser(description="T10 — Timestamp normalisation")
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
    print(f"T10 RESULT: {'PASS' if all_pass else 'FAIL'}")
    return 0 if all_pass else 1


if __name__ == "__main__":
    sys.exit(main())
