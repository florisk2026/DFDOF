"""NT7 -- UTC Normalisation (R8a + R8b)

Verify that temporal normalisation only occurs when the source data contains
explicit timezone information.

Checks:
  R8a -- drone_log CSVs: [NORM]:GPS:dateTimeStamp non-empty values must end
         with +00:00 or Z (GPS time is inherently UTC)
  R8a -- flight_record CSVs: [NORM]:CUSTOM.updateTime non-empty values must
         end with +00:00 or Z
  R8a -- images/videos with norm_time in P5 anomalies: the corresponding
         exif JSON must contain OffsetTimeOriginal or OffsetTimeDigitized
  R8b -- flight_log timestamps in P5 anomaly entries must NOT end with
         +00:00 or Z (local device time, no timezone known)
  R8b -- .info sidecar CaptureDate must NOT appear as norm_time in P5
         (local time, no timezone info)

Usage
-----
    python testing/nt7_utc.py state.json [state.json ...]
    python testing/nt7_utc.py *.json --output pre_results/results_nt7.json
"""
from __future__ import annotations

import argparse
import csv as csv_mod
import json
import sys
from datetime import datetime, timezone
from pathlib import Path


_UTC_SUFFIXES = ("+00:00", "z", "+0000")


def _load(path: str) -> dict:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def _is_utc(ts: str) -> bool:
    ts_lower = ts.strip().lower()
    return any(ts_lower.endswith(s) for s in _UTC_SUFFIXES)


def _check_norm_csv(csv_path: Path, col_name: str) -> list[str]:
    """Check that all non-empty values in col_name end with a UTC suffix."""
    violations = []
    if not csv_path.exists():
        return [f"file not found: {csv_path.name}"]
    try:
        with open(csv_path, newline="", encoding="utf-8", errors="replace") as fh:
            reader = csv_mod.DictReader(fh)
            header = reader.fieldnames or []
            if col_name not in header:
                return []  # column absent for this format, skip
            for row_num, row in enumerate(reader, start=2):
                val = row.get(col_name, "").strip()
                if val and not _is_utc(val):
                    violations.append(f"row {row_num}: {val!r} lacks UTC suffix")
    except Exception as exc:
        violations.append(f"read error: {exc}")
    return violations


def _check_exif_json_for_offset(exif_json_path: Path) -> bool:
    """Return True if the exif JSON contains OffsetTimeOriginal/Digitized."""
    if not exif_json_path.exists():
        return False
    try:
        data = json.loads(exif_json_path.read_text("utf-8"))
        text = json.dumps(data).lower()
        return "offsettimeoriginal" in text or "offsettimedigitized" in text or "offsettime" in text
    except Exception:
        return False


def _validate_case(state_path: str) -> dict:
    s = _load(state_path)
    case_id = s.get("case_id", Path(state_path).parent.name)
    case_dir = Path(state_path).parent
    issues: list[str] = []
    details: dict = {
        "drone_log_csvs_checked": 0,
        "flight_record_csvs_checked": 0,
        "flight_log_entries_checked": 0,
        "images_videos_checked": 0,
        "info_sidecars_checked": 0,
    }

    p5_artefacts = s.get("phase_outputs", {}).get("p5_normalisation_and_anomaly_checking", {}).get("normalised_artefacts", [])
    p5_anomalies = s.get("phase_outputs", {}).get("p5_normalisation_and_anomaly_checking", {}).get("derived_anomalies", [])

    # --- R8a: drone_log normalised CSVs ---
    dl_csvs = [a for a in p5_artefacts if a.get("artefact_category") == "drone_logs"]
    for a in dl_csvs:
        csv_path = Path(a.get("stored_path", ""))
        violations = _check_norm_csv(csv_path, "[NORM]:GPS:dateTimeStamp")
        if violations:
            issues.append(f"drone_log {csv_path.name}: {violations[:3]}")
        details["drone_log_csvs_checked"] += 1

    # --- R8a: flight_record normalised CSVs ---
    fr_csvs = [a for a in p5_artefacts if a.get("artefact_category") == "flight_records"]
    for a in fr_csvs:
        csv_path = Path(a.get("stored_path", ""))
        violations = _check_norm_csv(csv_path, "[NORM]:CUSTOM.updateTime")
        if violations:
            issues.append(f"flight_record {csv_path.name}: {violations[:3]}")
        details["flight_record_csvs_checked"] += 1

    # --- R8a: images/videos with norm_time must have OffsetTime in exif JSON ---
    for anomaly in p5_anomalies:
        cat = anomaly.get("evidence_category")
        if cat not in ("images", "videos"):
            continue
        acq = anomaly.get("acquisition_method", "")
        for obs in anomaly.get("observations", []):
            if "norm_time" in obs or "norm_date" in obs:
                # This image/video was normalised -- verify source had OffsetTime
                # The stored_path in the anomaly points to the exif JSON sidecar
                exif_path = Path(anomaly.get("stored_path", ""))
                if not _check_exif_json_for_offset(exif_path):
                    issues.append(
                        f"{cat} anomaly has norm_time but exif JSON lacks OffsetTime: {exif_path.name}"
                    )
                details["images_videos_checked"] += 1

    # --- R8b: flight_log timestamps must NOT be UTC ---
    for anomaly in p5_anomalies:
        if anomaly.get("evidence_category") != "flight_logs":
            continue
        for obs in anomaly.get("observations", []):
            entries = obs.get("entries", [])
            for entry in entries:
                ts = entry.get("timestamp", "")
                if ts and _is_utc(ts):
                    issues.append(
                        f"flight_log timestamp has UTC suffix (R8b violation): {ts!r}"
                    )
                details["flight_log_entries_checked"] += 1

    # --- R8b: .info sidecar CaptureDate must not appear as norm_time in P5 ---
    p4_observations = s.get("phase_outputs", {}).get("p4_decision_and_orchestration", {}).get("derived_observations", [])
    info_shas = {
        obs.get("evidence_sha256")
        for obs in p4_observations
        if obs.get("acquisition_method") == "p4_decision_and_orchestration"
        and obs.get("evidence_category") == "videos"
        and any("CaptureDate" in str(o) for o in obs.get("observations", []))
    }
    for anomaly in p5_anomalies:
        if anomaly.get("evidence_category") == "videos" and anomaly.get("evidence_sha256") in info_shas:
            for obs in anomaly.get("observations", []):
                if "norm_time" in obs or "norm_date" in obs:
                    issues.append(
                        f".info sidecar has norm_time in P5 (R8b violation): sha {anomaly.get('evidence_sha256','?')[:16]}"
                    )
                details["info_sidecars_checked"] += 1

    return {
        "case_id": case_id,
        "state_path": state_path,
        "details": details,
        "issues": issues,
        "passed": len(issues) == 0,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="NT7 -- UTC normalisation correctness")
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
        status = "PASS" if r.get("passed") else "FAIL"
        d = r.get("details", {})
        print(f"  Case: {r.get('case_id', '?')}  -> {status}")
        print(f"  Drone log CSVs checked:    {d.get('drone_log_csvs_checked', 0)}")
        print(f"  Flight record CSVs checked:{d.get('flight_record_csvs_checked', 0)}")
        print(f"  Flight log entries:        {d.get('flight_log_entries_checked', 0)}")
        print(f"  Images/videos checked:     {d.get('images_videos_checked', 0)}")
        if r.get("issues"):
            print(f"  Issues ({len(r['issues'])}):")
            for issue in r["issues"][:10]:
                print(f"    {issue}")

    print(f"\n{'='*60}")
    total_issues = sum(len(r.get("issues", [])) for r in results)
    print(f"NT7 RESULT: {'PASS' if all_pass else 'FAIL'}  ({len(results)} cases, {total_issues} issues)")

    if args.output:
        output = {
            "test": "NT7",
            "requirement": "R8a + R8b",
            "description": "UTC normalisation: timestamps normalised to UTC only when timezone info present in source",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "cases": results,
            "summary": "PASS" if all_pass else f"FAIL: {total_issues} normalisation issues",
        }
        Path(args.output).parent.mkdir(parents=True, exist_ok=True)
        Path(args.output).write_text(json.dumps(output, indent=2), encoding="utf-8")
        print(f"\nResults written to {args.output}")

    return 0 if all_pass else 1


if __name__ == "__main__":
    sys.exit(main())
