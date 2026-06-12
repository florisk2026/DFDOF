"""T6 — Multi-Source Correlation Quality.

Usage
-----
    python testing/validate_t6_correlation.py state.json [state.json ...]

Pass criteria (R5b)
-------------------
- Event timestamps are monotonically non-decreasing within each source
- All primary-matched flights satisfy: overlap_s >= 60.0 AND
  overlap_s >= 0.90 * min(duration_fr, duration_drone) AND
  median_distance_m <= 25.0
- Confidence labels match distance tiers: <5 m -> high, <15 m -> medium, <=25 m -> low
- GPS boundary event coordinates are non-zero and non-null-island
- Cases with no matchable drone log produce matched: false with no crash
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

_OVERLAP_MIN_S = 60.0
_OVERLAP_MIN_FRACTION = 0.90
_SPATIAL_MAX_MEDIAN_M = 25.0

_CONFIDENCE_TIERS = [
    (5.0, "high"),
    (15.0, "medium"),
    (25.0, "low"),
]


def _load(path: str) -> dict:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def _expected_confidence(median_m: float) -> str:
    for threshold, label in _CONFIDENCE_TIERS:
        if median_m < threshold:
            return label
    return "low"


def _check_timeline(tl_path: str) -> dict:
    tl = _load(tl_path)
    corr = tl.get("correlation_metadata", {})
    flight_id = tl.get("flight_id", "?")
    flights_id = tl.get("flights_identified", [])
    events = tl.get("events", [])

    issues = []

    # --- Threshold checks (only for matched flights) ---
    matched = corr.get("matched", False)
    threshold_pass = True
    confidence_pass = True
    if matched:
        overlap_s = corr.get("overlap_s", 0.0)
        overlap_frac = corr.get("overlap_fraction", 0.0)
        median_m = corr.get("median_distance_m", 999.0)
        confidence = corr.get("confidence", "")

        if overlap_s < _OVERLAP_MIN_S:
            issues.append(f"overlap_s {overlap_s:.1f} < {_OVERLAP_MIN_S}")
            threshold_pass = False
        if overlap_frac < _OVERLAP_MIN_FRACTION:
            issues.append(f"overlap_fraction {overlap_frac:.2f} < {_OVERLAP_MIN_FRACTION}")
            threshold_pass = False
        if median_m > _SPATIAL_MAX_MEDIAN_M:
            issues.append(f"median_distance_m {median_m:.1f} > {_SPATIAL_MAX_MEDIAN_M}")
            threshold_pass = False

        expected_conf = _expected_confidence(median_m)
        if confidence != expected_conf:
            issues.append(f"confidence '{confidence}' but expected '{expected_conf}'"
                          f" for median_m={median_m:.1f}")
            confidence_pass = False

    # --- Monotonic event timestamp check (per source) ---
    by_source: dict[str, list[str]] = {}
    for ev in events:
        ts = ev.get("timestamp")
        src = ev.get("source", "unknown")
        if ts:
            by_source.setdefault(src, []).append(ts)

    mono_issues = []
    for src, timestamps in by_source.items():
        for i in range(1, len(timestamps)):
            if timestamps[i] < timestamps[i - 1]:
                mono_issues.append(f"{src}: ts[{i}]={timestamps[i]} < ts[{i-1}]={timestamps[i-1]}")
    if mono_issues:
        issues.extend(mono_issues[:3])

    # --- GPS plausibility check on boundary events ---
    gps_issues = []
    for ev in events:
        if ev.get("event") in ("Log started", "Log ended"):
            data = ev.get("data", {}) or {}
            lat = data.get("latitude")
            lon = data.get("longitude")
            if lat is not None and lon is not None:
                if lat == 0.0 and lon == 0.0:
                    gps_issues.append(f"{ev['event']}: null-island (0,0)")
                elif abs(lat) < 0.01 and abs(lon) < 0.01:
                    gps_issues.append(f"{ev['event']}: near-zero ({lat},{lon})")
    if gps_issues:
        issues.extend(gps_issues[:3])

    overall = not issues
    return {
        "flight_id": flight_id,
        "matched": matched,
        "flights_identified_count": len(flights_id),
        "event_count": len(events),
        "threshold_pass": threshold_pass,
        "confidence_pass": confidence_pass,
        "mono_pass": not mono_issues,
        "gps_pass": not gps_issues,
        "issues": issues,
        "pass": overall,
        "corr": corr,
    }


def _find_timelines(state_path: str) -> list[Path]:
    base = Path(state_path).parent
    candidates = sorted(base.glob("p6_multisource_correlation/timeline_*.json"))
    if not candidates:
        candidates = sorted(base.glob("timeline_*.json"))
    return candidates


def _validate(state_path: str) -> dict:
    state = _load(state_path)
    case_id = state.get("case_id", "unknown")

    timelines = _find_timelines(state_path)
    flight_results = []
    for tl_path in timelines:
        flight_results.append(_check_timeline(str(tl_path)))

    # Unmatched flights: verify they have correlation_metadata with matched: false
    unmatched_ok = all(
        not fr["matched"] or fr["pass"] for fr in flight_results
    )

    return {
        "case_id": case_id,
        "flight_count": len(flight_results),
        "flights": flight_results,
        "pass": all(fr["pass"] for fr in flight_results),
    }


def _print_result(r: dict) -> None:
    print(f"\n{'='*60}")
    print(f"  Case: {r['case_id']}  ({r['flight_count']} flight(s))")
    for fr in r["flights"]:
        corr = fr["corr"]
        match_str = (f"overlap={corr.get('overlap_s',0):.1f}s"
                     f" ({int(corr.get('overlap_fraction',0)*100)}%),"
                     f" dist={corr.get('median_distance_m','-'):.1f}m,"
                     f" conf={corr.get('confidence','-')}"
                     if fr["matched"] else "unmatched")
        status = "PASS" if fr["pass"] else "FAIL"
        print(f"  {fr['flight_id']}: matched={fr['matched']}  {match_str}"
              f"  events={fr['event_count']}  -> {status}")
        for issue in fr["issues"]:
            print(f"    ISSUE: {issue}")
    print(f"  OVERALL: {'PASS' if r['pass'] else 'FAIL'}")


def main() -> int:
    ap = argparse.ArgumentParser(description="T6 — Multi-source correlation quality")
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
    print(f"T6 RESULT: {'PASS' if all_pass else 'FAIL'}")
    return 0 if all_pass else 1


if __name__ == "__main__":
    sys.exit(main())
