"""DFDOF Phase 7: Analysis and Validation.

Consumes outputs from P2–P6 to produce a single analysis.json per case containing:
- Source and artefact coverage (with per-category data-quality notes)
- Tool execution status
- Account and drone identity analysis (cross-source corroboration)
- Per-flight analysis (event counts, anomalies, peak height, flight modes, media)
- Uncorrelated artefacts (chain-aware: P3→P4→P5)
- Processing coverage score
- Forensic safe statements and further investigation items
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from config import (
    ACCOUNT_DATA,
    ACQUISITION_SELECT_ACCOUNT_DATA,
    CONTROLLER_ARTEFACT_CATEGORIES,
    DATABASES,
    DEVICE_AND_BACKUP_INFO,
    DRONE_LOGS,
    FLIGHT_LOGS,
    FLIGHT_RECORDS,
    IDENTIFICATION_DRONE_FLIGHT_STORAGE,
    IDENTIFICATION_DRONE_SD,
    IMAGES,
    SOURCE_IDENTIFICATION_TYPES,
    VIDEOS,
    utc_now_iso,
)
from state import State

_PHASE_NAME = Path(__file__).stem

# Row-level anomaly keys from P5 (keys whose values are lists of row indices)
_ROW_ANOMALY_KEYS = frozenset({
    "timestamp_regression",
    "timestamp_gap",
    "zero_coordinate",
    "missing_gps",
    "coordinate_jump",
    "altitude_negative",
    "altitude_spike",
    "motor_airborne_off",
    "gps_poor_fix",
    "gps_accuracy_poor",
    "quaternion_invalid",
    "attitude_out_of_bounds",
    "battery_cell_voltage_out_of_range",
    "battery_cell_imbalance",
    "battery_temperature_out_of_range",
    "motor_on_empty_battery",
})

# Maximum haversine distance (m) for "last known location" vs flight start to be "consistent"

# Drone-side source identification strings (for confidence determination)
_DRONE_SOURCE_IDS = frozenset({IDENTIFICATION_DRONE_SD, IDENTIFICATION_DRONE_FLIGHT_STORAGE})


# ---------------------------------------------------------------------------
# Section 1 — Source and artefact coverage (with data-quality notes)
# ---------------------------------------------------------------------------

def _source_coverage(state: State) -> list[dict[str, Any]]:
    """Return detection status for each expected evidence source type."""
    detected = {e.source_identification for e in state.input_evidence}
    return [
        {"source": s, "detected": s in detected}
        for s in SOURCE_IDENTIFICATION_TYPES
    ]


def _artefact_coverage(
    p3_artefacts: list[dict[str, Any]],
    p5_anomalies: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Count extracted artefacts per category with per-category data-quality notes."""
    # Count P3 artefacts per category
    counts: dict[str, int] = {}
    for a in p3_artefacts:
        cat = a.get("artefact_category", "")
        if cat:
            counts[cat] = counts.get(cat, 0) + 1

    # Build sha256 → source_identification lookup from P3
    sha_to_src: dict[str, str] = {
        a["sha256"]: a.get("source_identification", "")
        for a in p3_artefacts
        if a.get("sha256")
    }

    # Gather per-category quality stats from P5 anomalies
    # databases: {src_id: count of empty dbs}
    empty_db_by_src: dict[str, int] = {}
    # flight_records / drone_logs: files with row anomalies, empty/constant column file counts
    fr_row_anomaly_files = 0
    fr_empty_col_files = 0
    fr_const_col_files = 0
    dl_row_anomaly_files = 0
    dl_empty_col_files = 0
    dl_const_col_files = 0
    # flight_logs: non_readable, crash_dump, format counts
    fl_non_readable = 0
    fl_crash_dump = 0
    fl_format_counts: dict[str, int] = {}
    # images / videos: exif_zero_date, exif_missing_gps
    img_zero_date = 0
    img_missing_gps = 0
    vid_zero_date = 0
    vid_missing_gps = 0

    for obs_dict in p5_anomalies:
        cat = obs_dict.get("evidence_category", "")
        sha = obs_dict.get("evidence_sha256", "")
        src_id = sha_to_src.get(sha, obs_dict.get("stored_path", ""))
        obs_list = obs_dict.get("observations", [])

        for obs in obs_list:
            if cat == DATABASES:
                if obs.get("database_empty"):
                    sid = sha_to_src.get(sha, "")
                    empty_db_by_src[sid] = empty_db_by_src.get(sid, 0) + 1

            elif cat == FLIGHT_RECORDS:
                if any(isinstance(obs.get(k), list) and obs.get(k) for k in _ROW_ANOMALY_KEYS):
                    fr_row_anomaly_files += 1
                if obs.get("contains_no_value"):
                    fr_empty_col_files += 1
                if obs.get("contains_constant_value"):
                    fr_const_col_files += 1

            elif cat == DRONE_LOGS:
                if any(isinstance(obs.get(k), list) and obs.get(k) for k in _ROW_ANOMALY_KEYS):
                    dl_row_anomaly_files += 1
                if obs.get("contains_no_value"):
                    dl_empty_col_files += 1
                if obs.get("contains_constant_value"):
                    dl_const_col_files += 1

            elif cat == FLIGHT_LOGS:
                if obs.get("non_readable"):
                    fl_non_readable += 1
                fmt = obs.get("format", "")
                if fmt == "crash_dump":
                    fl_crash_dump += 1
                elif fmt:
                    fl_format_counts[fmt] = fl_format_counts.get(fmt, 0) + 1

            elif cat == IMAGES:
                if obs.get("exif_zero_date"):
                    img_zero_date += 1
                if obs.get("exif_missing_gps"):
                    img_missing_gps += 1

            elif cat == VIDEOS:
                if obs.get("exif_zero_date"):
                    vid_zero_date += 1
                if obs.get("exif_missing_gps"):
                    vid_missing_gps += 1

    result = []
    for cat in list(CONTROLLER_ARTEFACT_CATEGORIES):
        notes: list[str] = []

        if cat == DATABASES:
            for sid, n in sorted(empty_db_by_src.items()):
                notes.append(f"{n} database(s) empty ({sid})")

        elif cat == FLIGHT_RECORDS:
            if fr_row_anomaly_files:
                notes.append(f"{fr_row_anomaly_files} file(s) with row anomalies")
            if fr_empty_col_files:
                notes.append(f"{fr_empty_col_files} file(s) with empty columns")
            if fr_const_col_files:
                notes.append(f"{fr_const_col_files} file(s) with constant-value columns")

        elif cat == DRONE_LOGS:
            if dl_row_anomaly_files:
                notes.append(f"{dl_row_anomaly_files} file(s) with row anomalies")
            if dl_empty_col_files:
                notes.append(f"{dl_empty_col_files} file(s) with empty columns")
            if dl_const_col_files:
                notes.append(f"{dl_const_col_files} file(s) with constant-value columns")

        elif cat == FLIGHT_LOGS:
            if fl_non_readable:
                notes.append(f"{fl_non_readable} file(s) unreadable (binary)")
            if fl_crash_dump:
                notes.append(f"{fl_crash_dump} crash dump(s)")
            if fl_format_counts:
                fmt_parts = ", ".join(
                    f"{n} {f}" for f, n in sorted(fl_format_counts.items())
                )
                notes.append(f"formats: {fmt_parts}")

        elif cat == IMAGES:
            if img_zero_date:
                notes.append(f"{img_zero_date} file(s) with zeroed EXIF timestamp")
            if img_missing_gps:
                notes.append(f"{img_missing_gps} file(s) missing GPS")

        elif cat == VIDEOS:
            if vid_zero_date:
                notes.append(f"{vid_zero_date} file(s) with zeroed EXIF timestamp")
            if vid_missing_gps:
                notes.append(f"{vid_missing_gps} file(s) missing GPS")

        result.append({
            "category": cat,
            "count": counts.get(cat, 0),
            "notes": notes,
        })
    return result


def _artefact_coverage_per_source(
    p3_artefacts: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Count extracted artefacts per source, broken down by category."""
    counts: dict[str, dict[str, int]] = {}
    for a in p3_artefacts:
        src = a.get("source_identification", "")
        cat = a.get("artefact_category", "")
        if src and cat:
            counts.setdefault(src, {})
            counts[src][cat] = counts[src].get(cat, 0) + 1

    return [
        {
            "source": src,
            "artefacts": [
                {"category": cat, "count": counts[src][cat]}
                for cat in CONTROLLER_ARTEFACT_CATEGORIES
                if cat in counts.get(src, {})
            ],
        }
        for src in SOURCE_IDENTIFICATION_TYPES
        if src in counts
    ]


# ---------------------------------------------------------------------------
# Section 2 — Tool execution status
# ---------------------------------------------------------------------------

def _tool_status(state: State) -> list[dict[str, Any]]:
    """Summarise per-tool execution results from the tool invocation log."""
    groups: dict[str, dict[str, int]] = {}
    for entry in state.tool_invocation_log:
        name = entry.get("tool_name", "unknown")
        rc = entry.get("return_code")
        if name not in groups:
            groups[name] = {"invocation_count": 0, "success_count": 0}
        groups[name]["invocation_count"] += 1
        if rc == 0 or rc is None:
            groups[name]["success_count"] += 1

    result = []
    for name in sorted(groups):
        g = groups[name]
        n = g["invocation_count"]
        s = g["success_count"]
        if s == n:
            status = "ok"
        elif s == 0:
            status = "failed"
        else:
            status = "partial"
        result.append({
            "tool": name,
            "invocation_count": n,
            "success_count": s,
            "status": status,
        })
    return result


# ---------------------------------------------------------------------------
# Section 3 — Account and drone identity analysis
# ---------------------------------------------------------------------------

def _norm_drone_name(name: str) -> str:
    """Normalise a drone name for fuzzy comparison: strip prefix up to '-', lowercase, remove spaces."""
    if "-" in name:
        name = name.split("-", 1)[-1]
    return re.sub(r"\s+", "", name).lower()


def _source_type_from_event(event: dict[str, Any]) -> str:
    """Determine if a timeline event comes from a drone-side source."""
    source = event.get("source", "")
    for drone_sid in _DRONE_SOURCE_IDS:
        if drone_sid in source:
            return "drone"
    return "controller"


def _collect_all_identity_sources(
    p2_obs: list[dict[str, Any]],
    p4_obs: list[dict[str, Any]],
    p6_flights: list[dict[str, Any]],
) -> dict[str, list[dict[str, Any]]]:
    """Collect all identity-field observations from P2, P4, and flight timeline Log started events.

    Returns a dict keyed by output field name. Each value is a list of entries:
      {"value": ..., "source_pointer": "p2/p4:sha" or "sha:rowID", "source_type": "controller"|"drone"}
    """
    fields: dict[str, list[dict[str, Any]]] = {
        "account_email": [],
        "drone_serial": [],
        "drone_name": [],
        "installed_dji_apps": [],
        "dji_app_version": [],
    }

    # P2: installed_dji_apps from device_and_backup_info
    for obs_dict in p2_obs:
        if obs_dict.get("evidence_category") != DEVICE_AND_BACKUP_INFO:
            continue
        sha = obs_dict.get("evidence_sha256", "")
        for obs in obs_dict.get("observations", []):
            val = obs.get("installed_dji_apps")
            if val is not None:
                fields["installed_dji_apps"].append({
                    "value": val,
                    "source_pointer": f"p2:{sha}",
                    "source_type": "controller",
                })

    # P4: account_data observations
    for obs_dict in p4_obs:
        if obs_dict.get("evidence_category") != ACCOUNT_DATA:
            continue
        sha = obs_dict.get("evidence_sha256", "")
        sp = f"p4:{sha}"
        for obs in obs_dict.get("observations", []):
            for p4_key, out_key in (
                ("account_email", "account_email"),
                ("aircraft_sn", "drone_serial"),
                ("cached_product_name", "drone_name"),
                ("app_version", "dji_app_version"),
            ):
                val = obs.get(p4_key)
                if val is not None:
                    fields[out_key].append({
                        "value": val,
                        "source_pointer": sp,
                        "source_type": "controller",
                    })

    # Timeline: Log started events
    for flight in p6_flights:
        tl_path = flight.get("stored_path", "")
        if not tl_path:
            continue
        try:
            tl = json.loads(Path(tl_path).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        for ev in tl.get("events", []):
            if ev.get("event") != "Log started":
                continue
            data = ev.get("data", {})
            sp = ev.get("source_pointer", "")
            stype = _source_type_from_event(ev)
            if data.get("serial_drone"):
                fields["drone_serial"].append({
                    "value": data["serial_drone"],
                    "source_pointer": sp,
                    "source_type": stype,
                })
            if data.get("name_drone"):
                fields["drone_name"].append({
                    "value": data["name_drone"],
                    "source_pointer": sp,
                    "source_type": stype,
                })
            if data.get("dji_app_version"):
                fields["dji_app_version"].append({
                    "value": data["dji_app_version"],
                    "source_pointer": sp,
                    "source_type": stype,
                })
    return fields


def _build_account_and_drone_analysis(
    identity_sources: dict[str, list[dict[str, Any]]],
    p4_obs: list[dict[str, Any]],
    p6_flights: list[dict[str, Any]],
) -> dict[str, Any]:
    """Build the account_and_drone_analysis block from collected identity sources."""
    result: dict[str, Any] = {}

    for field, entries in identity_sources.items():
        if not entries:
            continue

        # For drone_name: normalise values for comparison, but keep original for display
        if field == "drone_name":
            norm_to_canonical: dict[str, str] = {}
            for e in entries:
                n = _norm_drone_name(str(e["value"]))
                if n not in norm_to_canonical:
                    norm_to_canonical[n] = str(e["value"])
            unique_norms = set(norm_to_canonical.keys())
        else:
            unique_vals = {str(e["value"]) for e in entries}

        corroboration_sources = [e["source_pointer"] for e in entries]
        has_drone_source = any(e["source_type"] == "drone" for e in entries)

        if field == "drone_name":
            if len(unique_norms) == 1:
                value: Any = norm_to_canonical[next(iter(unique_norms))]
                confidence = "multi-source" if has_drone_source else "single-source"
            else:
                value = sorted(set(str(e["value"]) for e in entries))
                confidence = "inconsistent"
        elif field == "installed_dji_apps":
            # Value is a list — collect all unique lists (compare as sorted tuples)
            seen: list[list] = []
            for e in entries:
                v = e["value"] if isinstance(e["value"], list) else [e["value"]]
                if v not in seen:
                    seen.append(v)
            value = seen[0] if len(seen) == 1 else seen
            confidence = "multi-source" if has_drone_source else "single-source"
        else:
            if len(unique_vals) == 1:
                value = next(iter(unique_vals))
                confidence = "multi-source" if has_drone_source else "single-source"
            else:
                value = sorted(unique_vals)
                confidence = "inconsistent"

        result[field] = {
            "value": value,
            "corroboration_sources": corroboration_sources,
            "confidence": confidence,
        }

    return result


# ---------------------------------------------------------------------------
# Section 4 — Per-flight analysis
# ---------------------------------------------------------------------------

def _analyse_flight(
    flight_compact: dict[str, Any],
    p5_anomalies: list[dict[str, Any]],
) -> dict[str, Any]:
    """Derive analysis metrics for one flight from compact state data + timeline JSON."""
    tl_path = flight_compact.get("stored_path", "")
    try:
        tl = json.loads(Path(tl_path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        tl = {}

    events: list[dict[str, Any]] = tl.get("events", [])
    corr = flight_compact.get("correlation", {})
    fi = flight_compact.get("flights_identified", [])

    flight_shas = {seg.get("evidence_sha256", "") for seg in fi}
    high_conf = sum(1 for e in events if e.get("confidence") == "high")

    # Corroboration sources (from flights_identified + possibly_correlated)
    corroboration: list[str] = [seg.get("evidence_sha256", "") for seg in fi]
    for pc in flight_compact.get("possibly_correlated", []):
        sp = pc.get("source_pointer", "")
        corroboration.append(sp.removeprefix("p5:"))
    corroboration = sorted(set(corroboration) - {""})

    # Peak height
    peak_height: float | None = None
    for ev in events:
        if ev.get("event") == "Reached peak height":
            h = ev.get("data", {}).get("relative_height")
            if h is not None:
                try:
                    peak_height = float(h)
                except (ValueError, TypeError):
                    pass
            break

    # Distinct flight modes (insertion order preserved)
    flight_modes: list[str] = []
    seen_modes: set[str] = set()
    for ev in events:
        if ev.get("event") == "Fly mode changed":
            mode = ev.get("data", {}).get("fly_mode", "")
            if mode and mode not in seen_modes:
                flight_modes.append(mode)
                seen_modes.add(mode)

    # Distance travelled, photo count, video duration, homepoint fields — first Log ended event
    distance_travelled: float | None = None
    number_photos_taken: int | None = None
    duration_recording: float | None = None
    distance_to_homepoint: float | None = None
    log_ended_height: float | None = None
    for ev in events:
        if ev.get("event") == "Log ended":
            ev_data = ev.get("data", {})
            d = ev_data.get("distance_travelled")
            if d is not None:
                try:
                    distance_travelled = float(d)
                except (ValueError, TypeError):
                    pass
            p = ev_data.get("number_photos_taken")
            if p is not None:
                try:
                    number_photos_taken = int(p)
                except (ValueError, TypeError):
                    pass
            vt = ev_data.get("duration_recording")
            if vt is not None:
                try:
                    duration_recording = float(vt)
                except (ValueError, TypeError):
                    pass
            dh = ev_data.get("distance_to_homepoint")
            if dh is not None:
                try:
                    distance_to_homepoint = float(dh)
                except (ValueError, TypeError):
                    pass
            ht = ev_data.get("height")
            if ht is not None:
                try:
                    log_ended_height = float(ht)
                except (ValueError, TypeError):
                    pass
            break

    if distance_to_homepoint is not None and log_ended_height is not None:
        flight_record_complete: bool | None = (
            distance_to_homepoint < 3.0 and log_ended_height < 2.0
        )
    else:
        flight_record_complete = None

    # Photo taken — any Photo mode changed event with mode != "No"
    photo_taken = False
    for ev in events:
        if ev.get("event") == "Photo mode changed":
            mode = str(ev.get("data", {}).get("photo_mode", "No")).strip().lower()
            if mode not in ("no", ""):
                photo_taken = True
                break

    # Video taken — any Record mode changed event with mode not in {"No", ""}
    video_taken = False
    for ev in events:
        if ev.get("event") == "Record mode changed":
            mode = str(ev.get("data", {}).get("record_mode", "No")).strip().lower()
            if mode not in ("no", ""):
                video_taken = True
                break

    return {
        "flight_id": flight_compact.get("flight_id"),
        "matched": corr.get("matched", False),
        "correlation_confidence": corr.get("confidence"),
        "source_count": len(fi),
        "event_count": len(events),
        "high_confidence_event_count": high_conf,
        "peak_height_m": peak_height,
        "distance_travelled": distance_travelled,
        "photo_taken": photo_taken,
        "number_photos_taken": number_photos_taken,
        "video_taken": video_taken,
        "duration_recording": duration_recording,
        "flight_record_complete": flight_record_complete,
        "flight_modes_observed": flight_modes,
        "possibly_correlated_count": len(flight_compact.get("possibly_correlated", [])),
        "plausibly_correlated_count": len(flight_compact.get("plausibly_correlated", [])),
        "corroboration_sources": corroboration,
    }


# ---------------------------------------------------------------------------
# Section 5 — Uncorrelated artefacts (chain-aware)
# ---------------------------------------------------------------------------

def _build_lineage_map(
    p3_artefacts: list[dict[str, Any]],
    p4_artefacts: list[dict[str, Any]],
    p5_artefacts: list[dict[str, Any]],
) -> dict[str, frozenset[str]]:
    """Map every known sha256 to the full set of shas in its lineage chain."""
    # parent_map: child_sha → parent_sha
    parent_map: dict[str, str] = {}
    for a in (*p4_artefacts, *p5_artefacts):
        child = a.get("sha256", "")
        parent = a.get("parent_sha256", "")
        if child and parent:
            parent_map[child] = parent

    # Collect all shas
    all_shas: set[str] = set()
    for a in (*p3_artefacts, *p4_artefacts, *p5_artefacts):
        sha = a.get("sha256", "")
        if sha:
            all_shas.add(sha)

    # Build child_map: parent → set of children (for downward walk)
    child_map: dict[str, set[str]] = {}
    for child, parent in parent_map.items():
        child_map.setdefault(parent, set()).add(child)

    # For each sha, collect its full chain (all ancestors + all descendants)
    cache: dict[str, frozenset[str]] = {}

    def _collect_chain(sha: str) -> frozenset[str]:
        if sha in cache:
            return cache[sha]
        # Walk up to root
        chain: set[str] = {sha}
        cur = sha
        seen: set[str] = {sha}
        while cur in parent_map:
            cur = parent_map[cur]
            if cur in seen:
                break
            seen.add(cur)
            chain.add(cur)
        # Walk down from root to collect all descendants
        root = cur
        stack = [root]
        while stack:
            node = stack.pop()
            chain.add(node)
            for child in child_map.get(node, ()):
                if child not in chain:
                    chain.add(child)
                    stack.append(child)
        fs = frozenset(chain)
        # Cache for all members
        for s in fs:
            cache[s] = fs
        return fs

    result: dict[str, frozenset[str]] = {}
    for sha in all_shas:
        if sha not in result:
            chain = _collect_chain(sha)
            for s in chain:
                result[s] = chain
    return result


def _uncorrelated_artefacts(
    p3_artefacts: list[dict[str, Any]],
    p4_artefacts: list[dict[str, Any]],
    p5_artefacts: list[dict[str, Any]],
    p6_flights: list[dict[str, Any]],
    account_and_drone_analysis: dict[str, Any],
) -> list[dict[str, Any]]:
    """List P3 artefacts whose full lineage chain is not referenced anywhere."""
    # Build referenced sha set from flights
    referenced: set[str] = set()
    for flight in p6_flights:
        for seg in flight.get("flights_identified", []):
            sha = seg.get("evidence_sha256", "")
            if sha:
                referenced.add(sha)
        for pc in flight.get("plausibly_correlated", []):
            if isinstance(pc, str):
                referenced.add(pc.removeprefix("p5:"))
        for pc in flight.get("possibly_correlated", []):
            sp = pc.get("source_pointer", "")
            for prefix in ("p5:", "p4:"):
                sp = sp.removeprefix(prefix)
            if sp:
                referenced.add(sp)

    # Add shas from account_and_drone_analysis corroboration_sources
    for field_data in account_and_drone_analysis.values():
        if not isinstance(field_data, dict):
            continue
        for sp in field_data.get("corroboration_sources", []):
            # Strip "p4:", "p2:" prefixes; strip ":rowID" suffix
            raw = sp
            for prefix in ("p4:", "p2:", "p5:"):
                raw = raw.removeprefix(prefix)
            # Remove :rowID suffix (sha256 is 64 hex chars)
            if ":" in raw:
                raw = raw.split(":")[0]
            if raw:
                referenced.add(raw)
    referenced.discard("")

    lineage = _build_lineage_map(p3_artefacts, p4_artefacts, p5_artefacts)

    uncorrelated = []
    for a in p3_artefacts:
        sha = a.get("sha256", "")
        if not sha:
            continue
        chain = lineage.get(sha, frozenset({sha}))
        if not chain.intersection(referenced):
            uncorrelated.append({"evidence_sha256": sha})
    return uncorrelated


# ---------------------------------------------------------------------------
# Section 6 — Processing coverage score
# ---------------------------------------------------------------------------

def _coverage_score(
    source_coverage: list[dict[str, Any]],
    artefact_coverage: list[dict[str, Any]],
    tool_status: list[dict[str, Any]],
    p6_flights: list[dict[str, Any]],
) -> dict[str, Any]:
    """Return raw coverage ratios — no percentages, no synthetic scores."""
    sources_detected = sum(1 for s in source_coverage if s["detected"])
    cats_with_data = sum(1 for c in artefact_coverage if c["count"] > 0)
    flights_matched = sum(
        1 for f in p6_flights if f.get("correlation", {}).get("matched", False)
    )
    tools_ok = sum(1 for t in tool_status if t["status"] == "ok")

    return {
        "evidence_sources_detected": {
            "value": sources_detected,
            "total": len(source_coverage),
        },
        "artefact_categories_with_data": {
            "value": cats_with_data,
            "total": len(artefact_coverage),
        },
        "flights_with_primary_correlation": {
            "value": flights_matched,
            "total": len(p6_flights),
        },
        "tools_succeeded": {
            "value": tools_ok,
            "total": len(tool_status),
        },
    }


# ---------------------------------------------------------------------------
# Section 7 — Forensic statements
# ---------------------------------------------------------------------------

def _forensic_conclusions(
    source_coverage: list[dict[str, Any]],
    flight_analyses: list[dict[str, Any]],
    account_and_drone: dict[str, Any],
    artefact_coverage: list[dict[str, Any]],
    p4_artefacts: list[dict[str, Any]],
) -> tuple[list[str], list[str]]:
    """Return (safe_statements, further_investigation) as lists of hedged strings."""
    safe: list[str] = []
    investigate: list[str] = []

    # Sources
    detected = [s["source"] for s in source_coverage if s["detected"]]
    safe.append(f"{len(detected)} evidence source(s) detected: {', '.join(detected)}.")

    # Flights
    total_flights = len(flight_analyses)
    matched = [f for f in flight_analyses if f["matched"]]
    high_conf = [f for f in matched if f.get("correlation_confidence") == "high"]
    safe.append(
        f"{total_flights} flight(s) identified; "
        f"{len(matched)} with primary GPS+temporal correlation "
        f"({len(high_conf)} high confidence)."
    )

    unmatched = [f for f in flight_analyses if not f["matched"]]
    if unmatched:
        ids = ", ".join(f["flight_id"] for f in unmatched)
        investigate.append(
            f"{len(unmatched)} flight record(s) could not be correlated to a drone log "
            f"({ids}) — independent corroboration is absent for these flight(s)."
        )

    incomplete = [f for f in flight_analyses if f.get("flight_record_complete") is False]
    if incomplete:
        ids = ", ".join(f["flight_id"] for f in incomplete)
        investigate.append(
            f"Flight record shows signs of corruption, additional analysis needed ({ids})."
        )

    total_plausible = sum(f.get("plausibly_correlated_count", 0) for f in flight_analyses)
    total_possible = sum(f.get("possibly_correlated_count", 0) for f in flight_analyses)
    if total_plausible > 0:
        investigate.append(
            f"{total_plausible} file(s) plausibly correlated — needs additional analysis."
        )
    if total_possible > 0:
        investigate.append(
            f"{total_possible} file(s) possibly correlated — needs additional analysis."
        )

    # Media capture indicators from flight event analysis
    has_info_file = any(
        a.get("acquisition_method") == ACQUISITION_SELECT_ACCOUNT_DATA
        and a.get("artefact_category") == VIDEOS
        for a in p4_artefacts
    )
    if any(f.get("video_taken") for f in flight_analyses):
        msg = "Flight analysis suspects a video was recorded"
        if has_info_file:
            msg += " — inspect .info file"
        investigate.append(msg + ".")
    if any(f.get("photo_taken") for f in flight_analyses):
        if any(
            f.get("photo_taken") and (f.get("number_photos_taken") or 0) > 0
            for f in flight_analyses
        ):
            investigate.append(
                "There were photo(s) taken that may reside both on controller and drone_sd"
                " - additional analysis needed."
            )
        else:
            investigate.append("Flight analysis suspects a photo was taken.")

    # Account / drone identity
    sn = account_and_drone.get("drone_serial")
    if sn:
        if sn["confidence"] == "inconsistent":
            investigate.append(
                f"Drone serial number inconsistency detected: "
                f"values observed: {', '.join(sn['value'])}."
            )
        else:
            v = sn["value"]
            safe.append(f"Drone serial number: {v} (confidence: {sn['confidence']}).")

    name = account_and_drone.get("drone_name")
    if name and name["confidence"] != "inconsistent":
        safe.append(f"Drone name: {name['value']} (confidence: {name['confidence']}).")

    app_ver = account_and_drone.get("dji_app_version")
    if app_ver and app_ver["confidence"] != "inconsistent":
        safe.append(
            f"DJI app version: {app_ver['value']} (confidence: {app_ver['confidence']})."
        )

    apps = account_and_drone.get("installed_dji_apps")
    if apps:
        val = apps["value"]
        if isinstance(val, list) and not isinstance(val[0], list):
            safe.append(
                f"Installed DJI apps: {', '.join(str(v) for v in val)} "
                f"(confidence: {apps['confidence']})."
            )

    # Data quality from artefact_coverage notes
    for cov in artefact_coverage:
        cat = cov["category"]
        total = cov.get("count", 0)
        total_empty = sum(
            int(note.split()[0])
            for note in cov["notes"]
            if "database(s) empty" in note and note.split()[0].isdigit()
        )
        if cat == DATABASES and total > 0:
            non_empty = total - total_empty
            if non_empty > 0:
                investigate.append(
                    f"{non_empty} database file(s) contain records and should be inspected for relevant artefacts."
                )
            if total_empty > 0:
                pass  # covered by safe statement below
        for note in cov["notes"]:
            if "empty" in note and cat == DATABASES:
                safe.append(
                    f"{note} — no database records available for further analysis."
                )
            elif "zeroed EXIF" in note:
                investigate.append(
                    f"{cat}: {note} — correlation of media needs additional analysis."
                )
            elif "unreadable" in note:
                investigate.append(
                    f"{cat}: {note} — content could not be parsed."
                )
            elif "crash dump" in note:
                investigate.append(
                    f"{cat}: {note} — application instability was recorded."
                )

    return safe, investigate


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def run_phase_7(state: State) -> State:
    """Phase 7: Analysis and Validation."""
    # Load prior phase outputs
    p2 = state.phase_outputs.get("p2_image_parsing", {})
    p2_obs: list[dict[str, Any]] = p2.get("derived_observations", [])

    p3 = state.phase_outputs.get("p3_artefact_extraction", {})
    p3_artefacts: list[dict[str, Any]] = p3.get("extracted_artefacts", [])

    p4 = state.phase_outputs.get("p4_decision_and_orchestration", {})
    p4_obs: list[dict[str, Any]] = p4.get("derived_observations", [])
    p4_artefacts: list[dict[str, Any]] = p4.get("decision_and_orchestration_artefacts", [])

    p5 = state.phase_outputs.get("p5_normalisation_and_anomaly_checking", {})
    p5_anomalies: list[dict[str, Any]] = p5.get("derived_anomalies", [])
    p5_artefacts: list[dict[str, Any]] = p5.get("normalised_artefacts", [])

    p6 = state.phase_outputs.get("p6_multisource_correlation", {})
    p6_flights: list[dict[str, Any]] = p6.get("flights", [])

    # Compute each analysis section
    source_cov = _source_coverage(state)
    artefact_cov = _artefact_coverage(p3_artefacts, p5_anomalies)
    artefact_cov_per_source = _artefact_coverage_per_source(p3_artefacts)
    tool_stat = _tool_status(state)

    identity_sources = _collect_all_identity_sources(p2_obs, p4_obs, p6_flights)
    account_and_drone = _build_account_and_drone_analysis(identity_sources, p4_obs, p6_flights)

    flight_analyses = [_analyse_flight(f, p5_anomalies) for f in p6_flights]

    uncorrelated = _uncorrelated_artefacts(
        p3_artefacts, p4_artefacts, p5_artefacts, p6_flights, account_and_drone
    )

    cov_score = _coverage_score(source_cov, artefact_cov, tool_stat, p6_flights)
    safe_stmts, further = _forensic_conclusions(
        source_cov, flight_analyses, account_and_drone, artefact_cov, p4_artefacts
    )

    state.phase_outputs[_PHASE_NAME] = {
        "completed_at": utc_now_iso(),
        "flight_count_analysed": len(flight_analyses),
        "source_coverage": source_cov,
        "artefact_coverage": artefact_cov,
        "artefact_coverage_per_source": artefact_cov_per_source,
        "tool_status": tool_stat,
        "account_and_drone_analysis": account_and_drone,
        "flight_analyses": flight_analyses,
        "uncorrelated_artefacts": uncorrelated,
        "coverage_score": cov_score,
        "safe_statements": safe_stmts,
        "further_investigation": further,
    }
    state.completed_phases.append(_PHASE_NAME)
    print(f"  Analysis complete: {len(flight_analyses)} flight(s) analysed.")
    return state
