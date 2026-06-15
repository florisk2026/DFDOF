"""DFDOF Phase 6: Multi-Source Correlation.

This phase:
 - creates a phase 6 output directory,
 - loads P5-normalised FLIGHT_RECORDS and DRONE_LOGS CSVs,
 - correlates each flight record against each drone log by temporal overlap
   and spatial distance (primary GPS rule),
 - builds a unified per-flight event timeline with ordered events,
 - writes one timeline_flightXX.json per identified flight and a compact state summary.
"""

from __future__ import annotations

import bisect
import csv
import re
import statistics
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from config import (
    ACQUISITION_EXIFTOOL,
    ACQUISITION_NORMALISE,
    DRONE_LOGS,
    FLIGHT_LOGS,
    FLIGHT_RECORDS,
    IDENTIFICATION_CONTROLLER_ANDROID,
    IDENTIFICATION_CONTROLLER_IOS,
    VIDEOS,
    clear_and_make,
    output_dir,
    utc_now_iso,
    _write_no_output,
    _has_real_output,
)
from phases.utils_phase import haversine_m, resolve_col, write_json
from state import State

_PHASE_NAME = Path(__file__).stem

# ===========================================================================
# PHASE 6: MULTI-SOURCE CORRELATION CONFIGURATION & THRESHOLD JUSTIFICATION
# ===========================================================================
# FORENSIC METHODOLOGY NOTE:
# These thresholds govern the decision logic for pairing drone logs with flight
# records and for extracting discrete flight events from telemetry streams. They
# are conservative engineering choices designed to minimise false correlations;
# no single threshold constitutes definitive proof of a matched or unmatched flight.
#
# Threshold Derivation Matrix:
# 1. Correlation Geometry : Temporal overlap and spatial plausibility bounds
# 2. Flight Physics       : Manufacturer-grounded event-detection boundaries
# 3. GNSS Engineering     : Multi-lateral satellite positioning constraints
# ===========================================================================

# Category 1: Correlation Geometry (Conservative Plausibility Bounds)

# Primary GPS-assisted temporal overlap floor (seconds) and minimum fraction.
# DatCon at 30 Hz, FlightRecord at 10 Hz — 60 s yields ≥600 rows at the slower rate,
# sufficient for meaningful spatial comparison. The 75 % fraction requirement
# accommodates the real-world timing difference between DAT logs (which start at
# drone power-on) and flight records (which start when the DJI app connects, often
# 30–60 s later). The FR may also extend past the DAT log end when the app
# disconnects after the firmware has already closed the DAT file. The spatial
# check (median GPS ≤ 25 m) provides the forensically strong confirmation.
_OVERLAP_MIN_S = 60.0
_OVERLAP_MIN_FRACTION = 0.75

# Half-width of the bisect window for nearest-neighbour GPS point matching (seconds).
# A ±2 s association gate absorbs independent-clock offsets between log sources
# without pairing GPS points from different manoeuvres.
_SPATIAL_WINDOW_S = 2.0

# Maximum median haversine distance for two candidates to represent the same flight.
# Consumer DJI GPS achieves ±1.5–3 m CEP; ICAO Annex 10 SPS horizontal accuracy is
# 13 m at 95 %. 25 m accommodates multipath and poor-fix conditions while firmly
# excluding flights from distinct aircraft (typical separation far exceeds 25 m).
_SPATIAL_MAX_MEDIAN_M = 25.0

# Minimum GPS point pairs required to compute a valid median distance.
# Fewer than 5 matched pairs do not characterise the spatial relationship reliably;
# the flight pair is left unmatched below this count.
_SPATIAL_MIN_PAIRS = 5

# Valid year range for drone operation timestamps.
# Filters DatCon GPS:dateTimeStamp firmware sentinels (year 1980 — GPS epoch
# default before fix; year 3236 — DJI firmware uninitialized value).
_VALID_YEAR_MIN = 2006   # year of first DJI consumer drone
_VALID_YEAR_MAX = 2099   # far-future sentinel guard

# Column name constants (mirrors P5)

# DatCon
_DRONE_TS_COL          = "[NORM]:GPS:dateTimeStamp"
_DRONE_CLOCK_COL       = "Clock:offsetTime"
_DRONE_COMPUTED_TS_COL = "[DERIVED]:UTC"   # in-memory only; not written to disk
# GPS lat/lon column names vary by DatCon version and drone platform.
# Newer DatCon (Mavic Air, etc.) uses GPS:Lat/GPS:Long; older Phantom 3 firmware
# uses GPS(0):Lat/GPS(0):Long. resolve_col() picks the first match at build time.
_DRONE_LAT_CANDIDATES   = ("GPS:Lat",   "GPS(0):Lat",  "IMUCalcs(0):Lat:C")
_DRONE_LON_CANDIDATES   = ("GPS:Long",  "GPS(0):Long", "IMUCalcs(0):Long:C")
_DRONE_MODE_CANDIDATES  = ("Controller:ctrl_mode",
                            "AirCraftCondition:craft_flight_mode",
                            "osd_data:flyCState")
_DRONE_MOTOR_CANDIDATES = ("Controller:motor_state",)  # prefix fallback handles :D suffix
_DRONE_ALT_COL    = "IMU_ATTI(0):alti:D"
_DRONE_HEIGHT_COL = "IMUCalcs(0):height:C"
_DRONE_DIST_COL   = "IMU_ATTI(0):distanceTravelled:C"
_DRONE_WARN_COL   = "eventLog"
_DRONE_ATTR_COL   = "Attribute|Value"

# FlightRecord
_FR_TS_COL     = "[NORM]:CUSTOM.updateTime"
_FR_LAT_COL    = "OSD.latitude"
_FR_LON_COL    = "OSD.longitude"
_FR_ALT_COL    = "OSD.altitude [m]"
_FR_STATE_COL  = "OSD.flycState"
_FR_HEIGHT_COL = "OSD.height [m]"
_FR_MOTOR_COL  = "OSD.isMotorUp"
_FR_DIST_COL          = "CALC.travelled [m]"
_FR_HOMEPOINT_COL     = "CALC.distance [m]"
_FR_GROUND_OR_SKY_COL = "OSD.groundOrSky"
_FR_DETAILS_APP_TYPE    = "DETAILS.appType"
_FR_DETAILS_APP_VER     = "DETAILS.appVersion"
_FR_DETAILS_AC_NAME     = "DETAILS.droneType"
_FR_DETAILS_AC_SN       = "DETAILS.aircraftSnBytes"
_FR_DETAILS_BATT_SN     = "DETAILS.batterySn"
_FR_DETAILS_RC_SN       = "DETAILS.rcSn"
_FR_DETAILS_CAM_SN      = "DETAILS.cameraSn"
_FR_DETAILS_PHOTO_NUM   = "DETAILS.photoNum"
_FR_DETAILS_VIDEO_TIME  = "DETAILS.videoTime [s]"
_FR_WARN_COL      = "APP_WARN.warn"
_FR_TIP_COL       = "APP_TIP.tip"
_FR_REC_STATE_COL = "CAMERA_INFO.recordState"
_FR_PHOTO_COL     = "CAMERA_INFO.photoState"
_FR_SD_COL        = "CAMERA_INFO.sdCardState"

def _try_float(value: str) -> float | None:
    """Return float(value) or None on parse failure."""
    try:
        return float(value)
    except (ValueError, TypeError):
        return None


def _norm_msg(s: str) -> str:
    """Normalise a log message for cross-format comparison.

    Absorbs level-prefix formatting differences ([Warning] vs Warning:),
    punctuation variation (comma vs period), non-breaking spaces, and
    Unicode replacement characters that arise from different DJI subsystems
    encoding the same event text differently.
    """
    s = s.lower()
    s = s.replace("\xa0", " ").replace("�", " ")
    s = re.sub(r"[,\.:\;\!\?\[\]]", " ", s)
    s = re.sub(r"\s+", " ", s).strip()
    return s


def _load_csv_rows(path: Path) -> tuple[list[str], list[dict[str, str]]]:
    """Read a normalised CSV into (header, rows) — single read, held in memory.

    Each row is a dict keyed by header name; short rows are padded with "".
    Returns ([], []) on missing file or IO error.
    """
    try:
        with path.open(encoding="utf-8", errors="replace", newline="") as fh:
            reader = csv.reader(fh)
            try:
                header = next(reader)
            except StopIteration:
                return [], []
            rows: list[dict[str, str]] = []
            for raw in reader:
                padded = raw + [""] * max(0, len(header) - len(raw))
                rows.append(dict(zip(header, padded)))
            return header, rows
    except OSError:
        return [], []


def _get_ts(row: dict[str, str], ts_col: str) -> datetime | None:
    """Parse the normalised UTC timestamp column from a row dict.

    Both [NORM] columns are already ISO 8601 +00:00 after P5 normalisation.
    Returns a timezone-aware datetime or None.
    Timestamps outside _VALID_YEAR_MIN–_VALID_YEAR_MAX are rejected; DatCon
    emits GPS epoch defaults (year 1980) and firmware sentinels (year 3236)
    before the GPS module acquires a proper fix.
    """
    val = row.get(ts_col, "").strip()
    if not val:
        return None
    try:
        dt = datetime.fromisoformat(val)
    except ValueError:
        return None
    if dt.tzinfo is None:
        return None  # timezone unknown — cannot confirm UTC
    if not (_VALID_YEAR_MIN <= dt.year <= _VALID_YEAR_MAX):
        return None  # garbage GPS firmware value
    return dt


def _build_time_index(
    rows: list[dict[str, str]], ts_col: str
) -> list[tuple[datetime, int]]:
    """Build sorted (datetime, row_list_index) pairs for O(log n) lookup."""
    index: list[tuple[datetime, int]] = []
    for i, row in enumerate(rows):
        dt = _get_ts(row, ts_col)
        if dt is not None:
            index.append((dt, i))
    index.sort(key=lambda t: t[0])
    return index


def _anchor_drone_timestamps(
    rows: list[dict[str, str]], ts_col: str, clock_col: str
) -> list[datetime | None]:
    """Derive absolute UTC for every drone log row via Clock:offsetTime anchoring.

    DatCon GPS:dateTimeStamp is unreliable before the GPS module acquires a
    proper fix — rows before lock carry firmware sentinels (year 3236) or GPS
    epoch defaults (year 1980). Clock:offsetTime is a monotonic counter
    (seconds since recording start) that is always reliable.

    This function finds the first GPS timestamp with a plausible year and uses
    its Clock:offsetTime value as an anchor to back-compute UTC for all rows:
        UTC(row) = anchor_utc + (row_clock - anchor_clock) seconds

    Returns a list of datetime|None, one per row. Returns [None]*len(rows) if
    no valid GPS anchor exists (e.g. drone log with no GPS fix at all).
    """
    anchor_utc: datetime | None = None
    anchor_clock: float | None = None
    for row in rows:
        ts = _get_ts(row, ts_col)  # already filters garbage years
        if ts is not None:
            clock_val = _try_float(row.get(clock_col, ""))
            if clock_val is not None:
                anchor_utc = ts
                anchor_clock = clock_val
                break

    if anchor_utc is None:
        return [None] * len(rows)
    assert anchor_clock is not None

    result: list[datetime | None] = []
    for row in rows:
        clock_val = _try_float(row.get(clock_col, ""))
        if clock_val is None:
            result.append(None)
        else:
            result.append(anchor_utc + timedelta(seconds=clock_val - anchor_clock))
    return result


def _build_candidate(
    evidence_dict: dict[str, Any],
    rows: list[dict[str, str]],
    ts_col: str,
    lat_col: str,
    lon_col: str,
    header: list[str],
) -> dict[str, Any] | None:
    """Build a FlightCandidate dict from an in-memory CSV row list.

    Returns None if no parseable timestamps exist (artefact is unusable).
    The returned dict holds references to the row list and header — not copies.
    """
    start_dt: datetime | None = None
    end_dt: datetime | None = None
    gps_count = 0

    for row in rows:
        dt = _get_ts(row, ts_col)
        if dt is not None:
            if start_dt is None or dt < start_dt:
                start_dt = dt
            if end_dt is None or dt > end_dt:
                end_dt = dt

        lat = _try_float(row.get(lat_col, ""))
        lon = _try_float(row.get(lon_col, ""))
        if lat is not None and lon is not None and (lat != 0.0 or lon != 0.0):
            gps_count += 1

    if start_dt is None:
        return None

    duration_s = (end_dt - start_dt).total_seconds() if end_dt else 0.0

    app_version: str | None = _fr_log_start_extras(rows).get("dji_app_version")

    return {
        "evidence_dict": evidence_dict,
        "rows": rows,
        "header": header,
        "ts_col": ts_col,
        "lat_col": lat_col,
        "lon_col": lon_col,
        "start_dt": start_dt,
        "end_dt": end_dt,
        "duration_s": duration_s,
        "gps_count": gps_count,
        "has_usable_gps": gps_count >= 10,
        "time_index": None,  # populated externally for drone candidates
        "app_version": app_version,
    }


def _compute_overlap(cand_a: dict[str, Any], cand_b: dict[str, Any]) -> float:
    """Return temporal overlap in seconds between two flight candidates."""
    lo = max(cand_a["start_dt"], cand_b["start_dt"])
    hi = min(cand_a["end_dt"], cand_b["end_dt"])
    return max(0.0, (hi - lo).total_seconds())


_FR_DEDUP_DURATION_DIFF_S = 5.0

# Source identifications considered "controller-side" for corroboration.
# Unmatched drone log candidates from these sources are cached copies on the
# paired controller — they corroborate drone-controller pairing but do not
# generate independent events (events are already captured from the primary DL).
_CONTROLLER_SOURCES: frozenset[str] = frozenset({
    IDENTIFICATION_CONTROLLER_IOS,
    IDENTIFICATION_CONTROLLER_ANDROID,
})


def _deduplicate_fr_candidates(
    candidates: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Remove FR candidates representing the same physical flight (multi-app scenario).

    Two FRs are considered the same flight when their temporal overlap meets the
    primary correlation floor (_OVERLAP_MIN_S) AND their durations differ by less
    than _FR_DEDUP_DURATION_DIFF_S. The candidate with more GPS points survives;
    ties keep the first occurrence (stable).
    """
    if len(candidates) <= 1:
        return candidates
    kept: list[dict[str, Any]] = []
    for cand in candidates:
        for i, existing in enumerate(kept):
            overlap = _compute_overlap(cand, existing)
            dur_diff = abs(cand["duration_s"] - existing["duration_s"])
            if overlap >= _OVERLAP_MIN_S and dur_diff < _FR_DEDUP_DURATION_DIFF_S:
                if cand["gps_count"] > existing["gps_count"]:
                    kept[i] = cand
                break
        else:
            kept.append(cand)
    return kept


def _compute_spatial(
    fr_cand: dict[str, Any],
    drone_cand: dict[str, Any],
) -> tuple[float | None, float]:
    """Return (median_distance_m, match_rate) using bisect nearest-neighbour.

    For each FR row with valid GPS, find the nearest drone row within
    ±_SPATIAL_WINDOW_S seconds. Returns (None, 0.0) if < _SPATIAL_MIN_PAIRS
    matched pairs found.
    """
    time_index: list[tuple[datetime, int]] = drone_cand["time_index"] or []
    if not time_index:
        return None, 0.0

    dt_list = [t[0] for t in time_index]
    drone_rows = drone_cand["rows"]

    distances: list[float] = []
    fr_gps_total = 0

    for row in fr_cand["rows"]:
        fr_dt = _get_ts(row, fr_cand["ts_col"])
        if fr_dt is None:
            continue
        fr_lat = _try_float(row.get(fr_cand["lat_col"], ""))
        fr_lon = _try_float(row.get(fr_cand["lon_col"], ""))
        if fr_lat is None or fr_lon is None or (fr_lat == 0.0 and fr_lon == 0.0):
            continue
        fr_gps_total += 1

        lo_dt = datetime.fromtimestamp(
            fr_dt.timestamp() - _SPATIAL_WINDOW_S, tz=timezone.utc
        )
        hi_dt = datetime.fromtimestamp(
            fr_dt.timestamp() + _SPATIAL_WINDOW_S, tz=timezone.utc
        )
        left = bisect.bisect_left(dt_list, lo_dt)
        right = bisect.bisect_right(dt_list, hi_dt)
        if left >= right:
            continue

        best_idx: int | None = None
        best_delta = float("inf")
        for k in range(left, right):
            delta = abs((dt_list[k] - fr_dt).total_seconds())
            if delta < best_delta:
                best_delta = delta
                best_idx = time_index[k][1]

        if best_idx is not None:
            d_row = drone_rows[best_idx]
            d_lat = _try_float(d_row.get(drone_cand["lat_col"], ""))
            d_lon = _try_float(d_row.get(drone_cand["lon_col"], ""))
            if d_lat is not None and d_lon is not None and (d_lat != 0.0 or d_lon != 0.0):
                distances.append(haversine_m(fr_lat, fr_lon, d_lat, d_lon))

    if len(distances) < _SPATIAL_MIN_PAIRS or fr_gps_total == 0:
        return None, 0.0

    match_rate = len(distances) / fr_gps_total
    return statistics.median(distances), match_rate


def _make_event(
    *,
    timestamp: str | None,
    timezone: str,
    source: str,
    source_pointer: str | None,
    event: str,
    data: dict[str, Any],
    confidence: str,
) -> dict[str, Any]:
    """Return a canonical event dict with all required schema fields."""
    ts = timestamp.strip() if isinstance(timestamp, str) else timestamp
    return {
        "timestamp": ts or None,
        "timezone": timezone,
        "source": source,
        "source_pointer": source_pointer,
        "event": event,
        "data": data,
        "confidence": confidence,
    }


def _ts_timezone(ts_str: str) -> str:
    """Return "UTC" if the timestamp string carries an explicit UTC marker, else "unknown"."""
    s = ts_str.strip()
    if s.endswith("Z") or "+00:00" in s or "+0000" in s:
        return "UTC"
    return "unknown"


def _event_data_drone(lat_col: str, lon_col: str):
    """Return an event-data builder for drone log rows using the resolved GPS columns."""
    def _fn(rows: list[dict[str, str]], row_id: int) -> dict[str, Any]:
        row = rows[row_id]
        return {
            "latitude":  _try_float(row.get(lat_col, "")),
            "longitude": _try_float(row.get(lon_col, "")),
            "altitude":  _try_float(row.get(_DRONE_ALT_COL, "")),
        }
    return _fn


def _event_data_fr(rows: list[dict[str, str]], row_id: int) -> dict[str, Any]:
    """Standard event data block for a flight record row."""
    row = rows[row_id]
    return {
        "latitude":  _try_float(row.get(_FR_LAT_COL, "")),
        "longitude": _try_float(row.get(_FR_LON_COL, "")),
        "altitude":  _try_float(row.get(_FR_ALT_COL, "")),
    }


def _event_confidence(ts_str: str, coord: dict[str, Any]) -> str:
    """Four-tier confidence based on GPS presence and UTC timestamp certainty."""
    lat = coord.get("latitude")
    lon = coord.get("longitude")
    has_gps = lat is not None and lon is not None and (lat != 0.0 or lon != 0.0)
    ts_utc = _ts_timezone(ts_str) == "UTC"
    if has_gps and ts_utc:
        return "high"
    if has_gps or ts_utc:
        return "medium"
    return "low"


def _drone_log_start_extras(rows: list[dict[str, str]]) -> dict[str, Any]:
    """Extract name_drone from the ACType Attribute|Value row."""
    for row in rows:
        cell = row.get(_DRONE_ATTR_COL, "").strip()
        if cell.startswith("ACType|"):
            return {"name_drone": cell.split("|", 1)[1].strip() or None}
    return {"name_drone": None}


def _fr_log_start_extras(rows: list[dict[str, str]]) -> dict[str, Any]:
    """Extract DETAILS metadata fields from the first populated row."""
    for row in rows:
        def _get(col: str) -> str | None:
            v = row.get(col, "").strip()
            return v or None
        phone_os        = _get(_FR_DETAILS_APP_TYPE)
        dji_app_version = _get(_FR_DETAILS_APP_VER)
        name_drone      = _get(_FR_DETAILS_AC_NAME)
        serial_drone    = _get(_FR_DETAILS_AC_SN)
        serial_battery  = _get(_FR_DETAILS_BATT_SN)
        serial_controller = _get(_FR_DETAILS_RC_SN)
        serial_camera   = _get(_FR_DETAILS_CAM_SN)
        if any(v is not None for v in (
            phone_os, dji_app_version, name_drone,
            serial_drone, serial_battery, serial_controller, serial_camera,
        )):
            return {
                "phone_os":           phone_os,
                "dji_app_version":    dji_app_version,
                "name_drone":         name_drone,
                "serial_drone":       serial_drone,
                "serial_battery":     serial_battery,
                "serial_controller":  serial_controller,
                "serial_camera":      serial_camera,
            }
    return {
        "phone_os": None, "dji_app_version": None, "name_drone": None,
        "serial_drone": None, "serial_battery": None,
        "serial_controller": None, "serial_camera": None,
    }


def _fr_log_end_extras(rows: list[dict[str, str]]) -> dict[str, Any]:
    """Read photo count and video duration from the last DETAILS row."""
    last = next(
        (r for r in reversed(rows) if r.get(_FR_DETAILS_PHOTO_NUM, "") != ""),
        None,
    )
    if last is None:
        return {}
    result: dict[str, Any] = {}
    photo = _try_float(last.get(_FR_DETAILS_PHOTO_NUM, ""))
    if photo is not None:
        result["number_photos_taken"] = int(photo)
    video = _try_float(last.get(_FR_DETAILS_VIDEO_TIME, ""))
    if video is not None:
        result["duration_recording"] = video
    return result


def _boundary_events(
    cand: dict[str, Any],
    data_fn: Any,
    ts_col: str,
    dist_col: str,
    start_extras_fn: Any = None,
    end_extras_fn: Any = None,
) -> list[dict[str, Any]]:
    """Return [log_started, log_ended] events for a single flight candidate."""
    ev_dict = cand["evidence_dict"]
    app_ver = cand.get("app_version")
    source = (
        f"{ev_dict.get('source_identification', '')}:{ev_dict.get('artefact_category', '')}"
        + (f" (v{app_ver})" if app_ver else "")
    )
    sha = ev_dict.get("sha256", "")
    rows = cand["rows"]

    first_idx = next((i for i, r in enumerate(rows) if _get_ts(r, ts_col) is not None), None)
    last_idx = next((i for i, r in enumerate(reversed(rows)) if _get_ts(r, ts_col) is not None), None)
    if last_idx is not None:
        last_idx = len(rows) - 1 - last_idx

    extras = start_extras_fn(rows) if start_extras_fn is not None else {}

    events = []
    for idx, label in ((first_idx, "Log started"), (last_idx, "Log ended")):
        if idx is None:
            continue
        row = rows[idx]
        ts_val = row.get(ts_col, "")
        norm_id = row.get("[NORM]:ID", "")
        data = data_fn(rows, idx)
        if label == "Log started":
            data = {**data, **extras}
        if label == "Log ended":
            end_extras = end_extras_fn(rows) if end_extras_fn is not None else {}
            gos = row.get(_FR_GROUND_OR_SKY_COL, "").strip() or None
            data = {
                **data,
                "distance_travelled": _try_float(row.get(dist_col, "")),
                "ground_or_sky": gos,
                "height": _try_float(row.get(_FR_HEIGHT_COL, "")),
                "distance_to_homepoint": _try_float(row.get(_FR_HOMEPOINT_COL, "")),
                **end_extras,
            }
        events.append(_make_event(
            timestamp=ts_val,
            timezone=_ts_timezone(ts_val),
            source=source,
            source_pointer=f"{sha}:{norm_id}",
            event=label,
            data=data,
            confidence=_event_confidence(ts_val, data),
        ))
    return events


def _peak_height_event(
    cand: dict[str, Any],
    data_fn: Any,
    ts_col: str,
    height_col: str,
) -> dict[str, Any] | None:
    """Return a single 'Reached peak height' event for the highest row."""
    ev_dict = cand["evidence_dict"]
    app_ver = cand.get("app_version")
    source = (
        f"{ev_dict.get('source_identification', '')}:{ev_dict.get('artefact_category', '')}"
        + (f" (v{app_ver})" if app_ver else "")
    )
    sha = ev_dict.get("sha256", "")
    rows = cand["rows"]

    best_idx: int | None = None
    best_h = float("-inf")
    for i, row in enumerate(rows):
        h = _try_float(row.get(height_col, ""))
        if h is not None and h > best_h:
            best_h = h
            best_idx = i

    if best_idx is None:
        return None

    row = rows[best_idx]
    ts_val = row.get(ts_col, "")
    norm_id = row.get("[NORM]:ID", "")
    data = {**data_fn(rows, best_idx), "relative_height": best_h}
    return _make_event(
        timestamp=ts_val,
        timezone=_ts_timezone(ts_val),
        source=source,
        source_pointer=f"{sha}:{norm_id}",
        event="Reached peak height",
        data=data,
        confidence=_event_confidence(ts_val, data),
    )


def _motor_events(
    cand: dict[str, Any],
    data_fn: Any,
    ts_col: str,
    motor_col: str,
    on_val: str,
    off_val: str,
) -> list[dict[str, Any]]:
    """Return events for motor state: initial state + every transition."""
    ev_dict = cand["evidence_dict"]
    app_ver = cand.get("app_version")
    source = (
        f"{ev_dict.get('source_identification', '')}:{ev_dict.get('artefact_category', '')}"
        + (f" (v{app_ver})" if app_ver else "")
    )
    sha = ev_dict.get("sha256", "")
    rows = cand["rows"]

    events = []
    prev: str | None = None
    for i, row in enumerate(rows):
        raw = row.get(motor_col, "").strip().upper()
        if not raw:
            continue
        if raw == on_val.upper():
            state = "on"
        elif raw == off_val.upper():
            state = "off"
        else:
            continue
        if prev is None or state != prev:
            label = "Motor turned on" if state == "on" else "Motor turned off"
            ts_val = row.get(ts_col, "")
            norm_id = row.get("[NORM]:ID", "")
            data = {**data_fn(rows, i), "motor_state": state}
            events.append(_make_event(
                timestamp=ts_val,
                timezone=_ts_timezone(ts_val),
                source=source,
                source_pointer=f"{sha}:{norm_id}",
                event=label,
                data=data,
                confidence=_event_confidence(ts_val, data),
            ))
            prev = state
    return events


def _fly_mode_events(
    cand: dict[str, Any],
    data_fn: Any,
    ts_col: str,
    mode_col: str,
) -> list[dict[str, Any]]:
    """Return an event for every fly-mode change (value transitions only)."""
    ev_dict = cand["evidence_dict"]
    app_ver = cand.get("app_version")
    source = (
        f"{ev_dict.get('source_identification', '')}:{ev_dict.get('artefact_category', '')}"
        + (f" (v{app_ver})" if app_ver else "")
    )
    sha = ev_dict.get("sha256", "")
    rows = cand["rows"]

    events = []
    prev: str | None = None
    for i, row in enumerate(rows):
        mode = row.get(mode_col, "").strip() or None
        if mode is None:
            continue
        if mode != prev:
            ts_val = row.get(ts_col, "")
            norm_id = row.get("[NORM]:ID", "")
            data = {**data_fn(rows, i), "fly_mode": mode}
            events.append(_make_event(
                timestamp=ts_val,
                timezone=_ts_timezone(ts_val),
                source=source,
                source_pointer=f"{sha}:{norm_id}",
                event="Fly mode changed",
                data=data,
                confidence=_event_confidence(ts_val, data),
            ))
            prev = mode
    return events


def _log_message_events(
    cand: dict[str, Any],
    data_fn: Any,
    ts_col: str,
    warn_col: str,
    event_label: str = "Log message",
) -> list[dict[str, Any]]:
    """Return a log-message event for every non-empty warn/log column value."""
    ev_dict = cand["evidence_dict"]
    app_ver = cand.get("app_version")
    source = (
        f"{ev_dict.get('source_identification', '')}:{ev_dict.get('artefact_category', '')}"
        + (f" (v{app_ver})" if app_ver else "")
    )
    sha = ev_dict.get("sha256", "")
    rows = cand["rows"]
    events = []
    for i, row in enumerate(rows):
        msg = row.get(warn_col, "").strip() or None
        if msg is None:
            continue
        ts_val = row.get(ts_col, "")
        norm_id = row.get("[NORM]:ID", "")
        data = {**data_fn(rows, i), "log_message": msg}
        events.append(_make_event(
            timestamp=ts_val,
            timezone=_ts_timezone(ts_val),
            source=source,
            source_pointer=f"{sha}:{norm_id}",
            event=event_label,
            data=data,
            confidence=_event_confidence(ts_val, data),
        ))
    return events


def _state_change_events(
    cand: dict[str, Any],
    col: str,
    event_label: str,
    data_key: str,
    include_initial: bool,
) -> list[dict[str, Any]]:
    """Emit an event on every value transition; optionally also on first occurrence."""
    ev_dict = cand["evidence_dict"]
    app_ver = cand.get("app_version")
    source = (
        f"{ev_dict.get('source_identification', '')}:{ev_dict.get('artefact_category', '')}"
        + (f" (v{app_ver})" if app_ver else "")
    )
    sha = ev_dict.get("sha256", "")
    rows = cand["rows"]
    events = []
    prev: str | None = None
    for i, row in enumerate(rows):
        val = row.get(col, "").strip() or None
        if val is None:
            continue
        if (prev is None and include_initial) or (prev is not None and val != prev):
            ts_val = row.get(_FR_TS_COL, "")
            norm_id = row.get("[NORM]:ID", "")
            data = {**_event_data_fr(rows, i), data_key: val}
            events.append(_make_event(
                timestamp=ts_val,
                timezone=_ts_timezone(ts_val),
                source=source,
                source_pointer=f"{sha}:{norm_id}",
                event=event_label,
                data=data,
                confidence=_event_confidence(ts_val, data),
            ))
        prev = val
    return events


def _exif_obs_datetime(obs_data: dict[str, Any]) -> datetime | None:
    """Combine norm_date + norm_time into a UTC-aware datetime.

    norm_date/norm_time are only present when UTC was confirmed by parse_exif_date.
    norm_time carries an explicit '+00:00' suffix, so fromisoformat is already timezone-aware.
    """
    d = obs_data.get("norm_date", "")
    t = obs_data.get("norm_time", "")
    if not d or not t:
        return None
    try:
        return datetime.fromisoformat(f"{d}T{t}")
    except ValueError:
        return None


def _parse_flight_dt(val: Any) -> datetime | None:
    """Parse an ISO string from flights_identified start/end into a datetime."""
    if not val:
        return None
    try:
        dt = datetime.fromisoformat(str(val))
        if dt.tzinfo is None:
            return None  # timezone unknown — cannot confirm UTC
        return dt
    except ValueError:
        return None


def _flight_covers_dt(flight: dict[str, Any], dt: datetime) -> bool:
    """Return True if dt falls within any flights_identified time window."""
    for seg in flight["flights_identified"]:
        s = _parse_flight_dt(seg.get("start"))
        e = _parse_flight_dt(seg.get("end"))
        if s and e and s <= dt <= e:
            return True
    return False


def _build_bbox(
    cand: dict[str, Any],
    lat_col: str,
    lon_col: str,
) -> tuple[float, float, float, float] | None:
    """Return (lat_min, lat_max, lon_min, lon_max) from all valid GPS rows, or None."""
    lats: list[float] = []
    lons: list[float] = []
    for row in cand["rows"]:
        lat = _try_float(row.get(lat_col, ""))
        lon = _try_float(row.get(lon_col, ""))
        if lat is not None and lon is not None and (lat != 0.0 or lon != 0.0):
            lats.append(lat)
            lons.append(lon)
    if not lats:
        return None
    return min(lats), max(lats), min(lons), max(lons)


def _merge_bboxes(
    a: tuple[float, float, float, float] | None,
    b: tuple[float, float, float, float] | None,
) -> tuple[float, float, float, float] | None:
    if a is None:
        return b
    if b is None:
        return a
    return min(a[0], b[0]), max(a[1], b[1]), min(a[2], b[2]), max(a[3], b[3])


def _point_in_bbox(lat: float, lon: float, bbox: tuple[float, float, float, float]) -> bool:
    lat_min, lat_max, lon_min, lon_max = bbox
    return lat_min <= lat <= lat_max and lon_min <= lon <= lon_max


def _correlate_exif_observations(
    flights: list[dict[str, Any]],
    p5_anomalies: list[dict[str, Any]],
    sha_to_source: dict[str, str],
) -> None:
    """Match P5 EXIF observations to flights by temporal window and/or GPS bounding box.

    Mutates each flight dict: appends to plausibly_correlated, possibly_correlated,
    and events.
    """
    for obs_dict in p5_anomalies:
        if obs_dict.get("acquisition_method") != ACQUISITION_NORMALISE:
            continue
        obs_list = obs_dict.get("observations", [])
        if not obs_list:
            continue
        obs_data = obs_list[0]
        norm_date = obs_data.get("norm_date", "")
        norm_time = obs_data.get("norm_time", "")
        obs_lat   = obs_data.get("gps_latitude")
        obs_lon   = obs_data.get("gps_longitude")
        has_dt  = bool(norm_date and norm_time)
        has_gps = obs_lat is not None and obs_lon is not None

        if not has_dt and not has_gps:
            continue

        sha       = obs_dict.get("evidence_sha256", "")
        category  = obs_dict.get("evidence_category", "")
        source_id = sha_to_source.get(sha, "")
        pointer   = f"p5:{sha}"

        for flight in flights:
            if has_dt:
                dt = _exif_obs_datetime(obs_data)
                if dt is None or not _flight_covers_dt(flight, dt):
                    continue
                if pointer not in flight["plausibly_correlated"]:
                    flight["plausibly_correlated"].append(pointer)
                ts_str = f"{norm_date}T{norm_time}"
                coord  = {"latitude": obs_lat, "longitude": obs_lon}
                flight["events"].append(_make_event(
                    timestamp      = ts_str,
                    timezone       = _ts_timezone(ts_str),
                    source         = f"{source_id}:{category}",
                    source_pointer = pointer,
                    event          = "Plausible media metadata correlation found",
                    data           = {
                        **coord,
                        "date":       norm_date,
                        "time":       norm_time,
                        "media_type": category,
                    },
                    confidence     = _event_confidence(ts_str, coord),
                ))
            elif has_gps:
                bbox = flight.get("_bbox")
                if bbox is None or not _point_in_bbox(obs_lat, obs_lon, bbox):
                    continue
                flight["possibly_correlated"].append({
                    "source":         f"{source_id}:{category}",
                    "source_pointer": pointer,
                    "data": {"longitude": obs_lon, "latitude": obs_lat},
                })


def _correlate_flight_log_observations(
    flights: list[dict[str, Any]],
    p5_anomalies: list[dict[str, Any]],
    sha_to_source: dict[str, str],
) -> None:
    """Match P5 flight_log observations to flights by log-message subset check.

    For each flight_log observation with message entries (not crash_dump),
    appends to possibly_correlated of every flight whose 'Log message' event set
    is a superset of the observation's messages.
    """
    flight_log_messages: list[set[str]] = [
        {
            _norm_msg(e["data"]["log_message"])
            for e in f["events"]
            if e.get("event") == "Log message"
            and isinstance(e.get("data"), dict)
            and "log_message" in e["data"]
        }
        for f in flights
    ]

    for obs_dict in p5_anomalies:
        if obs_dict.get("evidence_category") != FLIGHT_LOGS:
            continue
        obs_list = obs_dict.get("observations", [])
        if not obs_list:
            continue
        obs_data = obs_list[0]
        fmt = obs_data.get("format", "")
        if not fmt or fmt == "crash_dump":
            continue
        entries = obs_data.get("entries", [])
        if not entries:
            continue

        valid_entries = [e for e in entries if e.get("message")]
        if not valid_entries:
            continue
        norm_messages = {_norm_msg(e["message"]) for e in valid_entries}

        sha = obs_dict.get("evidence_sha256", "")
        source_id = sha_to_source.get(sha, "")
        pointer = f"p5:{sha}"

        for idx, flight in enumerate(flights):
            if not norm_messages.issubset(flight_log_messages[idx]):
                continue
            if pointer not in flight["plausibly_correlated"] and pointer not in [
                pc.get("source_pointer") for pc in flight["possibly_correlated"]
            ]:
                flight["possibly_correlated"].append({
                    "source": f"{source_id}: {FLIGHT_LOGS}",
                    "source_pointer": pointer,
                    "data": {"format": fmt, "entry_count": len(valid_entries)},
                })


def _correlate_video_duration(
    flights: list[dict[str, Any]],
    p4_obs: list[dict[str, Any]],
    sha_to_source: dict[str, str],
) -> None:
    """Match P4 video observations to flights by ExifTool Duration vs duration_recording."""
    for obs_dict in p4_obs:
        if obs_dict.get("evidence_category") != VIDEOS:
            continue
        if obs_dict.get("acquisition_method") != ACQUISITION_EXIFTOOL:
            continue
        obs_list = obs_dict.get("observations", [])
        if not obs_list:
            continue
        duration_raw = obs_list[0].get("Duration")
        if duration_raw is None:
            continue
        try:
            video_duration = float(duration_raw)
        except (ValueError, TypeError):
            continue

        sha = obs_dict.get("evidence_sha256", "")
        source_id = sha_to_source.get(sha, "")
        pointer = f"p4:{sha}"

        for flight in flights:
            log_ended_duration: float | None = None
            for ev in flight.get("events", []):
                if ev.get("event") == "Log ended":
                    dr = ev.get("data", {}).get("duration_recording")
                    if dr is not None:
                        try:
                            log_ended_duration = float(dr)
                        except (ValueError, TypeError):
                            pass
                    break

            if log_ended_duration is None:
                continue
            if abs(video_duration - log_ended_duration) >= 2.0:
                continue

            if pointer not in flight["plausibly_correlated"] and pointer not in [
                pc.get("source_pointer") for pc in flight["possibly_correlated"]
            ]:
                flight["possibly_correlated"].append({
                    "source": f"{source_id}:{VIDEOS}",
                    "source_pointer": pointer,
                    "data": {
                        "video_duration_s": video_duration,
                        "log_duration_s": log_ended_duration,
                    },
                })


def _confidence_from_distance(median_m: float) -> str:
    if median_m < 5.0:
        return "high"    # within DJI ±3 m horizontal spec
    if median_m < 15.0:
        return "medium"  # within ICAO SPS 13 m (95 %)
    return "low"         # approaching 25 m acceptance ceiling


def _correlate_primary(
    fr_cand: dict[str, Any], drone_cand: dict[str, Any]
) -> dict[str, Any] | None:
    """Primary GPS+temporal correlation rule.

    Returns a correlation dict on match, None if rule cannot apply or fails.
    """
    if not fr_cand["has_usable_gps"] or not drone_cand["has_usable_gps"]:
        return None

    overlap = _compute_overlap(fr_cand, drone_cand)
    min_dur = min(fr_cand["duration_s"], drone_cand["duration_s"])
    if overlap < _OVERLAP_MIN_S or overlap < _OVERLAP_MIN_FRACTION * min_dur:
        return None

    median_dist, match_rate = _compute_spatial(fr_cand, drone_cand)
    if median_dist is None or median_dist > _SPATIAL_MAX_MEDIAN_M:
        return None

    return {
        "matched": True,
        "rule": "primary",
        "confidence": _confidence_from_distance(median_dist),
        "overlap_s": round(overlap, 1),
        "overlap_fraction": round(overlap / min_dur, 4),
        "median_distance_m": round(median_dist, 2),
        "match_rate": round(match_rate, 4),
    }


def _build_flight_dict(
    flight_id: str,
    fr_cand: dict[str, Any] | None,
    drone_cand: dict[str, Any] | None,
    correlation: dict[str, Any],
) -> dict[str, Any]:
    """Assemble the full flight dict for timeline.json."""
    candidates = [c for c in (fr_cand, drone_cand) if c is not None]

    groups = []
    for c in candidates:
        s = c["start_dt"]
        e = c["end_dt"]
        dur = round((e - s).total_seconds(), 1) if s and e else None
        groups.append({
            "evidence_sha256": c["evidence_dict"].get("sha256", ""),
            "start": s.isoformat() if s else None,
            "end": e.isoformat() if e else None,
            "duration_s": dur,
        })

    events: list[dict[str, Any]] = []
    if fr_cand is not None:
        events += _boundary_events(fr_cand, _event_data_fr, _FR_TS_COL, _FR_DIST_COL, _fr_log_start_extras, _fr_log_end_extras)
        ph = _peak_height_event(fr_cand, _event_data_fr, _FR_TS_COL, _FR_HEIGHT_COL)
        if ph:
            events.append(ph)
        events += _motor_events(fr_cand, _event_data_fr, _FR_TS_COL, _FR_MOTOR_COL, "TRUE", "FALSE")
        events += _fly_mode_events(fr_cand, _event_data_fr, _FR_TS_COL, _FR_STATE_COL)
        events += _log_message_events(fr_cand, _event_data_fr, _FR_TS_COL, _FR_WARN_COL)
        events += _log_message_events(fr_cand, _event_data_fr, _FR_TS_COL, _FR_TIP_COL)
        events += _state_change_events(fr_cand, _FR_REC_STATE_COL, "Record mode changed", "record_mode", True)
        events += _state_change_events(fr_cand, _FR_PHOTO_COL, "Photo mode changed", "photo_mode", True)
        events += _state_change_events(fr_cand, _FR_SD_COL, "SD storage is full", "sd_state", False)
    if drone_cand is not None:
        drone_event_data = _event_data_drone(drone_cand["lat_col"], drone_cand["lon_col"])
        events += _boundary_events(drone_cand, drone_event_data, _DRONE_TS_COL, _DRONE_DIST_COL, _drone_log_start_extras)
        ph = _peak_height_event(drone_cand, drone_event_data, _DRONE_TS_COL, _DRONE_HEIGHT_COL)
        if ph:
            events.append(ph)
        if drone_cand.get("motor_col"):
            events += _motor_events(drone_cand, drone_event_data, _DRONE_TS_COL, drone_cand["motor_col"], "1", "0")
        if drone_cand.get("mode_col"):
            events += _fly_mode_events(drone_cand, drone_event_data, _DRONE_TS_COL, drone_cand["mode_col"])
        events += _log_message_events(drone_cand, drone_event_data, _DRONE_TS_COL, _DRONE_WARN_COL)
    events.sort(key=lambda e: e["timestamp"] or "")

    bbox = _merge_bboxes(
        _build_bbox(fr_cand, _FR_LAT_COL, _FR_LON_COL) if fr_cand is not None else None,
        _build_bbox(drone_cand, drone_cand["lat_col"], drone_cand["lon_col"]) if drone_cand is not None else None,
    )

    return {
        "flight_id": flight_id,
        "flights_identified": groups,
        "correlation_metadata": correlation,
        "plausibly_correlated": [],
        "possibly_correlated": [],
        "_bbox": bbox,
        "events": events,
    }


def run_phase_6(state: State) -> State:
    """Phase 6: Multi-source correlation and unified flight timeline."""
    phase_dir = output_dir() / state.case_id / _PHASE_NAME
    clear_and_make(phase_dir)

    p5 = state.phase_outputs.get("p5_normalisation_and_anomaly_checking", {})
    normalised_artefacts: list[dict[str, Any]] = p5.get("normalised_artefacts", [])

    fr_artefacts = [a for a in normalised_artefacts if a.get("artefact_category") == FLIGHT_RECORDS]
    drone_artefacts = [a for a in normalised_artefacts if a.get("artefact_category") == DRONE_LOGS]

    fr_candidates: list[dict[str, Any]] = []
    for ev_dict in fr_artefacts:
        identification = ev_dict.get("source_identification", "unknown")
        stored = ev_dict.get("stored_path") or ""
        try:
            header, rows = _load_csv_rows(Path(str(stored)))
            if not rows:
                state.raise_anomaly(6, identification,
                    f"empty flight record CSV: {Path(stored).name}",
                    category=FLIGHT_RECORDS)
                continue
            cand = _build_candidate(ev_dict, rows, _FR_TS_COL,
                                    _FR_LAT_COL, _FR_LON_COL, header)
            if cand is None:
                state.raise_anomaly(6, identification,
                    f"no parseable timestamps in flight record: {Path(stored).name}",
                    category=FLIGHT_RECORDS)
                continue
            fr_candidates.append(cand)
        except Exception as exc:
            state.raise_anomaly(6, identification,
                f"flight record load failed ({Path(stored).name}): {exc}",
                category=FLIGHT_RECORDS)

    drone_candidates: list[dict[str, Any]] = []
    for ev_dict in drone_artefacts:
        identification = ev_dict.get("source_identification", "unknown")
        stored = ev_dict.get("stored_path") or ""
        try:
            header, rows = _load_csv_rows(Path(str(stored)))
            if not rows:
                state.raise_anomaly(6, identification,
                    f"empty drone log CSV: {Path(stored).name}",
                    category=DRONE_LOGS)
                continue
            # Derive absolute UTC via clock-offset anchoring. GPS:dateTimeStamp
            # is unreliable before the drone GPS module acquires a proper fix;
            # Clock:offsetTime is a reliable monotonic counter throughout.
            computed = _anchor_drone_timestamps(rows, _DRONE_TS_COL, _DRONE_CLOCK_COL)
            for row, ts in zip(rows, computed):
                row[_DRONE_COMPUTED_TS_COL] = ts.isoformat() if ts else ""
            lat_col   = resolve_col(header, *_DRONE_LAT_CANDIDATES)   or ""
            lon_col   = resolve_col(header, *_DRONE_LON_CANDIDATES)   or ""
            mode_col  = resolve_col(header, *_DRONE_MODE_CANDIDATES)  or ""
            motor_col = resolve_col(header, *_DRONE_MOTOR_CANDIDATES) or ""
            cand = _build_candidate(ev_dict, rows, _DRONE_COMPUTED_TS_COL,
                                    lat_col, lon_col, header)
            if cand is None:
                state.raise_anomaly(6, identification,
                    f"no parseable timestamps in drone log: {Path(stored).name}",
                    category=DRONE_LOGS)
                continue
            cand["time_index"] = _build_time_index(rows, _DRONE_COMPUTED_TS_COL)
            cand["mode_col"]   = mode_col
            cand["motor_col"]  = motor_col
            drone_candidates.append(cand)
        except Exception as exc:
            state.raise_anomaly(6, identification,
                f"drone log load failed ({Path(stored).name}): {exc}",
                category=DRONE_LOGS)

    fr_candidates = _deduplicate_fr_candidates(fr_candidates)

    matched_fr: set[int] = set()
    matched_drone: set[int] = set()
    flights: list[dict[str, Any]] = []
    flight_counter = 0

    for fi, fr_cand in enumerate(fr_candidates):
        best_di: int | None = None
        best_corr: dict[str, Any] | None = None
        best_overlap = 0.0

        for di, drone_cand in enumerate(drone_candidates):
            if di in matched_drone:
                continue
            try:
                corr = _correlate_primary(fr_cand, drone_cand)
                if corr is not None:
                    ov = corr.get("overlap_s", 0.0)
                    if ov > best_overlap:
                        best_overlap = ov
                        best_di = di
                        best_corr = corr
            except Exception as exc:
                identification = fr_cand["evidence_dict"].get("source_identification", "unknown")
                state.raise_anomaly(6, identification, f"correlation error: {exc}")

        if best_di is not None and best_corr is not None:
            flight_counter += 1
            matched_fr.add(fi)
            matched_drone.add(best_di)
            drone_cand = drone_candidates[best_di]
            flights.append(_build_flight_dict(
                f"flight_{flight_counter:02d}", fr_cand, drone_cand, best_corr,
            ))

    for fi, fr_cand in enumerate(fr_candidates):
        if fi in matched_fr:
            continue
        flight_counter += 1
        flights.append(_build_flight_dict(
            f"flight_{flight_counter:02d}", fr_cand, None,
            {"matched": False},
        ))

    # -----------------------------------------------------------------------
    # Corroboration pass: controller-cached drone logs
    # -----------------------------------------------------------------------
    # DJI apps cache a copy of the drone's DAT telemetry on the controller
    # device (e.g. MCDatFlightRecords/). These are already extracted as
    # DRONE_LOGS by P3 and processed by DatCon in P4. If the drone-side copy
    # was consumed in the primary match, the controller copy would otherwise
    # become a spurious solo flight. Instead, we append it to the matched
    # flight's flights_identified as a corroborating evidence reference —
    # no new events are built (events were already captured from the primary DL).
    #
    # Composite time windows are built once from the primary-match results and
    # NOT updated as corroborating entries are added, preventing cascading matches.
    flight_windows: list[tuple[datetime, datetime] | None] = []
    for _fl in flights:
        _starts: list[datetime] = []
        _ends: list[datetime] = []
        for seg in _fl.get("flights_identified", []):
            if seg.get("start"):
                try:
                    _starts.append(datetime.fromisoformat(seg["start"]))
                except ValueError:
                    pass
            if seg.get("end"):
                try:
                    _ends.append(datetime.fromisoformat(seg["end"]))
                except ValueError:
                    pass
        flight_windows.append((min(_starts), max(_ends)) if _starts and _ends else None)

    corroborated_drone: set[int] = set()
    for di, drone_cand in enumerate(drone_candidates):
        if di in matched_drone:
            continue
        if drone_cand["evidence_dict"].get("source_identification", "") not in _CONTROLLER_SOURCES:
            continue
        cand_start = drone_cand["start_dt"]
        cand_end   = drone_cand["end_dt"]
        cand_dur   = drone_cand["duration_s"]
        best_fi: int | None = None
        best_ov = 0.0
        for fi, window in enumerate(flight_windows):
            if window is None:
                continue
            fl_start, fl_end = window
            overlap  = max(0.0, (min(fl_end, cand_end) - max(fl_start, cand_start)).total_seconds())
            min_dur  = min((fl_end - fl_start).total_seconds(), cand_dur)
            if overlap >= _OVERLAP_MIN_S and overlap >= _OVERLAP_MIN_FRACTION * min_dur:
                if overlap > best_ov:
                    best_ov = overlap
                    best_fi = fi
        if best_fi is not None:
            s   = drone_cand["start_dt"]
            e   = drone_cand["end_dt"]
            dur = round((e - s).total_seconds(), 1) if s and e else None
            flights[best_fi]["flights_identified"].append({
                "evidence_sha256": drone_cand["evidence_dict"].get("sha256", ""),
                "start": s.isoformat() if s else None,
                "end":   e.isoformat() if e else None,
                "duration_s": dur,
            })
            corroborated_drone.add(di)

    for di, drone_cand in enumerate(drone_candidates):
        if di in matched_drone or di in corroborated_drone:
            continue
        flight_counter += 1
        flights.append(_build_flight_dict(
            f"flight_{flight_counter:02d}", None, drone_cand,
            {"matched": False},
        ))

    flights.sort(key=lambda f: (f["flights_identified"][0]["start"] or "") if f["flights_identified"] else "")
    for i, flight in enumerate(flights, start=1):
        flight["flight_id"] = f"flight_{i:02d}"

    p4_artefacts: list[dict[str, Any]] = (
        state.phase_outputs.get("p4_decision_and_orchestration", {})
        .get("decision_and_orchestration_artefacts", [])
    )
    p4_obs: list[dict[str, Any]] = (
        state.phase_outputs.get("p4_decision_and_orchestration", {})
        .get("derived_observations", [])
    )
    p3_artefacts: list[dict[str, Any]] = (
        state.phase_outputs.get("p3_artefact_extraction", {})
        .get("extracted_artefacts", [])
    )
    sha_to_source: dict[str, str] = {
        a.get("sha256", ""): a.get("source_identification", "")
        for a in (*p4_artefacts, *p3_artefacts)
    }
    p5_anomalies: list[dict[str, Any]] = p5.get("derived_anomalies", [])
    _correlate_exif_observations(flights, p5_anomalies, sha_to_source)
    _correlate_flight_log_observations(flights, p5_anomalies, sha_to_source)
    _correlate_video_duration(flights, p4_obs, sha_to_source)

    _INTERNAL_KEYS = {"_bbox"}
    for flight in flights:
        fid = flight["flight_id"]
        idx = int(fid.split("_")[-1])
        tl_path = phase_dir / f"timeline_flight{idx:02d}.json"
        flight["events"].sort(key=lambda e: e["timestamp"] or "")
        write_json(tl_path, {
            "generated_at": utc_now_iso(),
            **{k: v for k, v in flight.items() if k not in _INTERNAL_KEYS and k != "events"},
            "events": flight["events"],
        })
        flight["stored_path"] = str(tl_path)

    compact_flights = [
        {
            "stored_path": f["stored_path"],
            "flight_id": f["flight_id"],
            "flights_identified": f["flights_identified"],
            "correlation": f["correlation_metadata"],
            "plausibly_correlated": f["plausibly_correlated"],
            "possibly_correlated": f["possibly_correlated"],
        }
        for f in flights
    ]

    if not _has_real_output(phase_dir):
        _write_no_output(phase_dir)

    state.phase_outputs[_PHASE_NAME] = {
        "completed_at": utc_now_iso(),
        "flight_count": len(flights),
        "flights": compact_flights,
    }
    state.completed_phases.append(_PHASE_NAME)
    print(f"  Identified {len(flights)} flight(s). Timeline files written to {phase_dir}")
    return state
