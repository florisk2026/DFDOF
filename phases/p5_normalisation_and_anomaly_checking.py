"""DFDOF Phase 5: Normalisation and Anomaly Checking.

This phase:
 - augments DatCon CSVs with [NORM]:ID, [NORM]:GPS:Date, [NORM]:GPS:Time,
   [NORM]:GPS:dateTimeStamp columns,
 - augments FlightRecord CSVs with [NORM]:ID and [NORM]:CUSTOM.updateTime,
 - runs 9 shared + format-specific single-source anomaly checks,
 - stores anomaly findings as Observations (not state anomaly flags),
 - wraps augmented CSVs as Evidence objects,
 - copies opaque-extension image files (.thumbnail, .THM) to viewable
   equivalents derived from their MIMEType.
"""

from __future__ import annotations

import csv
import json
import math
import re
import shutil
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Any, Callable

from config import (
    ACQUISITION_DATCON,
    ACQUISITION_EXIFTOOL,
    ACQUISITION_NORMALISE,
    ACQUISITION_TXTLOGTOCSV,
    DATABASES,
    DRONE_LOGS,
    EVIDENCE_TYPE_NORMALISED,
    FLIGHT_LOGS,
    FLIGHT_RECORDS,
    IDENTIFICATION_DRONE_SD,
    IMAGES,
    SOURCE_IDENTIFICATION_TYPES,
    clear_and_make,
    output_dir,
    utc_now_iso,
)
from evidence import Evidence, make_evidence
from observation import Observation, make_observation
from parsing.utils_parse import to_windows_path
from phases.utils_phase import (
    drone_sd_label,
    find_input_evidence_list_by_identification,
    haversine_m,
    parse_datcon_date,
    parse_datcon_time,
    parse_exif_date,
    parse_flightrecord_timestamp,
    parse_iso_timestamp,
)
from state import State

_PHASE_NAME = Path(__file__).stem

# ===========================================================================
# PHASE 5: FORENSIC SCREENING CONFIGURATION & THRESHOLD JUSTIFICATION
# ===========================================================================
# CRITICAL FORENSIC METHODOLOGY NOTE:
# These metrics serve as conservative forensic screening thresholds designed 
# to isolate telemetry anomalies requiring examiner review. They function as 
# indicators of structural, physical, or logging inconsistencies; they do not 
# independently constitute definitive mathematical proof of malicious tampering.
#
# Threshold Derivation Matrix:
# 1. Physics & Manufacturer Specs : Lithium Polymer/High-Voltage (LiPo/LiHV) bounds
# 2. GNSS Engineering Standards   : Multi-lateral satellite positioning constraints
# 3. Operational Heuristics       : Conservative UAV flight profile envelopes
# ===========================================================================

# ---------------------------------------------------------------------------
# Category 1: Physics & Manufacturer-Backed Thresholds (Highly Defensible)
# ---------------------------------------------------------------------------

# LiPo/LiHV absolute deep-discharge danger zone.
# Cells degrade severely below ~2.8V-3.0V. Values below 2.8V signify abnormal 
# hardware exhaustion, unfinalized log corruption, or telemetry degradation.
_BATTERY_CELL_MIN_V = 2.8  

# LiHV maximum nominal cell voltage is 4.35V. 
# Values exceeding 4.4V point directly to sensor noise, parsing bugs, or localized data corruption.
_BATTERY_CELL_MAX_V = 4.4  

# Severe cell imbalance threshold. 
# Healthy cells remain within a delta of 0.01V-0.10V under nominal load. A gap 
# exceeding 0.3V indicates cell degradation, active damage, or telemetry desynchronization.
_BATTERY_CELL_IMBALANCE_V = 0.3  

# Conservative physical battery temperature envelope.
# Broadened beyond DJI's strict operational thresholds (0°C to 40°C) to prevent false positives 
# during extreme ambient storage, severe impact friction, or hardware thermal runaway.
_BATTERY_TEMP_MIN_C = -20.0
_BATTERY_TEMP_MAX_C = 80.0  

# Unit quaternion normalization constraint validity tolerance.
# Physical orientation orientation-vectors must satisfy the equation: ||q|| = 1.
# Deviations greater than 0.01 demonstrate mathematical invalidity or structural record corruption.
_QUATERNION_NORM_EPS = 0.01  


# ---------------------------------------------------------------------------
# Category 2: GNSS Engineering Thresholds (Standard Standards)
# ---------------------------------------------------------------------------

# GNSS Engineering Convention: Horizontal Dilution of Precision (HDOP).
# Values between 1-2 denote ideal/excellent geometric precision; values > 5.0 
# reflect degraded positional reliability rendering coordinates legally/forensically speculative.
_GPS_HDOP_THRESHOLD = 5.0  

# Minimum physical satellite allocation required to compute a valid 3D geometric fix.
# Telemetry strings asserting 3D coordinates with fewer than 4 locked satellites 
# represent mathematically impossible or unvalidated tracking states.
_GPS_POOR_FIX_SATS = 4  


# ---------------------------------------------------------------------------
# Category 3: Heuristic Screening Thresholds (Conservative Plausibility Bounds)
# ---------------------------------------------------------------------------

# Conservative horizontal velocity plausibility threshold (~288 km/h).
# Exceeds the mechanical capability of standard consumer DJI platforms. Spikes beyond 80.0 m/s 
# flag timestamp desynchronization, packet drops, or multi-kilometer GPS signal "jumps."
_SPEED_THRESHOLD_MS = 80.0  

# Vertical velocity anomaly threshold. 
# Nominal sport-mode ascent limits scale between 3 m/s and 10 m/s. A vertical delta 
# exceeding 20.0 m/s indexes data ingestion anomalies, altitude sensor failures, or physical crashes.
_ALTITUDE_SPIKE_MS = 20.0  

# Operational temporal continuity threshold.
# Telemetry dropouts exceeding 60.0 seconds indicate record truncation, power interruptions, 
# or manual manipulation of intermediate logging streams.
_TIMESTAMP_GAP_S = 60.0  

# Ground-plane floating-point tolerance buffer.
# Protects the system from flagging standard floating-point calculation variance around 0.0m as an anomaly.
_ALTITUDE_NEGATIVE_M = -0.1  

# Motor-state altitude inconsistency threshold.
# If altitude reads >1.0m while internal ESCs register motors are off, it isolates 
# a structural logging contradiction or sensor desynchronization.
_MOTOR_AIRBORNE_HEIGHT_M = 1.0

# Image MIME types that need extension renaming (source extension → not viewable).
_OPAQUE_IMAGE_EXTENSIONS = {".thumbnail", ".thm"}
_MIME_TO_EXT: dict[str, str] = {
    "image/jpeg": ".jpg",
    "image/png": ".png",
    "image/gif": ".gif",
    "image/webp": ".webp",
    "image/tiff": ".tiff",
    "image/bmp": ".bmp",
}

# Flight log readability probe
_PROBE_BYTES = 8192
_NON_PRINTABLE_THRESHOLD = 0.15

# Flight log format regexes
_JSON_ARRAY_LOG_RE = re.compile(r'\["(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})","([^"]*)","([^"]*)"\]')
_BRACKET_RE = re.compile(r"\[([^\]]+),\s*([^\]]+)\]")
_BRACKET_INLINE_RE = re.compile(r"^\[([^\]]+)\](.+)$", re.MULTILINE)
_CRASH_SECTION_RE = re.compile(r"=+\s*Crash\s*=+", re.IGNORECASE)
_SECTION_RE = re.compile(r"=+\s*(.+?)\s*=+")
_HEADING_TS_RE = re.compile(r"^##\s+(\d{2}:\d{2}:\d{2})\s*$", re.MULTILINE)

# DatCon column names
_DATCON_DATE_COL = "GPS:Date"
_DATCON_TIME_COL = "GPS:Time"
_DATCON_DATETIME_STAMP_COL = "GPS:dateTimeStamp"
_DATCON_LAT_COL = "GPS:Lat"
_DATCON_LON_COL = "GPS:Long"
_DATCON_HEIGHT_COL = "IMUCalcs(0):height"
_DATCON_NUMSV_COL = "GPS:numSV"
_DATCON_HDOP_COL = "GPS:hDOP"
_DATCON_MOTOR_COL = "Controller:motor_state"
_DATCON_ROLL_COL = "IMU_ATTI(0):roll"
_DATCON_PITCH_COL = "IMU_ATTI(0):pitch"
_DATCON_QUATW_COL = "IMU_ATTI(0):quatW"
_DATCON_QUATX_COL = "IMU_ATTI(0):quatX"
_DATCON_QUATY_COL = "IMU_ATTI(0):quatY"
_DATCON_QUATZ_COL = "IMU_ATTI(0):quatZ"
_DATCON_CLOCK_COL = "Clock:offsetTime"

# FlightRecord column names
_FR_TIME_COL = "CUSTOM.updateTime"
_FR_LAT_COL = "OSD.latitude"
_FR_LON_COL = "OSD.longitude"
_FR_HEIGHT_COL = "OSD.height [m]"
_FR_NUMSV_COL = "OSD.gpsNum"
_FR_MOTOR_COL = "OSD.isMotorUp"
_FR_BATTERY_CAPACITY_COL = "CENTER_BATTERY.relativeCapacity"
_FR_BATTERY_CELLS = [
    "CENTER_BATTERY.voltageCell1 [V]",
    "CENTER_BATTERY.voltageCell2 [V]",
    "CENTER_BATTERY.voltageCell3 [V]",
    "CENTER_BATTERY.voltageCell4 [V]",
    "CENTER_BATTERY.voltageCell5 [V]",
    "CENTER_BATTERY.voltageCell6 [V]",
]
_FR_BATTERY_TEMP_COL = "CENTER_BATTERY.temperature [C]"


def _build_identification_map(state: State) -> dict[str, str]:
    """Map each P3-artefact sha256 to its source folder label.

    For drone_sd sources the label is drone_sd_1, drone_sd_2, … matching the
    numbered directories produced by P3/P4. All other sources use their
    identified_as string directly.

    Chain: P3-artefact.parent_sha256 → input-evidence sha256 → label.
    """
    drone_sd_sources = find_input_evidence_list_by_identification(state, IDENTIFICATION_DRONE_SD)
    drone_sd_sha_to_label: dict[str, str] = {
        ev.sha256: drone_sd_label(idx)
        for idx, ev in enumerate(drone_sd_sources, start=1)
        if ev.sha256
    }

    input_sha_to_label: dict[str, str] = {}
    for ev in state.input_evidence:
        if not ev.sha256:
            continue
        if ev.source_identification == IDENTIFICATION_DRONE_SD:
            label = drone_sd_sha_to_label.get(ev.sha256)
            if label:
                input_sha_to_label[ev.sha256] = label
        elif ev.source_identification:
            input_sha_to_label[ev.sha256] = ev.source_identification

    p3_artefacts = state.phase_outputs.get("p3_artefact_extraction", {}).get(
        "extracted_artefacts", []
    )
    p3_sha_to_label: dict[str, str] = {}
    for artefact in p3_artefacts:
        sha = str(artefact.get("sha256") or "")
        parent_sha = str(artefact.get("parent_sha256") or "")
        if sha and parent_sha in input_sha_to_label:
            p3_sha_to_label[sha] = input_sha_to_label[parent_sha]

    return p3_sha_to_label


def _try_float(value: str) -> float | None:
    try:
        return float(value)
    except (ValueError, TypeError):
        return None


def _exif_root(exif_data: Any) -> dict[str, Any] | None:
    if isinstance(exif_data, list) and exif_data and isinstance(exif_data[0], dict):
        return exif_data[0]
    return None


def _exif_find(data: Any, field: str) -> Any:
    if isinstance(data, dict):
        value = data.get(field)
        if value not in (None, ""):
            return value
        for item in data.values():
            found = _exif_find(item, field)
            if found is not None:
                return found
    elif isinstance(data, list):
        for item in data:
            found = _exif_find(item, field)
            if found is not None:
                return found
    return None


def _parse_gps_coordinates(value: Any) -> tuple[float, float] | None:
    if not isinstance(value, str):
        return None
    parts = re.findall(r"[-+]?\d+(?:\.\d+)?", value)
    if len(parts) < 2:
        return None
    lat = _try_float(parts[0])
    lon = _try_float(parts[1])
    if lat is None or lon is None:
        return None
    return lat, lon


def _exif_location(data: Any) -> tuple[float | None, float | None]:
    lat = _try_float(str(_exif_find(data, "GPSLatitude") or ""))
    lon = _try_float(str(_exif_find(data, "GPSLongitude") or ""))
    if lat is not None and lon is not None:
        return lat, lon
    parsed = _parse_gps_coordinates(_exif_find(data, "GPSCoordinates"))
    if parsed is not None:
        return parsed
    return None, None


def _find_col(header: list[str], base: str) -> int:
    """Find a column index by exact match, then by base-name prefix (handles DatCon :D/:C suffixes)."""
    if base in header:
        return header.index(base)
    for i, col in enumerate(header):
        if col.startswith(base + ":") or col.startswith(base + " "):
            return i
    return -1


def _apply_shared_checks(
    *,
    row_id: int,
    clock_delta_s: float | None,
    cur_gps_dt: datetime | None,
    lat: float | None,
    lon: float | None,
    height: float | None,
    motor_on: bool | None,
    gps_count: int | None,
    acc: dict[str, list[int]],
    prev: dict[str, Any],
) -> None:
    """Apply 9 shared anomaly checks for one row. Mutates acc and prev in place.

    clock_delta_s: elapsed seconds since previous row (high-frequency clock).
    cur_gps_dt:    GPS/app datetime for coordinate-speed check (1 Hz for DatCon).
    """
    # --- interval-based checks (use high-frequency clock) ---
    if clock_delta_s is not None:
        if clock_delta_s < 0.0:
            acc["timestamp_regression"].append(row_id)
        if clock_delta_s > _TIMESTAMP_GAP_S:
            acc["timestamp_gap"].append(row_id)

        # altitude spike: |Δheight / Δt| > threshold
        if (
            height is not None
            and prev.get("height") is not None
            and clock_delta_s > 0.0
        ):
            if abs(height - prev["height"]) / clock_delta_s > _ALTITUDE_SPIKE_MS:
                acc["altitude_spike"].append(row_id)

    # --- GPS coordinate checks ---
    if lat is None or lon is None:
        acc["missing_gps"].append(row_id)
    elif lat == 0.0 and lon == 0.0:
        acc["zero_coordinate"].append(row_id)
    else:
        # coordinate jump: use GPS timestamp for speed (GPS coords and GPS time are co-sourced)
        prev_gps_dt: datetime | None = prev.get("gps_dt")
        if prev.get("lat") is not None and prev.get("lon") is not None and cur_gps_dt is not None and prev_gps_dt is not None:
            gps_dt_s = (cur_gps_dt - prev_gps_dt).total_seconds()
            if gps_dt_s >= 0.1:
                dist = haversine_m(prev["lat"], prev["lon"], lat, lon)
                if dist / gps_dt_s > _SPEED_THRESHOLD_MS:
                    acc["coordinate_jump"].append(row_id)
        prev["lat"] = lat
        prev["lon"] = lon
        prev["gps_dt"] = cur_gps_dt

    # --- altitude checks ---
    if height is not None:
        if height < _ALTITUDE_NEGATIVE_M:
            acc["altitude_negative"].append(row_id)

    # --- motor airborne check ---
    if motor_on is False and height is not None and height > _MOTOR_AIRBORNE_HEIGHT_M:
        acc["motor_airborne_off"].append(row_id)

    # --- GPS quality ---
    if gps_count is not None and gps_count < _GPS_POOR_FIX_SATS:
        acc["gps_poor_fix"].append(row_id)

    # update prev state
    if height is not None:
        prev["height"] = height


def _make_shared_acc() -> dict[str, list]:
    return {
        "timestamp_regression": [],
        "timestamp_gap": [],
        "missing_gps": [],
        "zero_coordinate": [],
        "coordinate_jump": [],
        "altitude_negative": [],
        "altitude_spike": [],
        "motor_airborne_off": [],
        "gps_poor_fix": [],
        "contains_no_value": [],
        "contains_constant_value": [],
    }


def _check_column_values(
    header: list[str],
    column_values: dict[str, list[str]],
    acc: dict[str, list],
) -> None:
    """Populate contains_no_value and contains_constant_value in acc.

    Skips [NORM]:* columns (derived) and [NORM]:ID.
    contains_no_value:       column has only empty strings or 'nan' values.
    contains_constant_value: column has exactly one distinct non-empty/non-nan value.
    """
    for col in header:
        if col.startswith("[NORM]:"):
            continue
        vals = column_values.get(col, [])
        non_trivial = [v for v in vals if v and v.lower() != "nan"]
        if not non_trivial:
            acc["contains_no_value"].append(col)
        elif len(set(non_trivial)) == 1:
            acc["contains_constant_value"].append(col)


def _augment_csv(
    src: Path,
    dst: Path,
    acc_extra: list[str],
    bind_fn: Callable[[list[str]], Any],
    norm_header_fn: Callable[[list[str], Any], list[str]],
    process_row_fn: Callable[[int, list[str], Any, dict], tuple],
) -> dict[str, Any]:
    """Shared CSV augmentation driver.

    process_row_fn(row_id, padded, idx, acc) returns:
      (new_row, clock_delta_s, cur_gps_dt, lat, lon, height, motor_on, gps_count)
    Format-specific anomaly checks are applied inside process_row_fn via acc.
    """
    dst.parent.mkdir(parents=True, exist_ok=True)
    acc = _make_shared_acc()
    acc.update({k: [] for k in acc_extra})
    prev: dict[str, Any] = {"lat": None, "lon": None, "gps_dt": None, "height": None}

    with (
        src.open(newline="", encoding="utf-8", errors="replace") as fh_in,
        dst.open("w", newline="", encoding="utf-8") as fh_out,
    ):
        reader = csv.reader(fh_in)
        writer = csv.writer(fh_out)
        header = next(reader, None)
        if header is None:
            return {k: [] for k in acc}
        idx = bind_fn(header)
        writer.writerow(norm_header_fn(header, idx))
        column_values: dict[str, list[str]] = {col: [] for col in header}

        for row_id, row in enumerate(reader):
            padded = row + [""] * max(0, len(header) - len(row))
            new_row, clock_delta_s, cur_gps_dt, lat, lon, height, motor_on, gps_count = (
                process_row_fn(row_id, padded, idx, acc)
            )
            writer.writerow(new_row)
            _apply_shared_checks(
                row_id=row_id,
                clock_delta_s=clock_delta_s,
                cur_gps_dt=cur_gps_dt,
                lat=lat,
                lon=lon,
                height=height,
                motor_on=motor_on,
                gps_count=gps_count,
                acc=acc,
                prev=prev,
            )
            for i, col in enumerate(header):
                column_values[col].append(padded[i].strip())

    _check_column_values(header, column_values, acc)
    return {k: sorted(v) for k, v in acc.items()}


def _augment_datcon_csv(src: Path, dst: Path) -> dict[str, Any]:
    """Augment a DatCon CSV with NORM columns and run all anomaly checks.

    New NORM columns:
      [NORM]:ID            — prepended row index
      [NORM]:GPS:Date      — after GPS:Date  (YYYY-MM-DD)
      [NORM]:GPS:Time      — after GPS:Time  (HH:MM:SS[.fff])
      [NORM]:GPS:dateTimeStamp — after GPS:dateTimeStamp (ISO 8601 +00:00)

    Returns dict of {check_name: [row_id, ...]}.
    """

    def _bind(header: list[str]) -> dict:
        # GPS/clock columns use exact match; sensor columns use prefix match
        # because DatCon appends :C (calculated) or :D (direct) suffixes that vary by version.
        def _i(col: str) -> int:
            return header.index(col) if col in header else -1
        return {
            "date_idx": _i(_DATCON_DATE_COL),
            "time_idx": _i(_DATCON_TIME_COL),
            "dts_idx": _i(_DATCON_DATETIME_STAMP_COL),
            "lat_idx": _i(_DATCON_LAT_COL),
            "lon_idx": _i(_DATCON_LON_COL),
            "numsv_idx": _i(_DATCON_NUMSV_COL),
            "hdop_idx": _i(_DATCON_HDOP_COL),
            "clock_idx": _i(_DATCON_CLOCK_COL),
            "height_idx": _find_col(header, _DATCON_HEIGHT_COL),
            "motor_idx": _find_col(header, _DATCON_MOTOR_COL),
            "roll_idx": _find_col(header, _DATCON_ROLL_COL),
            "pitch_idx": _find_col(header, _DATCON_PITCH_COL),
            "quatw_idx": _find_col(header, _DATCON_QUATW_COL),
            "quatx_idx": _find_col(header, _DATCON_QUATX_COL),
            "quaty_idx": _find_col(header, _DATCON_QUATY_COL),
            "quatz_idx": _find_col(header, _DATCON_QUATZ_COL),
        }

    def _norm_header(header: list[str], idx: dict) -> list[str]:
        new_header: list[str] = ["[NORM]:ID"]
        for col in header:
            new_header.append(col)
            if col == _DATCON_DATE_COL:
                new_header.append("[NORM]:GPS:Date")
            elif col == _DATCON_TIME_COL:
                new_header.append("[NORM]:GPS:Time")
            elif col == _DATCON_DATETIME_STAMP_COL:
                new_header.append("[NORM]:GPS:dateTimeStamp")
        return new_header

    prev_clock: list[float | None] = [None]

    def _process_row(row_id: int, padded: list[str], idx: dict, acc: dict) -> tuple:
        def _val(i: int) -> str:
            return padded[i].strip() if i >= 0 else ""

        date_norm = parse_datcon_date(_val(idx["date_idx"])) or ""
        time_norm = parse_datcon_time(_val(idx["time_idx"])) or ""
        dts_norm = parse_iso_timestamp(_val(idx["dts_idx"])) or ""

        new_row: list[str] = [str(row_id)]
        for i, val in enumerate(padded):
            new_row.append(val)
            if i == idx["date_idx"]:
                new_row.append(date_norm)
            elif i == idx["time_idx"]:
                new_row.append(time_norm)
            elif i == idx["dts_idx"]:
                new_row.append(dts_norm)

        lat = _try_float(_val(idx["lat_idx"]))
        lon = _try_float(_val(idx["lon_idx"]))
        height = _try_float(_val(idx["height_idx"]))
        numsv = _try_float(_val(idx["numsv_idx"]))
        gps_count = int(numsv) if numsv is not None else None

        motor_str = _val(idx["motor_idx"])
        motor_on: bool | None = None
        if motor_str:
            mv = _try_float(motor_str)
            if mv is not None:
                motor_on = mv != 0.0

        clock_val = _try_float(_val(idx["clock_idx"]))
        clock_delta_s: float | None = None
        if clock_val is not None and prev_clock[0] is not None:
            clock_delta_s = clock_val - prev_clock[0]
        if clock_val is not None:
            prev_clock[0] = clock_val

        cur_gps_dt: datetime | None = None
        if dts_norm:
            try:
                cur_gps_dt = datetime.fromisoformat(dts_norm)
            except ValueError:
                pass

        hdop = _try_float(_val(idx["hdop_idx"]))
        if hdop is not None and hdop > _GPS_HDOP_THRESHOLD:
            acc["gps_accuracy_poor"].append(row_id)

        qw = _try_float(_val(idx["quatw_idx"]))
        qx = _try_float(_val(idx["quatx_idx"]))
        qy = _try_float(_val(idx["quaty_idx"]))
        qz = _try_float(_val(idx["quatz_idx"]))
        if qw is not None and qx is not None and qy is not None and qz is not None:
            norm = math.sqrt(qw**2 + qx**2 + qy**2 + qz**2)
            if abs(norm - 1.0) > _QUATERNION_NORM_EPS:
                acc["quaternion_invalid"].append(row_id)

        roll = _try_float(_val(idx["roll_idx"]))
        pitch = _try_float(_val(idx["pitch_idx"]))
        if roll is not None and abs(roll) > 180.0:
            acc["attitude_out_of_bounds"].append(row_id)
        elif pitch is not None and abs(pitch) > 90.0:
            acc["attitude_out_of_bounds"].append(row_id)

        return new_row, clock_delta_s, cur_gps_dt, lat, lon, height, motor_on, gps_count

    return _augment_csv(
        src, dst,
        ["gps_accuracy_poor", "quaternion_invalid", "attitude_out_of_bounds"],
        _bind, _norm_header, _process_row,
    )


def _augment_flight_record_csv(src: Path, dst: Path) -> dict[str, Any]:
    """Augment a FlightRecord CSV with [NORM]:ID and [NORM]:CUSTOM.updateTime.

    New NORM columns:
      [NORM]:ID                — prepended row index
      [NORM]:CUSTOM.updateTime — after CUSTOM.updateTime (ISO 8601 +00:00 UTC)

    Returns dict of {check_name: [row_id, ...]}.
    """

    def _bind(header: list[str]) -> dict:
        def _i(col: str) -> int:
            return header.index(col) if col in header else -1
        return {
            "time_idx": _i(_FR_TIME_COL),
            "lat_idx": _i(_FR_LAT_COL),
            "lon_idx": _i(_FR_LON_COL),
            "height_idx": _i(_FR_HEIGHT_COL),
            "numsv_idx": _i(_FR_NUMSV_COL),
            "motor_idx": _i(_FR_MOTOR_COL),
            "batt_cap_idx": _i(_FR_BATTERY_CAPACITY_COL),
            "cell_indices": [_i(c) for c in _FR_BATTERY_CELLS],
            "temp_idx": _i(_FR_BATTERY_TEMP_COL),
        }

    def _norm_header(header: list[str], idx: dict) -> list[str]:
        new_header: list[str] = ["[NORM]:ID"]
        for col in header:
            new_header.append(col)
            if col == _FR_TIME_COL:
                new_header.append("[NORM]:CUSTOM.updateTime")
        return new_header

    prev_dt: list[datetime | None] = [None]

    def _process_row(row_id: int, padded: list[str], idx: dict, acc: dict) -> tuple:
        def _val(i: int) -> str:
            return padded[i].strip() if i >= 0 else ""

        time_norm = parse_flightrecord_timestamp(_val(idx["time_idx"])) or ""

        new_row: list[str] = [str(row_id)]
        for i, val in enumerate(padded):
            new_row.append(val)
            if i == idx["time_idx"]:
                new_row.append(time_norm)

        lat = _try_float(_val(idx["lat_idx"]))
        lon = _try_float(_val(idx["lon_idx"]))
        height = _try_float(_val(idx["height_idx"]))
        numsv = _try_float(_val(idx["numsv_idx"]))
        gps_count = int(numsv) if numsv is not None else None

        motor_str = _val(idx["motor_idx"])
        motor_on: bool | None = None
        if motor_str:
            motor_on = motor_str == "True"

        cur_dt: datetime | None = None
        clock_delta_s: float | None = None
        if time_norm:
            try:
                cur_dt = datetime.fromisoformat(time_norm)
            except ValueError:
                pass
        if cur_dt is not None and prev_dt[0] is not None:
            clock_delta_s = (cur_dt - prev_dt[0]).total_seconds()
        if cur_dt is not None:
            prev_dt[0] = cur_dt

        cells: list[float] = []
        for ci in idx["cell_indices"]:
            v = _try_float(_val(ci))
            if v is not None and v != 0.0:
                cells.append(v)
                if v < _BATTERY_CELL_MIN_V or v > _BATTERY_CELL_MAX_V:
                    acc["battery_cell_voltage_out_of_range"].append(row_id)

        if len(cells) >= 2 and max(cells) - min(cells) > _BATTERY_CELL_IMBALANCE_V:
            acc["battery_cell_imbalance"].append(row_id)

        temp = _try_float(_val(idx["temp_idx"]))
        if temp is not None and (temp < _BATTERY_TEMP_MIN_C or temp > _BATTERY_TEMP_MAX_C):
            acc["battery_temperature_out_of_range"].append(row_id)

        batt_cap = _try_float(_val(idx["batt_cap_idx"]))
        if motor_on is True and batt_cap is not None and batt_cap <= 0:
            acc["motor_on_empty_battery"].append(row_id)

        return new_row, clock_delta_s, cur_dt, lat, lon, height, motor_on, gps_count

    return _augment_csv(
        src, dst,
        ["battery_cell_voltage_out_of_range", "battery_cell_imbalance",
         "battery_temperature_out_of_range", "motor_on_empty_battery"],
        _bind, _norm_header, _process_row,
    )


def _decode_image(
    artefact: dict[str, Any],
    phase_dir: Path,
    identification: str,
    exif_data: Any = None,
) -> Evidence | None:
    """Copy an opaque-extension image to a viewable file with the correct extension.

    Reads MIMEType from the exif JSON (stored_path), maps it to an extension,
    then copies the original binary (source_path) to the p5 output directory.
    Returns None if the source extension is already viewable, the MIME type is
    unknown, or any file is missing.
    """
    source_path = Path(str(artefact.get("source_path") or ""))
    if source_path.suffix.lower() not in _OPAQUE_IMAGE_EXTENSIONS:
        return None

    stored_path = Path(str(artefact.get("stored_path") or ""))
    if not source_path.exists() or not stored_path.exists():
        return None

    if exif_data is None:
        try:
            exif_data = json.loads(stored_path.read_text(encoding="utf-8"))
        except Exception:
            return None
    data = _exif_root(exif_data)
    if data is None:
        return None

    mime = str(_exif_find(data, "MIMEType") or "").lower()
    ext = _MIME_TO_EXT.get(mime)
    if not ext:
        return None

    dst_dir = phase_dir / identification / IMAGES
    dst_dir.mkdir(parents=True, exist_ok=True)
    dst = dst_dir / (source_path.stem + ext)
    shutil.copy2(source_path, dst)

    parent_evidence = Evidence.from_dict(artefact)
    return make_evidence(
        source_path=to_windows_path(str(source_path)),
        stored_path=dst,
        parent=parent_evidence,
        acquisition_method=ACQUISITION_NORMALISE,
        type=EVIDENCE_TYPE_NORMALISED,
        artefact_category=IMAGES,
    )


def _process_exif(
    artefact: dict[str, Any],
    exif_data: Any = None,
) -> Observation | None:
    """Normalise EXIF timestamps and check for zero-date / missing GPS.

    Uses parent_sha256 (original media sha256) as evidence_sha256, not the JSON's own sha256.
    Returns None if there is nothing to report (valid date, valid GPS, unparseable file).
    """
    stored_path = Path(str(artefact.get("stored_path") or ""))
    if not stored_path.exists():
        return None
    if exif_data is None:
        try:
            exif_data = json.loads(stored_path.read_text(encoding="utf-8"))
        except Exception:
            return None
    data = _exif_root(exif_data)
    if data is None:
        return None

    date_val = _exif_find(data, "DateTimeOriginal") or _exif_find(data, "CreateDate")
    exif_zero_date = not date_val or date_val == "0000:00:00 00:00:00"
    lat, lon = _exif_location(data)
    exif_missing_gps = lat is None or lon is None

    parsed = parse_exif_date(date_val or "")

    if parsed is None and not exif_zero_date and not exif_missing_gps:
        return None

    obs: dict[str, Any] = {}
    if parsed:
        obs["norm_date"], obs["norm_time"] = parsed
    if lat is not None and lon is not None:
        obs["gps_latitude"] = lat
        obs["gps_longitude"] = lon
    if exif_zero_date:
        obs["exif_zero_date"] = True
    if exif_missing_gps:
        obs["exif_missing_gps"] = True

    return make_observation(
        stored_path=str(stored_path),
        evidence_sha256=str(artefact.get("parent_sha256") or ""),
        evidence_category=str(artefact.get("artefact_category") or ""),
        acquisition_method=ACQUISITION_NORMALISE,
        observations=[obs],
    )


def _is_non_readable(path: Path) -> bool:
    """Return True if the file is binary or predominantly non-human-readable."""
    try:
        raw = path.read_bytes()[:_PROBE_BYTES]
        text = raw.decode("utf-8")
    except (UnicodeDecodeError, OSError):
        return True
    if not text:
        return False
    non_print = sum(1 for c in text if not c.isprintable() and c not in "\t\n\r")
    return (non_print / len(text)) > _NON_PRINTABLE_THRESHOLD


def _parse_crash_dump(text: str) -> list[dict[str, Any]]:
    """Extract structured failure entries from DJI Android crash log format."""
    entries: list[dict[str, Any]] = []
    section = ""
    in_crash_section = False
    exception_found = False
    for line in text.splitlines():
        m = _SECTION_RE.match(line.strip())
        if m:
            section = m.group(1).strip().lower()
            in_crash_section = "crash" in section
            exception_found = False
            continue
        if in_crash_section and not exception_found:
            stripped = line.strip()
            if stripped and not stripped.startswith("at ") and "\tat" not in stripped[:4]:
                if ": " in stripped:
                    exc_type, _, exc_msg = stripped.partition(": ")
                    entries.append({"type": "java_exception", "exception": exc_type, "message": exc_msg})
                    exception_found = True
                elif "Error" in stripped or "Exception" in stripped:
                    entries.append({"type": "java_exception", "exception": stripped, "message": ""})
                    exception_found = True
        if "thread" in section and line.strip().lower().startswith("crash name:"):
            name = line.strip()[len("crash name:"):].strip()
            if name and name.lower() != "null":
                entries.append({"type": "thread_crash", "name": name})
    return entries


def _parse_heading_log(text: str) -> list[dict[str, Any]]:
    """Extract (timestamp, message) pairs from ## HH:MM:SS / message format."""
    entries: list[dict[str, Any]] = []
    current_ts: str | None = None
    for line in text.splitlines():
        m = _HEADING_TS_RE.match(line)
        if m:
            current_ts = m.group(1)
        elif current_ts is not None and line.strip():
            entries.append({"timestamp": current_ts, "message": line.strip()})
            current_ts = None
    return entries


def _parse_bracketed_log(text: str, inline: bool = False) -> list[dict[str, Any]]:
    """Extract timestamp/message pairs from bracketed log formats.

    inline=False: [timestamp, message]  (comma-separated inside brackets)
    inline=True:  [timestamp]message    (message follows closing bracket)
    """
    pattern = _BRACKET_INLINE_RE if inline else _BRACKET_RE
    return [
        {"timestamp": m.group(1).strip(), "message": m.group(2).strip()}
        for m in pattern.finditer(text)
    ]


def _parse_json_array_log(text: str) -> list[dict[str, Any]]:
    """Extract entries from iOS JSON-array-of-arrays flight log format.

    Each record: ["timestamp", "level", "message"]
    level is included in the message when non-empty.
    """
    entries = []
    for m in _JSON_ARRAY_LOG_RE.finditer(text):
        ts = m.group(1)
        level = m.group(2).strip()
        msg = m.group(3).strip()
        entries.append({
            "timestamp": ts,
            "message": f"[{level}] {msg}" if level else msg,
        })
    return entries


def _classify_flight_log(text: str) -> tuple[str, list[dict[str, Any]]]:
    """Classify a flight log text and return (format_name, entries)."""
    if _JSON_ARRAY_LOG_RE.search(text):
        return "json_array_log", _parse_json_array_log(text)
    if _BRACKET_RE.search(text):
        return "bracketed_log", _parse_bracketed_log(text)
    if _BRACKET_INLINE_RE.search(text):
        return "bracketed_log", _parse_bracketed_log(text, inline=True)
    if _CRASH_SECTION_RE.search(text):
        return "crash_dump", _parse_crash_dump(text)
    if _HEADING_TS_RE.search(text):
        return "heading_log", _parse_heading_log(text)
    return "unknown", []


def _check_database_empty(db_path: Path) -> bool:
    """Return True if every table in the SQLite database has zero rows, or no tables exist."""
    try:
        con = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        try:
            tables = [r[0] for r in con.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()]
            return all(
                con.execute(f"SELECT COUNT(*) FROM [{t}]").fetchone()[0] == 0
                for t in tables
            ) if tables else True
        finally:
            con.close()
    except Exception:
        return False


def run_phase_5(state: State) -> State:
    phase_dir = output_dir() / state.case_id / _PHASE_NAME
    clear_and_make(phase_dir)

    normalised: list[Evidence] = []
    anomalies: list[Observation] = []

    p4_artefacts = state.phase_outputs.get("p4_decision_and_orchestration", {}).get(
        "decision_and_orchestration_artefacts", []
    )
    identification_map = _build_identification_map(state)
    _announced_categories: set[str] = set()
    _id_order = {ident: i for i, ident in enumerate(SOURCE_IDENTIFICATION_TYPES)}

    p3_artefacts = state.phase_outputs.get("p3_artefact_extraction", {}).get("extracted_artefacts", [])
    db_artefacts = [a for a in p3_artefacts if str(a.get("artefact_category") or "") == DATABASES]
    db_artefacts.sort(key=lambda a: (
        _id_order.get(identification_map.get(str(a.get("sha256") or ""), ""), 999),
        str(a.get("stored_path") or ""),
    ))

    if db_artefacts and DATABASES not in _announced_categories:
        print(f"  Normalising and Anomaly Checking {DATABASES}")
        _announced_categories.add(DATABASES)

    for artefact in db_artefacts:
        stored_path = Path(str(artefact.get("stored_path") or ""))
        sha = str(artefact.get("sha256") or "")
        identification = identification_map.get(sha, "unknown")
        if not stored_path.exists():
            state.raise_anomaly(5, identification, f"p3 database artefact not found: {stored_path.name}", category=DATABASES)
            continue
        if _check_database_empty(stored_path):
            anomalies.append(make_observation(
                stored_path=str(stored_path),
                evidence_sha256=sha,
                evidence_category=DATABASES,
                acquisition_method=ACQUISITION_NORMALISE,
                observations=[{"database_empty": True}],
            ))

    fl_artefacts = [a for a in p3_artefacts if str(a.get("artefact_category") or "") == FLIGHT_LOGS]
    fl_artefacts.sort(key=lambda a: (
        _id_order.get(identification_map.get(str(a.get("sha256") or ""), ""), 999),
        str(a.get("stored_path") or ""),
    ))

    if fl_artefacts and FLIGHT_LOGS not in _announced_categories:
        print(f"  Normalising and Anomaly Checking {FLIGHT_LOGS}")
        _announced_categories.add(FLIGHT_LOGS)

    for artefact in fl_artefacts:
        stored_path = Path(str(artefact.get("stored_path") or ""))
        sha = str(artefact.get("sha256") or "")
        identification = identification_map.get(sha, "unknown")
        if not stored_path.exists():
            state.raise_anomaly(5, identification, f"p3 flight_log artefact not found: {stored_path.name}", category=FLIGHT_LOGS)
            continue
        if _is_non_readable(stored_path):
            obs_data: dict[str, Any] = {"non_readable": True}
        else:
            try:
                text = stored_path.read_text(encoding="utf-8", errors="replace")
                fmt, entries = _classify_flight_log(text)
                obs_data: dict[str, Any] = {"format": fmt}
                if fmt != "unknown":
                    obs_data["entries"] = entries
            except OSError as exc:
                state.raise_anomaly(5, identification, f"flight_log read failed: {exc}", category=FLIGHT_LOGS)
                continue
        anomalies.append(make_observation(
            stored_path=str(stored_path),
            evidence_sha256=sha,
            evidence_category=FLIGHT_LOGS,
            acquisition_method=ACQUISITION_NORMALISE,
            observations=[obs_data],
        ))

    for artefact in p4_artefacts:
        acquisition = str(artefact.get("acquisition_method") or "")
        category = str(artefact.get("artefact_category") or "")
        parent_sha = str(artefact.get("parent_sha256") or "")
        identification = identification_map.get(parent_sha, "unknown")

        stored_path = Path(str(artefact.get("stored_path") or ""))
        if not stored_path.exists():
            state.raise_anomaly(
                5, identification, f"p4 artefact not found: {stored_path.name}", category=category
            )
            continue

        parent_evidence = Evidence.from_dict(artefact)

        if acquisition == ACQUISITION_DATCON and stored_path.suffix.lower() == ".csv":
            if DRONE_LOGS not in _announced_categories:
                print(f"  Normalising and Anomaly Checking {DRONE_LOGS}")
                _announced_categories.add(DRONE_LOGS)
            dst = phase_dir / identification / DRONE_LOGS / ("norm_" + stored_path.stem + ".csv")
            try:
                anomaly_results = _augment_datcon_csv(stored_path, dst)
            except Exception as exc:
                state.raise_anomaly(
                    5, identification, f"DatCon CSV augmentation failed: {exc}",
                    category=DRONE_LOGS,
                )
                continue

            evidence = make_evidence(
                source_path=to_windows_path(str(stored_path)),
                stored_path=dst,
                parent=parent_evidence,
                acquisition_method=ACQUISITION_NORMALISE,
                type=EVIDENCE_TYPE_NORMALISED,
                artefact_category=DRONE_LOGS,
            )
            normalised.append(evidence)
            non_empty = {k: v for k, v in anomaly_results.items() if v}
            anomalies.append(make_observation(
                stored_path=str(evidence.stored_path),
                evidence_sha256=evidence.sha256,
                evidence_category=DRONE_LOGS,
                acquisition_method=ACQUISITION_NORMALISE,
                observations=[non_empty],
            ))

        elif acquisition == ACQUISITION_TXTLOGTOCSV and stored_path.suffix.lower() == ".csv":
            if FLIGHT_RECORDS not in _announced_categories:
                print(f"  Normalising and Anomaly Checking {FLIGHT_RECORDS}")
                _announced_categories.add(FLIGHT_RECORDS)
            dst = phase_dir / identification / FLIGHT_RECORDS / ("norm_" + stored_path.stem + ".csv")
            try:
                anomaly_results = _augment_flight_record_csv(stored_path, dst)
            except Exception as exc:
                state.raise_anomaly(
                    5, identification, f"FlightRecord CSV augmentation failed: {exc}",
                    category=FLIGHT_RECORDS,
                )
                continue

            evidence = make_evidence(
                source_path=to_windows_path(str(stored_path)),
                stored_path=dst,
                parent=parent_evidence,
                acquisition_method=ACQUISITION_NORMALISE,
                type=EVIDENCE_TYPE_NORMALISED,
                artefact_category=FLIGHT_RECORDS,
            )
            normalised.append(evidence)
            non_empty = {k: v for k, v in anomaly_results.items() if v}
            anomalies.append(make_observation(
                stored_path=str(evidence.stored_path),
                evidence_sha256=evidence.sha256,
                evidence_category=FLIGHT_RECORDS,
                acquisition_method=ACQUISITION_NORMALISE,
                observations=[non_empty],
            ))

        elif acquisition == ACQUISITION_EXIFTOOL:
            if category not in _announced_categories:
                print(f"  Normalising and Anomaly Checking {category}")
                _announced_categories.add(category)
            exif_stored = Path(str(artefact.get("stored_path") or ""))
            exif_data: dict[str, Any] | None = None
            if exif_stored.exists():
                try:
                    exif_data = json.loads(exif_stored.read_text(encoding="utf-8"))
                except Exception:
                    pass
            decoded = _decode_image(artefact, phase_dir, identification, exif_data)
            if decoded is not None:
                normalised.append(decoded)
            obs = _process_exif(artefact, exif_data)
            if obs is not None:
                anomalies.append(obs)

    _id_rank = {ident: i for i, ident in enumerate(SOURCE_IDENTIFICATION_TYPES)}

    def _anomaly_sort_key(obs: Observation) -> tuple:
        path_parts = Path(obs.content.stored_path or "").parts
        rank = 999
        for seg in path_parts:
            # exact match (controller_android, controller_ios, drone_flight_storage)
            if seg in _id_rank:
                rank = _id_rank[seg]
                break
            # prefix match for drone_sd_1, drone_sd_2, …
            matched = next((ident for ident in _id_rank if seg.startswith(ident + "_") or seg == ident), None)
            if matched:
                rank = _id_rank[matched]
                break
        return (rank, obs.content.evidence_category or "", obs.content.stored_path or "")

    anomalies.sort(key=_anomaly_sort_key)

    state.phase_outputs[_PHASE_NAME] = {
        "completed_at": utc_now_iso(),
        "normalised_artefacts": [e.to_dict() for e in normalised],
        "derived_anomalies": [o.to_dict() for o in anomalies],
    }
    state.completed_phases.append(_PHASE_NAME)
    return state
