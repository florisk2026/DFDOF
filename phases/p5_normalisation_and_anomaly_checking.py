"""DFDOF Phase 5: Normalisation and Anomaly Checking.

This phase:
 - augments DatCon CSVs with [NORM]:ID, [NORM]:GPS:Date, [NORM]:GPS:Time,
   [NORM]:GPS:dateTimeStamp columns,
 - augments FlightRecord CSVs with [NORM]:ID and [NORM]:CUSTOM.updateTime,
 - runs 10 shared + format-specific single-source anomaly checks,
 - stores anomaly findings as Observations (not state anomaly flags),
 - wraps augmented CSVs as Evidence objects,
 - copies opaque-extension image files (.thumbnail, .THM) to viewable
   equivalents derived from their MIMEType.
"""

from __future__ import annotations

import csv
import json
import math
import shutil
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Any

from config import (
    ACQUISITION_DATCON,
    ACQUISITION_EXIFTOOL,
    ACQUISITION_NORMALISE,
    ACQUISITION_TXTLOGTOCSV,
    DATABASES,
    DRONE_LOGS,
    EVIDENCE_TYPE_NORMALISED,
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

_SPEED_THRESHOLD_MS = 80.0
_TIMESTAMP_GAP_S = 60.0
_ALTITUDE_SPIKE_MS = 20.0
_ALTITUDE_NEGATIVE_M = -0.1
_MOTOR_AIRBORNE_HEIGHT_M = 1.0
_GPS_POOR_FIX_SATS = 4
_GPS_HDOP_THRESHOLD = 5.0
_QUATERNION_NORM_EPS = 0.01
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

_BATTERY_CELL_MIN_V = 2.8
_BATTERY_CELL_MAX_V = 4.4
_BATTERY_CELL_IMBALANCE_V = 0.3
_BATTERY_TEMP_MIN_C = -20.0
_BATTERY_TEMP_MAX_C = 80.0

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
    """Map each P3-artefact-sha256 to its source folder label.

    For drone_sd sources the label is drone_sd_1, drone_sd_2, … matching the
    numbered directories produced by P3/P4. All other sources use their
    identification string directly.

    Chain: P3-artefact.parent_sha256 → input-evidence sha256 → label.
    P4 artefacts carry parent_sha256 pointing to P3 artefacts, so this map
    is keyed on P3-artefact sha256 and looked up via P4-artefact.parent_sha256.
    """
    p1_records = state.phase_outputs.get("p1_provenance", {}).get("identified_evidence", [])
    source_path_to_id: dict[str, str] = {}
    for record in p1_records:
        src = str(record.get("source_path") or "")
        ident = str(record.get("identified_by_operator_as") or record.get("identified_as", ""))
        if src:
            source_path_to_id[src] = ident

    # Map input-evidence sha256 → folder label, with drone_sd numbered.
    drone_sd_sources = find_input_evidence_list_by_identification(state, IDENTIFICATION_DRONE_SD)
    drone_sd_sha_to_label: dict[str, str] = {
        ev.sha256: drone_sd_label(idx)
        for idx, ev in enumerate(drone_sd_sources, start=1)
        if ev.sha256
    }

    input_sha_to_label: dict[str, str] = {}
    for evidence in state.input_evidence:
        if not evidence.sha256:
            continue
        if evidence.sha256 in drone_sd_sha_to_label:
            input_sha_to_label[evidence.sha256] = drone_sd_sha_to_label[evidence.sha256]
        else:
            src = str(evidence.source_path)
            if src in source_path_to_id:
                input_sha_to_label[evidence.sha256] = source_path_to_id[src]

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
    """Apply 10 shared anomaly checks for one row. Mutates acc and prev in place.

    clock_delta_s: elapsed seconds since previous row (high-frequency clock).
    cur_gps_dt:    GPS/app datetime for coordinate-speed check (1 Hz for DatCon).
    """
    # --- interval-based checks (use high-frequency clock) ---
    if clock_delta_s is not None:
        if clock_delta_s == 0.0 and row_id > 0:
            acc["duplicate_timestamp"].append(row_id)
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
        "duplicate_timestamp": [],
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


def _augment_datcon_csv(src: Path, dst: Path) -> dict[str, Any]:
    """Augment a DatCon CSV with NORM columns and run all anomaly checks.

    New NORM columns:
      [NORM]:ID            — prepended row index
      [NORM]:GPS:Date      — after GPS:Date  (YYYY-MM-DD)
      [NORM]:GPS:Time      — after GPS:Time  (HH:MM:SS[.fff])
      [NORM]:GPS:dateTimeStamp — after GPS:dateTimeStamp (ISO 8601 +00:00)

    Returns dict of {check_name: [row_id, ...]}.
    """
    dst.parent.mkdir(parents=True, exist_ok=True)

    acc = _make_shared_acc()
    acc.update({
        "gps_accuracy_poor": [],
        "quaternion_invalid": [],
        "attitude_out_of_bounds": [],
    })
    prev: dict[str, Any] = {"lat": None, "lon": None, "gps_dt": None, "height": None}
    prev_clock: float | None = None

    with (
        src.open(newline="", encoding="utf-8", errors="replace") as fh_in,
        dst.open("w", newline="", encoding="utf-8") as fh_out,
    ):
        reader = csv.reader(fh_in)
        writer = csv.writer(fh_out)

        header = next(reader, None)
        if header is None:
            return {k: [] for k in acc}

        # GPS/clock columns use exact match; sensor columns use prefix match
        # because DatCon appends :C (calculated) or :D (direct) suffixes that vary by version.
        def _idx(col: str) -> int:
            return header.index(col) if col in header else -1

        date_idx = _idx(_DATCON_DATE_COL)
        time_idx = _idx(_DATCON_TIME_COL)
        dts_idx = _idx(_DATCON_DATETIME_STAMP_COL)
        lat_idx = _idx(_DATCON_LAT_COL)
        lon_idx = _idx(_DATCON_LON_COL)
        numsv_idx = _idx(_DATCON_NUMSV_COL)
        hdop_idx = _idx(_DATCON_HDOP_COL)
        clock_idx = _idx(_DATCON_CLOCK_COL)
        # Sensor columns: prefix match handles :C/:D suffix variants
        height_idx = _find_col(header, _DATCON_HEIGHT_COL)
        motor_idx = _find_col(header, _DATCON_MOTOR_COL)
        roll_idx = _find_col(header, _DATCON_ROLL_COL)
        pitch_idx = _find_col(header, _DATCON_PITCH_COL)
        quatw_idx = _find_col(header, _DATCON_QUATW_COL)
        quatx_idx = _find_col(header, _DATCON_QUATX_COL)
        quaty_idx = _find_col(header, _DATCON_QUATY_COL)
        quatz_idx = _find_col(header, _DATCON_QUATZ_COL)

        new_header: list[str] = ["[NORM]:ID"]
        for col in header:
            new_header.append(col)
            if col == _DATCON_DATE_COL:
                new_header.append("[NORM]:GPS:Date")
            elif col == _DATCON_TIME_COL:
                new_header.append("[NORM]:GPS:Time")
            elif col == _DATCON_DATETIME_STAMP_COL:
                new_header.append("[NORM]:GPS:dateTimeStamp")
        writer.writerow(new_header)

        column_values: dict[str, list[str]] = {col: [] for col in header}

        for row_id, row in enumerate(reader):
            padded = row + [""] * max(0, len(header) - len(row))

            def _val(idx: int) -> str:
                return padded[idx].strip() if idx >= 0 else ""

            date_val = _val(date_idx)
            time_val = _val(time_idx)
            dts_val = _val(dts_idx)
            date_norm = parse_datcon_date(date_val) or ""
            time_norm = parse_datcon_time(time_val) or ""
            dts_norm = parse_iso_timestamp(dts_val) or ""

            new_row: list[str] = [str(row_id)]
            for i, val in enumerate(padded):
                new_row.append(val)
                if i == date_idx:
                    new_row.append(date_norm)
                elif i == time_idx:
                    new_row.append(time_norm)
                elif i == dts_idx:
                    new_row.append(dts_norm)
            writer.writerow(new_row)

            # --- parse values for checks ---
            lat = _try_float(_val(lat_idx))
            lon = _try_float(_val(lon_idx))
            height = _try_float(_val(height_idx))
            numsv = _try_float(_val(numsv_idx))
            gps_count = int(numsv) if numsv is not None else None

            # motor: 0 = off, non-zero = on
            motor_str = _val(motor_idx)
            motor_on: bool | None = None
            if motor_str:
                mv = _try_float(motor_str)
                if mv is not None:
                    motor_on = mv != 0.0

            # clock delta (high-frequency)
            clock_val = _try_float(_val(clock_idx))
            clock_delta_s: float | None = None
            if clock_val is not None and prev_clock is not None:
                clock_delta_s = clock_val - prev_clock
            if clock_val is not None:
                prev_clock = clock_val

            # GPS datetime (1 Hz) for coordinate speed check
            cur_gps_dt: datetime | None = None
            if dts_norm:
                try:
                    cur_gps_dt = datetime.fromisoformat(dts_norm)
                except ValueError:
                    pass

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

            # --- DatCon-specific checks ---
            hdop = _try_float(_val(hdop_idx))
            if hdop is not None and hdop > _GPS_HDOP_THRESHOLD:
                acc["gps_accuracy_poor"].append(row_id)

            qw = _try_float(_val(quatw_idx))
            qx = _try_float(_val(quatx_idx))
            qy = _try_float(_val(quaty_idx))
            qz = _try_float(_val(quatz_idx))
            if qw is not None and qx is not None and qy is not None and qz is not None:
                norm = math.sqrt(qw**2 + qx**2 + qy**2 + qz**2)
                if abs(norm - 1.0) > _QUATERNION_NORM_EPS:
                    acc["quaternion_invalid"].append(row_id)

            roll = _try_float(_val(roll_idx))
            pitch = _try_float(_val(pitch_idx))
            if roll is not None and abs(roll) > 180.0:
                acc["attitude_out_of_bounds"].append(row_id)
            elif pitch is not None and abs(pitch) > 90.0:
                acc["attitude_out_of_bounds"].append(row_id)

            for i, col in enumerate(header):
                column_values[col].append(padded[i].strip())

    _check_column_values(header, column_values, acc)
    return {k: sorted(v) for k, v in acc.items()}


def _augment_flight_record_csv(src: Path, dst: Path) -> dict[str, Any]:
    """Augment a FlightRecord CSV with [NORM]:ID and [NORM]:CUSTOM.updateTime.

    New NORM columns:
      [NORM]:ID                — prepended row index
      [NORM]:CUSTOM.updateTime — after CUSTOM.updateTime (ISO 8601 +00:00 UTC)

    Returns dict of {check_name: [row_id, ...]}.
    """
    dst.parent.mkdir(parents=True, exist_ok=True)

    acc = _make_shared_acc()
    acc.update({
        "battery_cell_voltage_out_of_range": [],
        "battery_cell_imbalance": [],
        "battery_temperature_out_of_range": [],
        "motor_on_empty_battery": [],
    })
    prev: dict[str, Any] = {"lat": None, "lon": None, "gps_dt": None, "height": None}
    prev_dt: datetime | None = None

    with (
        src.open(newline="", encoding="utf-8", errors="replace") as fh_in,
        dst.open("w", newline="", encoding="utf-8") as fh_out,
    ):
        reader = csv.reader(fh_in)
        writer = csv.writer(fh_out)

        header = next(reader, None)
        if header is None:
            return {k: [] for k in acc}

        def _idx(col: str) -> int:
            return header.index(col) if col in header else -1

        time_idx = _idx(_FR_TIME_COL)
        lat_idx = _idx(_FR_LAT_COL)
        lon_idx = _idx(_FR_LON_COL)
        height_idx = _idx(_FR_HEIGHT_COL)
        numsv_idx = _idx(_FR_NUMSV_COL)
        motor_idx = _idx(_FR_MOTOR_COL)
        batt_cap_idx = _idx(_FR_BATTERY_CAPACITY_COL)
        cell_indices = [_idx(c) for c in _FR_BATTERY_CELLS]
        temp_idx = _idx(_FR_BATTERY_TEMP_COL)

        new_header: list[str] = ["[NORM]:ID"]
        for col in header:
            new_header.append(col)
            if col == _FR_TIME_COL:
                new_header.append("[NORM]:CUSTOM.updateTime")
        writer.writerow(new_header)

        column_values: dict[str, list[str]] = {col: [] for col in header}

        for row_id, row in enumerate(reader):
            padded = row + [""] * max(0, len(header) - len(row))

            def _val(idx: int) -> str:
                return padded[idx].strip() if idx >= 0 else ""

            time_val = _val(time_idx)
            time_norm = parse_flightrecord_timestamp(time_val) or ""

            new_row: list[str] = [str(row_id)]
            for i, val in enumerate(padded):
                new_row.append(val)
                if i == time_idx:
                    new_row.append(time_norm)
            writer.writerow(new_row)

            # --- parse values for checks ---
            lat = _try_float(_val(lat_idx))
            lon = _try_float(_val(lon_idx))
            height = _try_float(_val(height_idx))
            numsv = _try_float(_val(numsv_idx))
            gps_count = int(numsv) if numsv is not None else None

            motor_str = _val(motor_idx)
            motor_on: bool | None = None
            if motor_str:
                motor_on = motor_str == "True"

            # clock delta from CUSTOM.updateTime (ms precision)
            cur_dt: datetime | None = None
            clock_delta_s: float | None = None
            if time_norm:
                try:
                    cur_dt = datetime.fromisoformat(time_norm)
                except ValueError:
                    pass
            if cur_dt is not None and prev_dt is not None:
                clock_delta_s = (cur_dt - prev_dt).total_seconds()
            if cur_dt is not None:
                prev_dt = cur_dt

            _apply_shared_checks(
                row_id=row_id,
                clock_delta_s=clock_delta_s,
                cur_gps_dt=cur_dt,
                lat=lat,
                lon=lon,
                height=height,
                motor_on=motor_on,
                gps_count=gps_count,
                acc=acc,
                prev=prev,
            )

            # --- FlightRecord-specific checks ---
            cells: list[float] = []
            for ci in cell_indices:
                v = _try_float(_val(ci))
                if v is not None and v != 0.0:
                    cells.append(v)
                    if v < _BATTERY_CELL_MIN_V or v > _BATTERY_CELL_MAX_V:
                        acc["battery_cell_voltage_out_of_range"].append(row_id)

            if len(cells) >= 2:
                if max(cells) - min(cells) > _BATTERY_CELL_IMBALANCE_V:
                    acc["battery_cell_imbalance"].append(row_id)

            temp = _try_float(_val(temp_idx))
            if temp is not None and (temp < _BATTERY_TEMP_MIN_C or temp > _BATTERY_TEMP_MAX_C):
                acc["battery_temperature_out_of_range"].append(row_id)

            batt_cap = _try_float(_val(batt_cap_idx))
            if motor_on is True and batt_cap is not None and batt_cap <= 0:
                acc["motor_on_empty_battery"].append(row_id)

            for i, col in enumerate(header):
                column_values[col].append(padded[i].strip())

    _check_column_values(header, column_values, acc)
    return {k: sorted(v) for k, v in acc.items()}


def _decode_image(
    artefact: dict[str, Any],
    phase_dir: Path,
    identification: str,
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

    try:
        data = json.loads(stored_path.read_text(encoding="utf-8"))
    except Exception:
        return None

    mime = str(data.get("MIMEType") or "").lower()
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


def _process_exif(artefact: dict[str, Any]) -> Observation | None:
    """Normalise EXIF timestamps and check for zero-date / missing GPS.

    Uses parent_sha256 (original media sha256) as evidence_sha256, not the JSON's own sha256.
    Returns None if there is nothing to report (valid date, valid GPS, unparseable file).
    """
    stored_path = Path(str(artefact.get("stored_path") or ""))
    if not stored_path.exists():
        return None
    try:
        data = json.loads(stored_path.read_text(encoding="utf-8"))
    except Exception:
        return None

    date_val = data.get("DateTimeOriginal") or data.get("CreateDate")
    exif_zero_date = not date_val or date_val == "0000:00:00 00:00:00"
    exif_missing_gps = "GPSLatitude" not in data or "GPSLongitude" not in data

    parsed = parse_exif_date(date_val or "")

    if parsed is None and not exif_zero_date and not exif_missing_gps:
        return None

    obs: dict[str, Any] = {}
    if parsed:
        obs["norm_date"], obs["norm_time"] = parsed
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
            decoded = _decode_image(artefact, phase_dir, identification)
            if decoded is not None:
                normalised.append(decoded)
            obs = _process_exif(artefact)
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
