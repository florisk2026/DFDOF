from __future__ import annotations

import csv
import json
from pathlib import Path

import config
from evidence import make_evidence
from phases import p5_normalisation_and_anomaly_checking as p5
from phases.utils_phase import (
    haversine_m,
    parse_datcon_date,
    parse_datcon_time,
    parse_flightrecord_timestamp,
    parse_iso_timestamp,
)
from state import State


# Helpers

def _build_state(
    tmp_path: Path,
    identification: str,
    p4_file: Path,
    p4_acquisition: str,
    p4_category: str,
) -> State:
    """Build a minimal State with a wired P1→P3→P4 chain for one artefact."""
    state = State(case_id="CASE-P5-TEST", operator="Tester")

    src = tmp_path / "source.zip"
    if not src.exists():
        src.write_text("src", encoding="utf-8")
    source_ev = make_evidence(
        source_path=str(src),
        stored_path=src,
        parent=None,
        acquisition_method=config.ACQUISITION_LOGICAL,
        type=config.EVIDENCE_TYPE_INPUT,
        source_identification=identification,
    )
    state.input_evidence.append(source_ev)

    p3_raw = tmp_path / "p3_raw.bin"
    if not p3_raw.exists():
        p3_raw.write_text("raw", encoding="utf-8")
    p3_ev = make_evidence(
        source_path=str(p3_raw),
        stored_path=p3_raw,
        parent=source_ev,
        acquisition_method=config.ACQUISITION_EXTRACT_LOGICAL,
        type=config.EVIDENCE_TYPE_EXTRACTED,
        artefact_category=p4_category,
    )
    state.phase_outputs["p3_artefact_extraction"] = {
        "extracted_artefacts": [p3_ev.to_dict()]
    }

    p4_ev = make_evidence(
        source_path=str(p3_raw),
        stored_path=p4_file,
        parent=p3_ev,
        acquisition_method=p4_acquisition,
        type=config.EVIDENCE_TYPE_DECODED,
        artefact_category=p4_category,
    )
    state.phase_outputs["p4_decision_and_orchestration"] = {
        "decision_and_orchestration_artefacts": [p4_ev.to_dict()]
    }
    return state


def _write_datcon_csv(path: Path, rows: list[list[str]]) -> None:
    """Write a DatCon-style CSV with GPS, clock, and key sensor columns."""
    header = [
        "Clock:Tick#", "Clock:offsetTime",
        "GPS:Date", "GPS:Time", "GPS:dateTimeStamp",
        "GPS:Lat", "GPS:Long", "GPS:numSV", "GPS:hDOP",
        "IMUCalcs(0):height:C", "Controller:motor_state",
        "eventLog",
    ]
    with path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(header)
        w.writerows(rows)


def _write_flight_record_csv(path: Path, rows: list[list[str]]) -> None:
    """Write a FlightRecord-style CSV with all columns used by P5 checks."""
    header = [
        "CUSTOM.updateTime", "OSD.latitude", "OSD.longitude", "OSD.height [m]",
        "OSD.gpsNum", "OSD.compassError", "OSD.battery", "OSD.isMotorUp",
        "CENTER_BATTERY.relativeCapacity",
        "CENTER_BATTERY.voltageCell1 [V]", "CENTER_BATTERY.voltageCell2 [V]",
        "CENTER_BATTERY.voltageCell3 [V]", "CENTER_BATTERY.voltageCell4 [V]",
        "CENTER_BATTERY.temperature [C]",
    ]
    with path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(header)
        w.writerows(rows)


# Helper unit tests

def test_parse_datcon_date_valid() -> None:
    assert parse_datcon_date("20180419") == "2018-04-19"


def test_parse_datcon_date_invalid() -> None:
    assert parse_datcon_date("") is None
    assert parse_datcon_date("2018") is None
    assert parse_datcon_date("abcdefgh") is None


def test_parse_datcon_time_valid() -> None:
    assert parse_datcon_time("172449") == "17:24:49"
    assert parse_datcon_time("172449.123") == "17:24:49.123"


def test_parse_datcon_time_invalid() -> None:
    assert parse_datcon_time("") is None
    assert parse_datcon_time("1724") is None


def test_haversine_m_same_point() -> None:
    assert haversine_m(0.0, 0.0, 0.0, 0.0) == 0.0


def test_haversine_m_known_distance() -> None:
    d = haversine_m(0.0, 0.0, 1.0, 0.0)
    assert 110_000 < d < 112_000


def test_parse_iso_timestamp_z_suffix() -> None:
    assert parse_iso_timestamp("2018-04-19T17:24:49Z") == "2018-04-19T17:24:49+00:00"


def test_parse_iso_timestamp_offset() -> None:
    assert parse_iso_timestamp("2018-04-19T17:24:49+02:00") == "2018-04-19T17:24:49+02:00"


def test_parse_iso_timestamp_invalid() -> None:
    assert parse_iso_timestamp("") is None
    assert parse_iso_timestamp("not-a-date") is None


def test_parse_flightrecord_timestamp_with_ms() -> None:
    assert parse_flightrecord_timestamp("2018/04/19 17:25:11.078") == "2018-04-19T17:25:11.078000+00:00"


def test_parse_flightrecord_timestamp_no_ms() -> None:
    assert parse_flightrecord_timestamp("2018/04/19 17:25:11") == "2018-04-19T17:25:11+00:00"


def test_parse_flightrecord_timestamp_invalid() -> None:
    assert parse_flightrecord_timestamp("") is None
    assert parse_flightrecord_timestamp("not-a-date") is None


# Phase 5 integration tests — DatCon

def _datcon_row(
    tick: str = "0",
    offset: str = "0.0",
    date: str = "20180419",
    time: str = "172449",
    dts: str = "2018-04-19T17:24:49Z",
    lat: str = "39.9612830",
    lon: str = "-106.2165130",
    numsv: str = "10",
    hdop: str = "1.2",
    height: str = "5.0",
    motor: str = "1",
    event: str = "",
) -> list[str]:
    return [tick, offset, date, time, dts, lat, lon, numsv, hdop, height, motor, event]


def test_datcon_norm_columns(tmp_path: Path, monkeypatch) -> None:
    """DatCon CSV gets [NORM]:ID, date/time, and dateTimeStamp NORM columns at correct positions."""
    project_root = tmp_path
    (project_root / "Documents").mkdir(parents=True)
    monkeypatch.setattr(Path, "home", lambda: project_root)

    p4_csv = tmp_path / "FLY029.csv"
    _write_datcon_csv(p4_csv, [
        _datcon_row(offset="0.0", dts="2018-04-19T17:24:49Z"),
        _datcon_row(tick="1", offset="1.0", dts="2018-04-19T17:24:50Z",
                    lat="39.9612840", lon="-106.2165120"),
    ])

    state = _build_state(
        tmp_path, config.IDENTIFICATION_CONTROLLER_IOS,
        p4_csv, config.ACQUISITION_DATCON, config.DRONE_LOGS,
    )
    result = p5.run_phase_5(state)

    artefacts = result.phase_outputs[p5._PHASE_NAME]["normalised_artefacts"]
    assert len(artefacts) == 1
    norm_path = Path(artefacts[0]["stored_path"])
    assert norm_path.exists()
    assert norm_path.name.startswith("norm_")

    with norm_path.open(newline="", encoding="utf-8") as fh:
        reader = csv.reader(fh)
        header = next(reader)
        rows = list(reader)

    assert header[0] == "[NORM]:ID"
    assert "[NORM]:GPS:Date" in header
    assert "[NORM]:GPS:Time" in header
    assert "[NORM]:GPS:dateTimeStamp" in header

    date_norm_idx = header.index("[NORM]:GPS:Date")
    time_norm_idx = header.index("[NORM]:GPS:Time")
    gps_date_idx = header.index("GPS:Date")
    gps_time_idx = header.index("GPS:Time")
    dts_idx = header.index("GPS:dateTimeStamp")
    dts_norm_idx = header.index("[NORM]:GPS:dateTimeStamp")

    assert date_norm_idx == gps_date_idx + 1
    assert time_norm_idx == gps_time_idx + 1
    assert dts_norm_idx == dts_idx + 1

    assert rows[0][0] == "0"
    assert rows[1][0] == "1"
    assert rows[0][date_norm_idx] == "2018-04-19"
    assert rows[0][time_norm_idx] == "17:24:49"
    assert rows[0][dts_norm_idx] == "2018-04-19T17:24:49+00:00"


def test_datcon_coordinate_jump_anomaly(tmp_path: Path, monkeypatch) -> None:
    """Two GPS rows 1000 km apart in 1 second → coordinate_jump contains those row IDs."""
    project_root = tmp_path
    (project_root / "Documents").mkdir(parents=True)
    monkeypatch.setattr(Path, "home", lambda: project_root)

    p4_csv = tmp_path / "FLY_speed.csv"
    _write_datcon_csv(p4_csv, [
        _datcon_row(offset="0.0", dts="2018-04-19T12:00:00Z", lat="1.0", lon="0.0"),
        _datcon_row(tick="1", offset="1.0", dts="2018-04-19T12:00:01Z", lat="10.0", lon="0.0"),
    ])

    state = _build_state(
        tmp_path, config.IDENTIFICATION_CONTROLLER_IOS,
        p4_csv, config.ACQUISITION_DATCON, config.DRONE_LOGS,
    )
    result = p5.run_phase_5(state)

    anomalies = result.phase_outputs[p5._PHASE_NAME]["derived_anomalies"]
    assert anomalies
    obs = anomalies[0]["observations"][0]
    assert 1 in obs["coordinate_jump"]


def test_datcon_zero_coord_anomaly(tmp_path: Path, monkeypatch) -> None:
    """Row with GPS:Lat=0, GPS:Long=0 → zero_coordinate contains that row ID."""
    project_root = tmp_path
    (project_root / "Documents").mkdir(parents=True)
    monkeypatch.setattr(Path, "home", lambda: project_root)

    p4_csv = tmp_path / "FLY_zero.csv"
    _write_datcon_csv(p4_csv, [
        _datcon_row(offset="0.0", lat="0.0", lon="0.0"),
        _datcon_row(tick="1", offset="1.0", lat="39.961", lon="-106.216"),
    ])

    state = _build_state(
        tmp_path, config.IDENTIFICATION_CONTROLLER_IOS,
        p4_csv, config.ACQUISITION_DATCON, config.DRONE_LOGS,
    )
    result = p5.run_phase_5(state)

    obs = result.phase_outputs[p5._PHASE_NAME]["derived_anomalies"][0]["observations"][0]
    assert 0 in obs["zero_coordinate"]


def test_datcon_timestamp_regression(tmp_path: Path, monkeypatch) -> None:
    """Clock:offsetTime decreasing between rows → timestamp_regression contains row_id 1."""
    project_root = tmp_path
    (project_root / "Documents").mkdir(parents=True)
    monkeypatch.setattr(Path, "home", lambda: project_root)

    p4_csv = tmp_path / "FLY_regression.csv"
    _write_datcon_csv(p4_csv, [
        _datcon_row(offset="1.0"),
        _datcon_row(tick="1", offset="0.5"),  # goes backward
    ])

    state = _build_state(
        tmp_path, config.IDENTIFICATION_CONTROLLER_IOS,
        p4_csv, config.ACQUISITION_DATCON, config.DRONE_LOGS,
    )
    result = p5.run_phase_5(state)

    obs = result.phase_outputs[p5._PHASE_NAME]["derived_anomalies"][0]["observations"][0]
    assert 1 in obs["timestamp_regression"]


def test_datcon_altitude_negative(tmp_path: Path, monkeypatch) -> None:
    """Relative height below -2 m → altitude_negative contains that row_id."""
    project_root = tmp_path
    (project_root / "Documents").mkdir(parents=True)
    monkeypatch.setattr(Path, "home", lambda: project_root)

    p4_csv = tmp_path / "FLY_alt.csv"
    _write_datcon_csv(p4_csv, [
        _datcon_row(offset="0.0", height="-5.0"),
        _datcon_row(tick="1", offset="1.0", height="5.0"),
    ])

    state = _build_state(
        tmp_path, config.IDENTIFICATION_CONTROLLER_IOS,
        p4_csv, config.ACQUISITION_DATCON, config.DRONE_LOGS,
    )
    result = p5.run_phase_5(state)

    obs = result.phase_outputs[p5._PHASE_NAME]["derived_anomalies"][0]["observations"][0]
    assert 0 in obs["altitude_negative"]


# Phase 5 integration tests — FlightRecord

def _fr_row(
    time: str = "2018/04/19 17:25:11.078",
    lat: str = "39.961",
    lon: str = "-106.216",
    height: str = "5.0",
    numsv: str = "10",
    compass_err: str = "False",
    batt_osd: str = "0",
    motor: str = "True",
    batt_cap: str = "80",
    cell1: str = "3.9",
    cell2: str = "3.9",
    cell3: str = "3.9",
    cell4: str = "3.9",
    temp: str = "25.0",
) -> list[str]:
    return [time, lat, lon, height, numsv, compass_err, batt_osd, motor,
            batt_cap, cell1, cell2, cell3, cell4, temp]


def test_flight_record_norm_columns(tmp_path: Path, monkeypatch) -> None:
    """FlightRecord CSV gets [NORM]:ID and [NORM]:CUSTOM.updateTime; no GPS date/time columns."""
    project_root = tmp_path
    (project_root / "Documents").mkdir(parents=True)
    monkeypatch.setattr(Path, "home", lambda: project_root)

    p4_csv = tmp_path / "DJIFlightRecord.csv"
    _write_flight_record_csv(p4_csv, [_fr_row()])

    state = _build_state(
        tmp_path, config.IDENTIFICATION_CONTROLLER_ANDROID,
        p4_csv, config.ACQUISITION_TXTLOGTOCSV, config.FLIGHT_RECORDS,
    )
    result = p5.run_phase_5(state)

    artefacts = result.phase_outputs[p5._PHASE_NAME]["normalised_artefacts"]
    assert len(artefacts) == 1
    norm_path = Path(artefacts[0]["stored_path"])

    with norm_path.open(newline="", encoding="utf-8") as fh:
        reader = csv.reader(fh)
        header = next(reader)
        data_rows = list(reader)

    assert header[0] == "[NORM]:ID"
    assert "[NORM]:CUSTOM.updateTime" in header
    assert "[NORM]:GPS:Date" not in header
    assert "[NORM]:GPS:Time" not in header

    time_idx = header.index("CUSTOM.updateTime")
    norm_time_idx = header.index("[NORM]:CUSTOM.updateTime")
    assert norm_time_idx == time_idx + 1

    assert data_rows[0][0] == "0"
    assert data_rows[0][1] == "2018/04/19 17:25:11.078"
    assert data_rows[0][norm_time_idx] == "2018-04-19T17:25:11.078000+00:00"


def test_flight_record_motor_on_empty_battery(tmp_path: Path, monkeypatch) -> None:
    """OSD.isMotorUp=True and CENTER_BATTERY.relativeCapacity=0 → motor_on_empty_battery flagged."""
    project_root = tmp_path
    (project_root / "Documents").mkdir(parents=True)
    monkeypatch.setattr(Path, "home", lambda: project_root)

    p4_csv = tmp_path / "DJIFlightRecord_batt.csv"
    _write_flight_record_csv(p4_csv, [
        _fr_row(motor="True", batt_cap="0"),
        _fr_row(time="2018/04/19 17:25:12.078", motor="True", batt_cap="80"),
    ])

    state = _build_state(
        tmp_path, config.IDENTIFICATION_CONTROLLER_ANDROID,
        p4_csv, config.ACQUISITION_TXTLOGTOCSV, config.FLIGHT_RECORDS,
    )
    result = p5.run_phase_5(state)

    obs = result.phase_outputs[p5._PHASE_NAME]["derived_anomalies"][0]["observations"][0]
    assert 0 in obs["motor_on_empty_battery"]
    assert 1 not in obs.get("motor_on_empty_battery", [])


def test_flight_record_battery_cell_voltage_out_of_range(tmp_path: Path, monkeypatch) -> None:
    """Cell voltage below 2.8 V → battery_cell_voltage_out_of_range contains that row_id."""
    project_root = tmp_path
    (project_root / "Documents").mkdir(parents=True)
    monkeypatch.setattr(Path, "home", lambda: project_root)

    p4_csv = tmp_path / "DJIFlightRecord_cell.csv"
    _write_flight_record_csv(p4_csv, [
        _fr_row(cell1="2.0"),  # < 2.8 V → anomaly
        _fr_row(time="2018/04/19 17:25:12.078", cell1="3.9"),  # normal
    ])

    state = _build_state(
        tmp_path, config.IDENTIFICATION_CONTROLLER_ANDROID,
        p4_csv, config.ACQUISITION_TXTLOGTOCSV, config.FLIGHT_RECORDS,
    )
    result = p5.run_phase_5(state)

    obs = result.phase_outputs[p5._PHASE_NAME]["derived_anomalies"][0]["observations"][0]
    assert 0 in obs["battery_cell_voltage_out_of_range"]
    assert 1 not in obs.get("battery_cell_voltage_out_of_range", [])


# Phase 5 integration tests — EXIF

def test_exif_anomaly_observation(tmp_path: Path, monkeypatch) -> None:
    """EXIF JSON with zero date and no GPS → Observation with exif_contains_no_norm_time and exif_contains_no_gps.

    norm_date/norm_time must be absent (zero date → omit).
    evidence_sha256 must be the parent (original media) sha256, not the JSON sha256.
    """
    project_root = tmp_path
    (project_root / "Documents").mkdir(parents=True)
    monkeypatch.setattr(Path, "home", lambda: project_root)

    exif_json = tmp_path / "DJI_0001_exif.json"
    exif_json.write_text(
        json.dumps([{
            "SourceFile": str(exif_json),
            "File": {"FileName": "DJI_0001.MP4", "MIMEType": "video/mp4"},
            "QuickTime": {"CreateDate": "0000:00:00 00:00:00"},
        }]),
        encoding="utf-8",
    )

    state = _build_state(
        tmp_path, config.IDENTIFICATION_DRONE_SD,
        exif_json, config.ACQUISITION_EXIFTOOL, config.VIDEOS,
    )
    result = p5.run_phase_5(state)

    anomalies = result.phase_outputs[p5._PHASE_NAME]["derived_anomalies"]
    assert len(anomalies) == 1
    anomaly = anomalies[0]
    obs = anomaly["observations"][0]
    assert obs["exif_contains_no_norm_time"] is True
    assert obs["exif_contains_no_gps"] is True
    assert "norm_date" not in obs
    assert "norm_time" not in obs
    parent_sha = result.phase_outputs["p3_artefact_extraction"]["extracted_artefacts"][0]["sha256"]
    assert anomaly["evidence_sha256"] == parent_sha

    assert result.phase_outputs[p5._PHASE_NAME]["normalised_artefacts"] == []


def test_exif_valid_date_normalised(tmp_path: Path, monkeypatch) -> None:
    """EXIF JSON with valid CreateDate + offset → Observation has norm_date + norm_time; no anomaly flags."""
    project_root = tmp_path
    (project_root / "Documents").mkdir(parents=True)
    monkeypatch.setattr(Path, "home", lambda: project_root)

    exif_json = tmp_path / "DJI_0002_exif.json"
    exif_json.write_text(
        json.dumps([{
            "SourceFile": str(exif_json),
            "File": {"FileName": "DJI_0002.MP4", "MIMEType": "video/mp4"},
            "QuickTime": {"CreateDate": "2018:04:19 17:24:49", "OffsetTimeDigitized": "+00:00"},
            "Track1": {"GPSCoordinates": "39.961 -106.216 2380.0"},
        }]),
        encoding="utf-8",
    )

    state = _build_state(
        tmp_path, config.IDENTIFICATION_DRONE_SD,
        exif_json, config.ACQUISITION_EXIFTOOL, config.VIDEOS,
    )
    result = p5.run_phase_5(state)

    anomalies = result.phase_outputs[p5._PHASE_NAME]["derived_anomalies"]
    assert len(anomalies) == 1
    anomaly = anomalies[0]
    obs = anomaly["observations"][0]
    assert obs["norm_date"] == "2018-04-19"
    assert obs["norm_time"] == "17:24:49+00:00"
    assert obs["gps_latitude"] == 39.961
    assert obs["gps_longitude"] == -106.216
    assert "exif_contains_no_norm_time" not in obs
    assert "exif_contains_no_gps" not in obs
    parent_sha = result.phase_outputs["p3_artefact_extraction"]["extracted_artefacts"][0]["sha256"]
    assert anomaly["evidence_sha256"] == parent_sha


def test_exif_no_offset_no_norm_time(tmp_path: Path, monkeypatch) -> None:
    """EXIF JSON with valid CreateDate but no offset → no norm_date/norm_time; exif_contains_no_norm_time flagged."""
    project_root = tmp_path
    (project_root / "Documents").mkdir(parents=True)
    monkeypatch.setattr(Path, "home", lambda: project_root)

    exif_json = tmp_path / "DJI_0003_exif.json"
    exif_json.write_text(
        json.dumps([{
            "SourceFile": str(exif_json),
            "File": {"FileName": "DJI_0003.MP4", "MIMEType": "video/mp4"},
            "QuickTime": {"CreateDate": "2018:04:19 17:24:49"},
            "Track1": {"GPSCoordinates": "39.961 -106.216 2380.0"},
        }]),
        encoding="utf-8",
    )

    state = _build_state(
        tmp_path, config.IDENTIFICATION_DRONE_SD,
        exif_json, config.ACQUISITION_EXIFTOOL, config.VIDEOS,
    )
    result = p5.run_phase_5(state)

    anomalies = result.phase_outputs[p5._PHASE_NAME]["derived_anomalies"]
    assert len(anomalies) == 1
    obs = anomalies[0]["observations"][0]
    assert obs["exif_contains_no_norm_time"] is True
    assert "exif_contains_no_gps" not in obs
    assert "norm_date" not in obs
    assert "norm_time" not in obs
    assert obs["gps_latitude"] == 39.961


# Phase 5 infrastructure tests

def test_missing_p4_artefact(tmp_path: Path, monkeypatch) -> None:
    """P4 artefact listed in state but file missing → anomaly flagged, phase still completes."""
    project_root = tmp_path
    (project_root / "Documents").mkdir(parents=True)
    monkeypatch.setattr(Path, "home", lambda: project_root)

    missing_csv = tmp_path / "ghost.csv"
    missing_csv.write_text("temp", encoding="utf-8")

    state = _build_state(
        tmp_path, config.IDENTIFICATION_CONTROLLER_IOS,
        missing_csv, config.ACQUISITION_DATCON, config.DRONE_LOGS,
    )
    missing_csv.unlink()
    result = p5.run_phase_5(state)

    assert p5._PHASE_NAME in result.completed_phases
    assert any("ghost.csv" in flag for flag in result.anomaly_flags)
    assert result.phase_outputs[p5._PHASE_NAME]["normalised_artefacts"] == []


def test_no_empty_output_dirs(tmp_path: Path, monkeypatch) -> None:
    """Source with only EXIF artefacts produces no output subdirectory."""
    project_root = tmp_path
    (project_root / "Documents").mkdir(parents=True)
    monkeypatch.setattr(Path, "home", lambda: project_root)

    exif_json = tmp_path / "DJI_0001_exif.json"
    exif_json.write_text(
        json.dumps([{
            "SourceFile": str(exif_json),
            "File": {"FileName": "DJI_0001.MP4", "MIMEType": "video/mp4"},
            "QuickTime": {"CreateDate": "2018:04:19 17:24:49"},
            "Track1": {"GPSCoordinates": "39.96 -106.21 2380.0"},
        }]),
        encoding="utf-8",
    )

    state = _build_state(
        tmp_path, config.IDENTIFICATION_DRONE_SD,
        exif_json, config.ACQUISITION_EXIFTOOL, config.VIDEOS,
    )
    result = p5.run_phase_5(state)

    phase_dir = project_root / "Documents" / "dfdof_output" / "CASE-P5-TEST" / p5._PHASE_NAME
    subdirs = [d for d in phase_dir.iterdir() if d.is_dir()] if phase_dir.exists() else []
    assert subdirs == []


# Database empty-row anomaly check

import sqlite3 as _sqlite3


def _build_state_db(tmp_path: Path, identification: str, db_path: Path) -> State:
    """Build a minimal State with a P1→P3 chain for one database artefact."""
    state = State(case_id="CASE-P5-TEST", operator="Tester")

    src = tmp_path / "source.zip"
    if not src.exists():
        src.write_text("src", encoding="utf-8")
    source_ev = make_evidence(
        source_path=str(src),
        stored_path=src,
        parent=None,
        acquisition_method=config.ACQUISITION_LOGICAL,
        type=config.EVIDENCE_TYPE_INPUT,
        source_identification=identification,
    )
    state.input_evidence.append(source_ev)

    p3_ev = make_evidence(
        source_path=db_path.name,
        stored_path=db_path,
        parent=source_ev,
        acquisition_method=config.ACQUISITION_EXTRACT_LOGICAL,
        type=config.EVIDENCE_TYPE_EXTRACTED,
        artefact_category=config.DATABASES,
    )
    state.phase_outputs["p3_artefact_extraction"] = {
        "extracted_artefacts": [p3_ev.to_dict()]
    }
    state.phase_outputs["p4_decision_and_orchestration"] = {
        "decision_and_orchestration_artefacts": []
    }
    return state


def test_p5_database_empty_raises_observation(tmp_path: Path, monkeypatch) -> None:
    """SQLite DB with a table but zero rows → derived_anomalies contains database_empty observation."""
    (tmp_path / "Documents").mkdir(parents=True)
    monkeypatch.setattr(Path, "home", lambda: tmp_path)

    db_path = tmp_path / "dji.db"
    con = _sqlite3.connect(str(db_path))
    con.execute("CREATE TABLE flights (id INTEGER PRIMARY KEY, name TEXT)")
    con.commit()
    con.close()

    state = _build_state_db(tmp_path, config.IDENTIFICATION_CONTROLLER_IOS, db_path)
    result = p5.run_phase_5(state)

    anomalies = result.phase_outputs[p5._PHASE_NAME]["derived_anomalies"]
    assert len(anomalies) == 1
    assert anomalies[0]["evidence_category"] == config.DATABASES
    assert anomalies[0]["observations"][0]["database_empty"] is True


def test_p5_database_non_empty_no_observation(tmp_path: Path, monkeypatch) -> None:
    """SQLite DB with populated rows → no derived_anomaly."""
    (tmp_path / "Documents").mkdir(parents=True)
    monkeypatch.setattr(Path, "home", lambda: tmp_path)

    db_path = tmp_path / "dji.db"
    con = _sqlite3.connect(str(db_path))
    con.execute("CREATE TABLE flights (id INTEGER PRIMARY KEY, name TEXT)")
    con.execute("INSERT INTO flights VALUES (1, 'flight1')")
    con.commit()
    con.close()

    state = _build_state_db(tmp_path, config.IDENTIFICATION_CONTROLLER_IOS, db_path)
    result = p5.run_phase_5(state)

    anomalies = result.phase_outputs[p5._PHASE_NAME]["derived_anomalies"]
    assert anomalies == []


def test_p5_database_missing_file_raises_anomaly_flag(tmp_path: Path, monkeypatch) -> None:
    """P3 database artefact with missing file → anomaly flag raised, phase completes."""
    (tmp_path / "Documents").mkdir(parents=True)
    monkeypatch.setattr(Path, "home", lambda: tmp_path)

    db_path = tmp_path / "ghost.db"
    db_path.write_text("placeholder", encoding="utf-8")

    state = _build_state_db(tmp_path, config.IDENTIFICATION_CONTROLLER_IOS, db_path)
    db_path.unlink()

    result = p5.run_phase_5(state)

    assert p5._PHASE_NAME in result.completed_phases
    assert any("ghost.db" in flag for flag in result.anomaly_flags)
    assert result.phase_outputs[p5._PHASE_NAME]["derived_anomalies"] == []


# Flight log parsing — unit tests

def test_is_non_readable_binary() -> None:
    """File with high non-printable byte ratio → True."""
    import tempfile
    with tempfile.NamedTemporaryFile(suffix=".dat", delete=False) as fh:
        fh.write(bytes(range(256)) * 32)
        path = Path(fh.name)
    try:
        assert p5._is_non_readable(path) is True
    finally:
        path.unlink(missing_ok=True)


def test_is_non_readable_text(tmp_path: Path) -> None:
    """Plain ASCII text file → False."""
    log = tmp_path / "log.txt"
    log.write_text("2018-04-19 17:24:45 INFO starting\nFailed to connect\n", encoding="utf-8")
    assert p5._is_non_readable(log) is False


def test_parse_crash_dump_extracts_failed_with_timestamp() -> None:
    text = (
        "===== Crash =====\n"
        "java.lang.OutOfMemoryError: Failed to allocate memory\n"
        "\tat java.util.Arrays.copyOf(Arrays.java:3210)\n"
        "=======Thread info======\n"
        "Crash name:java.lang.OutOfMemoryError: Failed to allocate memory\n"
        " Cause is:null\n"
    )
    entries = p5._parse_crash_dump(text)
    assert len(entries) == 2
    assert entries[0]["type"] == "java_exception"
    assert entries[0]["exception"] == "java.lang.OutOfMemoryError"
    assert entries[0]["message"] == "Failed to allocate memory"
    assert entries[1]["type"] == "thread_crash"
    assert "OutOfMemoryError" in entries[1]["name"]


def test_parse_crash_dump_no_matches() -> None:
    text = "2018-04-19 17:24:45 INFO all good\n"
    assert p5._parse_crash_dump(text) == []


def test_parse_bracketed_log_single() -> None:
    text = "[2018-04-19 17:24:45, some diagnostic message]"
    entries = p5._parse_bracketed_log(text)
    assert len(entries) == 1
    assert entries[0]["timestamp"] == "2018-04-19 17:24:45"
    assert entries[0]["message"] == "some diagnostic message"


def test_parse_bracketed_log_multiple() -> None:
    text = "[2018-04-19 17:24:45, msg one][2018-04-19 17:25:00, msg two]"
    entries = p5._parse_bracketed_log(text)
    assert len(entries) == 2
    assert entries[1]["message"] == "msg two"


def test_classify_flight_log_crash() -> None:
    text = "===== Crash =====\njava.lang.RuntimeException: Failed to arm motors\n"
    fmt, entries = p5._classify_flight_log(text)
    assert fmt == "crash_dump"
    assert len(entries) == 1
    assert entries[0]["type"] == "java_exception"


def test_classify_flight_log_bracketed() -> None:
    text = "[2018-04-19 17:24:45, signal lost]"
    fmt, entries = p5._classify_flight_log(text)
    assert fmt == "bracketed_log"
    assert len(entries) == 1


def test_classify_flight_log_unknown() -> None:
    text = "some plain text with no special format"
    fmt, entries = p5._classify_flight_log(text)
    assert fmt == "unknown"
    assert entries == []


def test_parse_json_array_log_basic() -> None:
    text = '[["2018-04-19 11:25:15","","Home Point Recorded."]]'
    entries = p5._parse_json_array_log(text)
    assert len(entries) == 1
    assert entries[0]["timestamp"] == "2018-04-19 11:25:15"
    assert entries[0]["message"] == "Home Point Recorded."


def test_parse_json_array_log_with_level() -> None:
    text = '[["2018-04-19 11:26:34","Warning","Low battery warning"]]'
    entries = p5._parse_json_array_log(text)
    assert len(entries) == 1
    assert entries[0]["timestamp"] == "2018-04-19 11:26:34"
    assert entries[0]["message"] == "[Warning] Low battery warning"


def test_parse_json_array_log_multiple() -> None:
    text = (
        '[["2018-04-19 11:25:15","","Home Point Recorded."]],'
        '[["2018-04-19 11:26:00","","Taking off"]],'
        '[["2018-04-19 11:26:34","Warning","Low battery warning"]]'
    )
    entries = p5._parse_json_array_log(text)
    assert len(entries) == 3
    assert entries[0]["timestamp"] == "2018-04-19 11:25:15"
    assert entries[2]["message"] == "[Warning] Low battery warning"


def test_classify_flight_log_json_array() -> None:
    text = '[["2018-04-19 11:25:15","","Home Point Recorded."]],[["2018-04-19 11:26:34","Warning","msg"]]'
    fmt, entries = p5._classify_flight_log(text)
    assert fmt == "json_array_log"
    assert len(entries) == 2


def test_classify_flight_log_bracketed_not_affected_by_json_array() -> None:
    text = "[2018-04-19 17:24:45, signal lost]"
    fmt, entries = p5._classify_flight_log(text)
    assert fmt == "bracketed_log"
    assert entries[0]["timestamp"] == "2018-04-19 17:24:45"
    assert entries[0]["message"] == "signal lost"


# Flight log parsing — integration tests (run_phase_5)

def _build_state_fl(tmp_path: Path, identification: str, log_path: Path) -> State:
    """Build a minimal State with a P1→P3 chain for one flight_log artefact (no P4)."""
    state = State(case_id="CASE-P5-FL", operator="Tester")

    src = tmp_path / "source_fl.zip"
    if not src.exists():
        src.write_text("src", encoding="utf-8")
    source_ev = make_evidence(
        source_path=str(src),
        stored_path=src,
        parent=None,
        acquisition_method=config.ACQUISITION_LOGICAL,
        type=config.EVIDENCE_TYPE_INPUT,
        source_identification=identification,
    )
    state.input_evidence.append(source_ev)

    p3_ev = make_evidence(
        source_path=log_path.name,
        stored_path=log_path,
        parent=source_ev,
        acquisition_method=config.ACQUISITION_EXTRACT_LOGICAL,
        type=config.EVIDENCE_TYPE_EXTRACTED,
        artefact_category=config.FLIGHT_LOGS,
    )
    state.phase_outputs["p3_artefact_extraction"] = {
        "extracted_artefacts": [p3_ev.to_dict()]
    }
    state.phase_outputs["p4_decision_and_orchestration"] = {
        "decision_and_orchestration_artefacts": []
    }
    return state


def test_run_phase_5_flight_log_non_readable(tmp_path: Path, monkeypatch) -> None:
    """Binary flight log → observation with non_readable: True."""
    (tmp_path / "Documents").mkdir(parents=True)
    monkeypatch.setattr(Path, "home", lambda: tmp_path)

    log = tmp_path / "encoded.dat"
    log.write_bytes(bytes(range(256)) * 32)

    state = _build_state_fl(tmp_path, config.IDENTIFICATION_CONTROLLER_ANDROID, log)
    result = p5.run_phase_5(state)

    anomalies = result.phase_outputs[p5._PHASE_NAME]["derived_anomalies"]
    assert len(anomalies) == 1
    obs = anomalies[0]["observations"][0]
    assert obs == {"non_readable": True}
    assert anomalies[0]["evidence_category"] == config.FLIGHT_LOGS


def test_run_phase_5_flight_log_crash_dump(tmp_path: Path, monkeypatch) -> None:
    """Crash dump log → observation with format=crash_dump and entries."""
    (tmp_path / "Documents").mkdir(parents=True)
    monkeypatch.setattr(Path, "home", lambda: tmp_path)

    log = tmp_path / "crash.txt"
    log.write_text(
        "===== Crash =====\njava.lang.RuntimeException: Failed to initialise GPS\n",
        encoding="utf-8",
    )

    state = _build_state_fl(tmp_path, config.IDENTIFICATION_CONTROLLER_ANDROID, log)
    result = p5.run_phase_5(state)

    anomalies = result.phase_outputs[p5._PHASE_NAME]["derived_anomalies"]
    assert len(anomalies) == 1
    obs = anomalies[0]["observations"][0]
    assert obs["format"] == "crash_dump"
    assert len(obs["entries"]) == 1
    assert obs["entries"][0]["type"] == "java_exception"
    assert obs["entries"][0]["message"] == "Failed to initialise GPS"


def test_run_phase_5_flight_log_bracketed(tmp_path: Path, monkeypatch) -> None:
    """Bracketed log → observation with format=bracketed_log and entries."""
    (tmp_path / "Documents").mkdir(parents=True)
    monkeypatch.setattr(Path, "home", lambda: tmp_path)

    log = tmp_path / "maplog.txt"
    log.write_text(
        "[2018-04-19 17:24:45, route calculated][2018-04-19 17:25:00, waypoint reached]",
        encoding="utf-8",
    )

    state = _build_state_fl(tmp_path, config.IDENTIFICATION_CONTROLLER_ANDROID, log)
    result = p5.run_phase_5(state)

    anomalies = result.phase_outputs[p5._PHASE_NAME]["derived_anomalies"]
    assert len(anomalies) == 1
    obs = anomalies[0]["observations"][0]
    assert obs["format"] == "bracketed_log"
    assert len(obs["entries"]) == 2
    assert obs["entries"][0]["timestamp"] == "2018-04-19 17:24:45"


# _build_identification_map — ExtractDJI intermediate chain


def test_build_identification_map_extractdji_intermediate(tmp_path: Path) -> None:
    """DatCon CSV whose parent is an ExtractDJI output (P4) resolves to drone_flight_storage,
    not 'unknown'.  Regression test for the df050 ASSISTANT_EXPORT path where ExtractDJI
    sits between the P3 DAT and the DatCon CSV."""
    from phases.p5_normalisation_and_anomaly_checking import _build_identification_map

    state = State(case_id="CASE-P5-IDMAP", operator="Tester")

    # Input evidence — drone_flight_storage ZIP
    src = tmp_path / "flight_storage.zip"
    src.write_text("src", encoding="utf-8")
    input_ev = make_evidence(
        source_path=str(src),
        stored_path=src,
        parent=None,
        acquisition_method=config.ACQUISITION_LOGICAL,
        type=config.EVIDENCE_TYPE_INPUT,
        source_identification=config.IDENTIFICATION_DRONE_FLIGHT_STORAGE,
    )
    state.input_evidence.append(input_ev)

    # P3 artefact — raw DAT file extracted from the ZIP
    dat = tmp_path / "FLY005.DAT"
    dat.write_text("dat", encoding="utf-8")
    p3_ev = make_evidence(
        source_path=dat.name,
        stored_path=dat,
        parent=input_ev,
        acquisition_method=config.ACQUISITION_EXTRACT_LOGICAL,
        type=config.EVIDENCE_TYPE_EXTRACTED,
        artefact_category=config.DRONE_LOGS,
    )
    state.phase_outputs["p3_artefact_extraction"] = {
        "extracted_artefacts": [p3_ev.to_dict()]
    }

    # P4 ExtractDJI output — FLY*.DAT extracted from the raw DAT
    fly_dat = tmp_path / "FLY001.DAT"
    fly_dat.write_text("fly", encoding="utf-8")
    extractdji_ev = make_evidence(
        source_path=fly_dat.name,
        stored_path=fly_dat,
        parent=p3_ev,
        acquisition_method=config.ACQUISITION_EXTRACT_DJI,
        type=config.EVIDENCE_TYPE_EXTRACTED,
        artefact_category=config.DRONE_LOGS,
    )

    # P4 DatCon CSV — output from DatCon run on the ExtractDJI FLY*.DAT
    csv_file = tmp_path / "FLY001.csv"
    csv_file.write_text("csv", encoding="utf-8")
    datcon_ev = make_evidence(
        source_path=csv_file.name,
        stored_path=csv_file,
        parent=extractdji_ev,
        acquisition_method=config.ACQUISITION_DATCON,
        type=config.EVIDENCE_TYPE_DECODED,
        artefact_category=config.DRONE_LOGS,
    )

    state.phase_outputs["p4_decision_and_orchestration"] = {
        "decision_and_orchestration_artefacts": [
            extractdji_ev.to_dict(),
            datcon_ev.to_dict(),
        ]
    }

    id_map = _build_identification_map(state)

    # P3 DAT should map directly
    assert id_map[p3_ev.sha256] == config.IDENTIFICATION_DRONE_FLIGHT_STORAGE
    # ExtractDJI output (P4) should inherit the label from its P3 parent
    assert id_map[extractdji_ev.sha256] == config.IDENTIFICATION_DRONE_FLIGHT_STORAGE
    # DatCon CSV's parent_sha256 = extractdji_ev.sha256, so must also resolve correctly
    assert id_map[extractdji_ev.sha256] == config.IDENTIFICATION_DRONE_FLIGHT_STORAGE
    # The DatCon CSV's own SHA is not in the map (only its parent is looked up at line 1006)
    # but the key used for lookup at line 1006 is datcon_ev.parent_sha256 = extractdji_ev.sha256
    assert datcon_ev.parent_sha256 == extractdji_ev.sha256
    assert id_map.get(datcon_ev.parent_sha256) == config.IDENTIFICATION_DRONE_FLIGHT_STORAGE
