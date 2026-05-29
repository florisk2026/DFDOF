from __future__ import annotations

import csv
import json
from datetime import datetime, timezone
from pathlib import Path

import config
from evidence import make_evidence
from observation import make_observation
from phases import p6_multisource_correlation as p6
from state import State


# ---------------------------------------------------------------------------
# CSV writers
# ---------------------------------------------------------------------------

_NORM_DRONE_HEADER = [
    "[NORM]:ID",
    "[NORM]:GPS:dateTimeStamp",
    "GPS:Lat", "GPS:Long",
    "IMUCalcs(0):height:C",
    "Controller:motor_state:D",
    "GPS:numSV",
    "Clock:offsetTime",
    "Controller:ctrl_mode",
]

_NORM_FR_HEADER = [
    "[NORM]:ID",
    "[NORM]:CUSTOM.updateTime",
    "OSD.latitude", "OSD.longitude",
    "OSD.height [m]",
    "OSD.isMotorUp",
    "OSD.gpsNum",
    "CENTER_BATTERY.relativeCapacity",
    "OSD.flycState",
    "APP_WARN.warn",
    "APP_TIP.tip",
    "CAMERA_INFO.recordState",
    "CAMERA_INFO.photoState",
    "CAMERA_INFO.sdCardState",
]


def _write_norm_drone_csv(path: Path, rows: list[list[str]]) -> None:
    with path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(_NORM_DRONE_HEADER)
        w.writerows(rows)


def _write_norm_fr_csv(path: Path, rows: list[list[str]]) -> None:
    with path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(_NORM_FR_HEADER)
        w.writerows(rows)


def _drone_row(
    norm_id: str = "0",
    ts: str = "",
    lat: str = "39.9612",
    lon: str = "-106.2165",
    height: str = "5.0",
    motor: str = "1",
    numsv: str = "10",
    clock: str = "0.0",
    mode: str = "P-GPS",
) -> list[str]:
    return [norm_id, ts, lat, lon, height, motor, numsv, clock, mode]


def _fr_row(
    norm_id: str = "0",
    ts: str = "",
    lat: str = "39.9612",
    lon: str = "-106.2165",
    height: str = "5.0",
    motor: str = "TRUE",
    numsv: str = "10",
    batt: str = "80",
    mode: str = "AutoTakeoff",
    warn: str = "",
    tip: str = "",
    rec: str = "",
    photo: str = "",
    sd: str = "",
) -> list[str]:
    return [norm_id, ts, lat, lon, height, motor, numsv, batt, mode, warn, tip, rec, photo, sd]


# ---------------------------------------------------------------------------
# State builder
# ---------------------------------------------------------------------------

def _build_p6_state(
    tmp_path: Path,
    monkeypatch,
    fr_path: Path | None = None,
    fr_identification: str = config.IDENTIFICATION_CONTROLLER_IOS,
    drone_path: Path | None = None,
    drone_identification: str = config.IDENTIFICATION_DRONE_SD,
    fr_anomalies: dict | None = None,
    drone_anomalies: dict | None = None,
) -> State:
    """Build a State with P5 normalised artefacts for P6 testing."""
    project_root = tmp_path
    (project_root / "Documents").mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(Path, "home", lambda: project_root)

    state = State(case_id="CASE-P6-TEST", operator="Tester")
    normalised_artefacts = []
    derived_anomalies = []

    if fr_path is not None:
        src = tmp_path / "fr_src.zip"
        src.write_bytes(b"src")
        src_ev = make_evidence(
            source_path=str(src), stored_path=src, parent=None,
            acquisition_method=config.ACQUISITION_LOGICAL,
            type=config.EVIDENCE_TYPE_INPUT,
            source_identification=fr_identification,
        )
        p4_ev = make_evidence(
            source_path=str(fr_path), stored_path=fr_path, parent=src_ev,
            acquisition_method=config.ACQUISITION_TXTLOGTOCSV,
            type=config.EVIDENCE_TYPE_DECODED,
            artefact_category=config.FLIGHT_RECORDS,
        )
        norm_ev = make_evidence(
            source_path=str(fr_path), stored_path=fr_path, parent=p4_ev,
            acquisition_method=config.ACQUISITION_NORMALISE,
            type=config.EVIDENCE_TYPE_NORMALISED,
            artefact_category=config.FLIGHT_RECORDS,
        )
        normalised_artefacts.append(norm_ev.to_dict())
        if fr_anomalies:
            obs = make_observation(
                stored_path=str(fr_path),
                evidence_sha256=norm_ev.sha256,
                evidence_category=config.FLIGHT_RECORDS,
                acquisition_method=config.ACQUISITION_NORMALISE,
                observations=[fr_anomalies],
            )
            derived_anomalies.append(obs.to_dict())

    if drone_path is not None:
        src2 = tmp_path / "drone_src.dat"
        src2.write_bytes(b"src")
        src2_ev = make_evidence(
            source_path=str(src2), stored_path=src2, parent=None,
            acquisition_method=config.ACQUISITION_LOGICAL,
            type=config.EVIDENCE_TYPE_INPUT,
            source_identification=drone_identification,
        )
        p4_drone = make_evidence(
            source_path=str(drone_path), stored_path=drone_path, parent=src2_ev,
            acquisition_method=config.ACQUISITION_DATCON,
            type=config.EVIDENCE_TYPE_DECODED,
            artefact_category=config.DRONE_LOGS,
        )
        norm_drone = make_evidence(
            source_path=str(drone_path), stored_path=drone_path, parent=p4_drone,
            acquisition_method=config.ACQUISITION_NORMALISE,
            type=config.EVIDENCE_TYPE_NORMALISED,
            artefact_category=config.DRONE_LOGS,
        )
        normalised_artefacts.append(norm_drone.to_dict())
        if drone_anomalies:
            obs = make_observation(
                stored_path=str(drone_path),
                evidence_sha256=norm_drone.sha256,
                evidence_category=config.DRONE_LOGS,
                acquisition_method=config.ACQUISITION_NORMALISE,
                observations=[drone_anomalies],
            )
            derived_anomalies.append(obs.to_dict())

    state.phase_outputs["p5_normalisation_and_anomaly_checking"] = {
        "normalised_artefacts": normalised_artefacts,
        "derived_anomalies": derived_anomalies,
    }
    return state


def _overlapping_rows(
    n: int = 30,
    base_ts: str = "2018-04-19T11:25:00+00:00",
    interval_s: int = 3,
    lat: str = "39.9612",
    lon: str = "-106.2165",
) -> list[tuple[str, str, str]]:
    """Return (norm_id, ts, lat, lon) tuples for n rows at interval_s apart."""
    from datetime import timedelta
    base = datetime.fromisoformat(base_ts)
    result = []
    for i in range(n):
        dt = base + timedelta(seconds=i * interval_s)
        result.append((str(i), dt.isoformat(), lat, lon))
    return result


# ---------------------------------------------------------------------------
# Unit tests — helpers
# ---------------------------------------------------------------------------

def test_load_csv_rows_missing_file(tmp_path: Path) -> None:
    header, rows = p6._load_csv_rows(tmp_path / "nonexistent.csv")
    assert header == []
    assert rows == []


def test_load_csv_rows_valid(tmp_path: Path) -> None:
    csv_path = tmp_path / "test.csv"
    _write_norm_fr_csv(csv_path, [_fr_row(norm_id="0", ts="2018-04-19T11:25:00+00:00")])
    header, rows = p6._load_csv_rows(csv_path)
    assert header == _NORM_FR_HEADER
    assert len(rows) == 1
    assert rows[0]["[NORM]:ID"] == "0"


def test_get_ts_valid() -> None:
    row = {"[NORM]:GPS:dateTimeStamp": "2018-04-19T17:24:49+00:00"}
    dt = p6._get_ts(row, "[NORM]:GPS:dateTimeStamp")
    assert dt is not None
    assert dt.year == 2018 and dt.hour == 17
    assert dt.tzinfo is not None


def test_get_ts_empty() -> None:
    assert p6._get_ts({"[NORM]:GPS:dateTimeStamp": ""}, "[NORM]:GPS:dateTimeStamp") is None


def test_get_ts_missing_key() -> None:
    assert p6._get_ts({}, "[NORM]:GPS:dateTimeStamp") is None


def test_compute_overlap_full() -> None:
    utc = timezone.utc
    a = {"start_dt": datetime(2018, 4, 19, 11, 25, 0, tzinfo=utc),
         "end_dt":   datetime(2018, 4, 19, 11, 40, 0, tzinfo=utc)}
    b = {"start_dt": datetime(2018, 4, 19, 11, 25, 0, tzinfo=utc),
         "end_dt":   datetime(2018, 4, 19, 11, 40, 0, tzinfo=utc)}
    assert p6._compute_overlap(a, b) == 900.0


def test_compute_overlap_partial() -> None:
    utc = timezone.utc
    a = {"start_dt": datetime(2018, 4, 19, 11, 25, 0, tzinfo=utc),
         "end_dt":   datetime(2018, 4, 19, 11, 40, 0, tzinfo=utc)}
    b = {"start_dt": datetime(2018, 4, 19, 11, 30, 0, tzinfo=utc),
         "end_dt":   datetime(2018, 4, 19, 11, 45, 0, tzinfo=utc)}
    assert p6._compute_overlap(a, b) == 600.0


def test_compute_overlap_none() -> None:
    utc = timezone.utc
    a = {"start_dt": datetime(2018, 4, 19, 11, 0, 0, tzinfo=utc),
         "end_dt":   datetime(2018, 4, 19, 11, 10, 0, tzinfo=utc)}
    b = {"start_dt": datetime(2018, 4, 19, 12, 0, 0, tzinfo=utc),
         "end_dt":   datetime(2018, 4, 19, 12, 10, 0, tzinfo=utc)}
    assert p6._compute_overlap(a, b) == 0.0


def test_build_candidate_no_timestamps(tmp_path: Path) -> None:
    csv_path = tmp_path / "empty_ts.csv"
    _write_norm_fr_csv(csv_path, [_fr_row(ts="")])
    header, rows = p6._load_csv_rows(csv_path)
    assert p6._build_candidate({}, rows, p6._FR_TS_COL,
                                p6._FR_LAT_COL, p6._FR_LON_COL, header) is None


# ---------------------------------------------------------------------------
# Integration tests — run_phase_6
# ---------------------------------------------------------------------------

def test_no_p5_data(tmp_path: Path, monkeypatch) -> None:
    """Phase runs cleanly with empty P5 outputs and produces 0 flights."""
    project_root = tmp_path
    (project_root / "Documents").mkdir(parents=True)
    monkeypatch.setattr(Path, "home", lambda: project_root)

    state = State(case_id="CASE-P6-EMPTY", operator="Tester")
    state.phase_outputs["p5_normalisation_and_anomaly_checking"] = {
        "normalised_artefacts": [],
        "derived_anomalies": [],
    }
    result = p6.run_phase_6(state)

    out = result.phase_outputs[p6._PHASE_NAME]
    assert out["flight_count"] == 0
    assert out["flights"] == []
    assert p6._PHASE_NAME in result.completed_phases


def test_matched_flight_primary(tmp_path: Path, monkeypatch) -> None:
    """iOS FR + drone log with identical GPS and timestamps → 1 matched flight."""
    # Build 30 rows, 3s apart, same location → overlap 87s, median dist 0m.
    rows_data = _overlapping_rows(n=30, interval_s=3)

    fr_csv = tmp_path / "DJIFlightRecord.csv"
    _write_norm_fr_csv(fr_csv, [
        _fr_row(norm_id=r[0], ts=r[1], lat=r[2], lon=r[3])
        for r in rows_data
    ])

    drone_csv = tmp_path / "FLY029.csv"
    _write_norm_drone_csv(drone_csv, [
        _drone_row(norm_id=r[0], ts=r[1], lat=r[2], lon=r[3])
        for r in rows_data
    ])

    state = _build_p6_state(tmp_path, monkeypatch, fr_path=fr_csv, drone_path=drone_csv)
    result = p6.run_phase_6(state)

    out = result.phase_outputs[p6._PHASE_NAME]
    assert out["flight_count"] == 1

    flight = out["flights"][0]
    assert flight["correlation"]["matched"] is True
    assert flight["correlation"]["rule"] == "primary"
    assert flight["correlation"]["median_distance_m"] == 0.0
    shas = {g["evidence_sha256"] for g in flight["flights_identified"]}
    assert len(shas) == 2


def test_unmatched_fr_only(tmp_path: Path, monkeypatch) -> None:
    """FR with no drone log → 1 unmatched single-source flight."""
    rows_data = _overlapping_rows(n=30, interval_s=3)
    fr_csv = tmp_path / "DJIFlightRecord.csv"
    _write_norm_fr_csv(fr_csv, [
        _fr_row(norm_id=r[0], ts=r[1], lat=r[2], lon=r[3])
        for r in rows_data
    ])

    state = _build_p6_state(tmp_path, monkeypatch, fr_path=fr_csv)
    result = p6.run_phase_6(state)

    out = result.phase_outputs[p6._PHASE_NAME]
    assert out["flight_count"] == 1
    assert out["flights"][0]["correlation"] == {"matched": False}


def test_unmatched_drone_only(tmp_path: Path, monkeypatch) -> None:
    """Drone log with no FR → 1 unmatched single-source flight."""
    rows_data = _overlapping_rows(n=30, interval_s=3)
    drone_csv = tmp_path / "FLY029.csv"
    _write_norm_drone_csv(drone_csv, [
        _drone_row(norm_id=r[0], ts=r[1], lat=r[2], lon=r[3])
        for r in rows_data
    ])

    state = _build_p6_state(tmp_path, monkeypatch, drone_path=drone_csv)
    result = p6.run_phase_6(state)

    out = result.phase_outputs[p6._PHASE_NAME]
    assert out["flight_count"] == 1
    assert out["flights"][0]["correlation"] == {"matched": False}


def test_no_overlap_both_uncorrelated(tmp_path: Path, monkeypatch) -> None:
    """FR and drone log with no temporal overlap → both become unmatched flights."""
    # FR at T, drone at T+1h
    fr_rows = _overlapping_rows(n=30, base_ts="2018-04-19T11:00:00+00:00", interval_s=3)
    dr_rows = _overlapping_rows(n=30, base_ts="2018-04-19T12:00:00+00:00", interval_s=3)

    fr_csv = tmp_path / "fr.csv"
    dr_csv = tmp_path / "drone.csv"
    _write_norm_fr_csv(fr_csv, [_fr_row(norm_id=r[0], ts=r[1], lat=r[2], lon=r[3]) for r in fr_rows])
    _write_norm_drone_csv(dr_csv, [_drone_row(norm_id=r[0], ts=r[1], lat=r[2], lon=r[3]) for r in dr_rows])

    state = _build_p6_state(tmp_path, monkeypatch, fr_path=fr_csv, drone_path=dr_csv)
    result = p6.run_phase_6(state)

    out = result.phase_outputs[p6._PHASE_NAME]
    assert out["flight_count"] == 2
    assert all(not f["correlation"]["matched"] for f in out["flights"])


def test_timeline_json_written(tmp_path: Path, monkeypatch) -> None:
    """Per-flight timeline_flightXX.json is written with expected top-level keys."""
    rows_data = _overlapping_rows(n=30, interval_s=3)
    fr_csv = tmp_path / "fr.csv"
    _write_norm_fr_csv(fr_csv, [_fr_row(norm_id=r[0], ts=r[1]) for r in rows_data])

    state = _build_p6_state(tmp_path, monkeypatch, fr_path=fr_csv)
    result = p6.run_phase_6(state)

    out = result.phase_outputs[p6._PHASE_NAME]
    assert out["flight_count"] == 1
    timeline_path = Path(out["flights"][0]["stored_path"])
    assert timeline_path.exists()
    data = json.loads(timeline_path.read_text(encoding="utf-8"))
    assert "generated_at" in data
    assert "flight_id" in data
    assert "flights_identified" in data
    assert "events" in data


def test_make_event_schema_fields() -> None:
    """_make_event returns a dict with exactly the required schema fields."""
    ev = p6._make_event(
        timestamp="2018-04-19T11:25:00+00:00",
        timezone="UTC",
        source="controller_ios",
        source_pointer="row:5",
        event="motor_on",
        data={"motor_state": True},
        confidence="high",
    )
    required = {"timestamp", "timezone", "source", "source_pointer",
                "event", "data", "confidence"}
    assert required == set(ev.keys())


def test_completed_phases_updated(tmp_path: Path, monkeypatch) -> None:
    """_PHASE_NAME is added to state.completed_phases after run."""
    project_root = tmp_path
    (project_root / "Documents").mkdir(parents=True)
    monkeypatch.setattr(Path, "home", lambda: project_root)

    state = State(case_id="CASE-P6-PHASES", operator="Tester")
    state.phase_outputs["p5_normalisation_and_anomaly_checking"] = {
        "normalised_artefacts": [], "derived_anomalies": [],
    }
    result = p6.run_phase_6(state)
    assert p6._PHASE_NAME in result.completed_phases


def test_empty_csv_raises_anomaly(tmp_path: Path, monkeypatch) -> None:
    """An empty (header-only) FR CSV raises an anomaly and is skipped."""
    project_root = tmp_path
    (project_root / "Documents").mkdir(parents=True)
    monkeypatch.setattr(Path, "home", lambda: project_root)

    empty_csv = tmp_path / "empty_fr.csv"
    _write_norm_fr_csv(empty_csv, [])  # header only, no data rows

    src = tmp_path / "src.zip"
    src.write_bytes(b"src")
    src_ev = make_evidence(
        source_path=str(src), stored_path=src, parent=None,
        acquisition_method=config.ACQUISITION_LOGICAL,
        type=config.EVIDENCE_TYPE_INPUT,
        source_identification=config.IDENTIFICATION_CONTROLLER_IOS,
    )
    p4_ev = make_evidence(
        source_path=str(empty_csv), stored_path=empty_csv, parent=src_ev,
        acquisition_method=config.ACQUISITION_TXTLOGTOCSV,
        type=config.EVIDENCE_TYPE_DECODED, artefact_category=config.FLIGHT_RECORDS,
    )
    norm_ev = make_evidence(
        source_path=str(empty_csv), stored_path=empty_csv, parent=p4_ev,
        acquisition_method=config.ACQUISITION_NORMALISE,
        type=config.EVIDENCE_TYPE_NORMALISED, artefact_category=config.FLIGHT_RECORDS,
    )

    state = State(case_id="CASE-P6-EMPTY-CSV", operator="Tester")
    state.phase_outputs["p5_normalisation_and_anomaly_checking"] = {
        "normalised_artefacts": [norm_ev.to_dict()],
        "derived_anomalies": [],
    }
    result = p6.run_phase_6(state)

    assert result.phase_outputs[p6._PHASE_NAME]["flight_count"] == 0
    assert any("empty flight record" in flag for flag in result.anomaly_flags)


# ---------------------------------------------------------------------------
# Unit tests — new helpers
# ---------------------------------------------------------------------------

def test_ts_timezone_utc_offset() -> None:
    assert p6._ts_timezone("2018-04-19T11:25:00+00:00") == "UTC"


def test_ts_timezone_utc_z() -> None:
    assert p6._ts_timezone("2018-04-19T11:25:00Z") == "UTC"


def test_ts_timezone_no_offset() -> None:
    assert p6._ts_timezone("2018-04-19T11:25:00") == "unknown"


def test_ts_timezone_local_offset() -> None:
    assert p6._ts_timezone("2018-04-19T11:25:00+02:00") == "unknown"


def test_event_confidence_high() -> None:
    coord = {"latitude": 39.9, "longitude": -106.2, "altitude": 5.0}
    assert p6._event_confidence("2018-04-19T11:25:00+00:00", coord) == "high"


def test_event_confidence_medium_gps_no_utc() -> None:
    coord = {"latitude": 39.9, "longitude": -106.2, "altitude": 5.0}
    assert p6._event_confidence("2018-04-19T11:25:00", coord) == "medium"


def test_event_confidence_medium_utc_no_gps() -> None:
    coord = {"latitude": None, "longitude": None, "altitude": None}
    assert p6._event_confidence("2018-04-19T11:25:00+00:00", coord) == "medium"


def test_event_confidence_low() -> None:
    coord = {"latitude": None, "longitude": None, "altitude": None}
    assert p6._event_confidence("2018-04-19T11:25:00", coord) == "low"


def test_event_data_drone_extracts_columns() -> None:
    rows = [{"GPS:Lat": "39.9612", "GPS:Long": "-106.2165", "IMU_ATTI(0):alti:D": "5.3"}]
    c = p6._event_data_drone(rows, 0)
    assert c == {"latitude": 39.9612, "longitude": -106.2165, "altitude": 5.3}


def test_event_data_fr_extracts_columns() -> None:
    rows = [{"OSD.latitude": "39.9612", "OSD.longitude": "-106.2165", "OSD.altitude [m]": "8.1"}]
    c = p6._event_data_fr(rows, 0)
    assert c == {"latitude": 39.9612, "longitude": -106.2165, "altitude": 8.1}


# ---------------------------------------------------------------------------
# Unit tests — log-start extras helpers
# ---------------------------------------------------------------------------

def test_drone_log_start_extras_found() -> None:
    """ACType row is found and drone name extracted."""
    rows = [
        {"Attribute|Value": "Firmware Date| Jan 25 2018"},
        {"Attribute|Value": "ACType|MavicAir"},
        {"Attribute|Value": ""},
    ]
    result = p6._drone_log_start_extras(rows)
    assert result == {"name_drone": "MavicAir"}


def test_drone_log_start_extras_missing() -> None:
    """No ACType row → name_drone is None."""
    rows = [{"Attribute|Value": "Firmware Date| Jan 25 2018"}, {"Attribute|Value": ""}]
    result = p6._drone_log_start_extras(rows)
    assert result == {"name_drone": None}


def test_fr_log_start_extras_populated() -> None:
    """DETAILS fields extracted from first row containing values."""
    row = {
        "DETAILS.appType": "iOS",
        "DETAILS.appVersion": "4.2.12",
        "DETAILS.droneType": "Mavic Air",
        "DETAILS.aircraftSnBytes": "0K1DECE2BC0633",
        "DETAILS.batterySn": "0K4AEBQA3400DT",
        "DETAILS.rcSn": "0RKCECL0061D5R",
        "DETAILS.cameraSn": "0GNLEBJ018Z2YB",
    }
    result = p6._fr_log_start_extras([row])
    assert result["phone_os"] == "iOS"
    assert result["dji_app_version"] == "4.2.12"
    assert result["name_drone"] == "Mavic Air"
    assert result["serial_drone"] == "0K1DECE2BC0633"
    assert result["serial_battery"] == "0K4AEBQA3400DT"
    assert result["serial_controller"] == "0RKCECL0061D5R"
    assert result["serial_camera"] == "0GNLEBJ018Z2YB"


def test_fr_log_start_extras_empty() -> None:
    """All DETAILS columns empty → all values are None."""
    result = p6._fr_log_start_extras([{}])
    assert all(v is None for v in result.values())
    assert set(result.keys()) == {
        "phone_os", "dji_app_version", "name_drone",
        "serial_drone", "serial_battery", "serial_controller", "serial_camera",
    }


def test_fr_log_end_extras_present() -> None:
    """Both DETAILS fields populated → int photo count and float video duration."""
    rows = [{"DETAILS.photoNum": "3", "DETAILS.videoTime [s]": "45.5"}]
    result = p6._fr_log_end_extras(rows)
    assert result["number_photos_taken"] == 3
    assert isinstance(result["number_photos_taken"], int)
    assert result["duration_recording"] == 45.5


def test_fr_log_end_extras_absent() -> None:
    """No DETAILS.photoNum column → empty dict returned."""
    assert p6._fr_log_end_extras([{}]) == {}
    assert p6._fr_log_end_extras([]) == {}


def test_boundary_events_fr_log_ended_includes_photo_video(tmp_path: Path, monkeypatch) -> None:
    """Log ended event for a FlightRecord includes number_photos_taken and duration_recording."""
    rows_data = _overlapping_rows(n=5, interval_s=3)
    extended_header = _NORM_FR_HEADER + ["DETAILS.photoNum", "DETAILS.videoTime [s]"]
    fr_csv = tmp_path / "fr.csv"
    with fr_csv.open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(extended_header)
        for i, r in enumerate(rows_data):
            base = _fr_row(norm_id=r[0], ts=r[1])
            photo = "2" if i == len(rows_data) - 1 else ""
            video = "60" if i == len(rows_data) - 1 else ""
            w.writerow(base + [photo, video])

    state = _build_p6_state(tmp_path, monkeypatch, fr_path=fr_csv)
    result = p6.run_phase_6(state)

    tl_path = Path(result.phase_outputs[p6._PHASE_NAME]["flights"][0]["stored_path"])
    events = json.loads(tl_path.read_text(encoding="utf-8"))["events"]
    ended = next(e for e in events if e["event"] == "Log ended")
    assert ended["data"]["number_photos_taken"] == 2
    assert ended["data"]["duration_recording"] == 60.0


def test_boundary_events_fr_log_ended_osd_fields(tmp_path: Path, monkeypatch) -> None:
    """Log ended event includes ground_or_sky, height, and distance_to_homepoint."""
    extended_header = _NORM_FR_HEADER + ["OSD.groundOrSky", "OSD.height [m]", "CALC.distance [m]"]
    rows_data = _overlapping_rows(n=5, interval_s=3)
    fr_csv = tmp_path / "fr.csv"
    with fr_csv.open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(extended_header)
        for i, r in enumerate(rows_data):
            base = _fr_row(norm_id=r[0], ts=r[1])
            last = i == len(rows_data) - 1
            w.writerow(base + ["Ground" if last else "", "1.2" if last else "", "5.6" if last else ""])

    state = _build_p6_state(tmp_path, monkeypatch, fr_path=fr_csv)
    result = p6.run_phase_6(state)

    tl_path = Path(result.phase_outputs[p6._PHASE_NAME]["flights"][0]["stored_path"])
    events = json.loads(tl_path.read_text(encoding="utf-8"))["events"]
    ended = next(e for e in events if e["event"] == "Log ended")
    assert ended["data"]["ground_or_sky"] == "Ground"
    assert ended["data"]["height"] == 1.2
    assert ended["data"]["distance_to_homepoint"] == 5.6


def test_boundary_events_fr_log_ended_osd_fields_null_when_empty(tmp_path: Path, monkeypatch) -> None:
    """ground_or_sky and distance_to_homepoint are null when columns are absent from the CSV."""
    # Standard _fr_row / _NORM_FR_HEADER does not include OSD.groundOrSky or CALC.distance [m],
    # so those fields should come through as None; height is present but empty string → None.
    extended_header = _NORM_FR_HEADER + ["OSD.groundOrSky", "CALC.distance [m]"]
    rows_data = _overlapping_rows(n=3, interval_s=3)
    fr_csv = tmp_path / "fr.csv"
    with fr_csv.open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(extended_header)
        for r in rows_data:
            w.writerow(_fr_row(norm_id=r[0], ts=r[1], height="") + ["", ""])

    state = _build_p6_state(tmp_path, monkeypatch, fr_path=fr_csv)
    result = p6.run_phase_6(state)

    tl_path = Path(result.phase_outputs[p6._PHASE_NAME]["flights"][0]["stored_path"])
    events = json.loads(tl_path.read_text(encoding="utf-8"))["events"]
    ended = next(e for e in events if e["event"] == "Log ended")
    assert ended["data"]["ground_or_sky"] is None
    assert ended["data"]["height"] is None
    assert ended["data"]["distance_to_homepoint"] is None


# ---------------------------------------------------------------------------
# Integration tests — boundary events
# ---------------------------------------------------------------------------

def test_boundary_events_present(tmp_path: Path, monkeypatch) -> None:
    """Single FR candidate produces exactly 2 events: Log started + Log ended."""
    rows_data = _overlapping_rows(n=10, interval_s=3)
    fr_csv = tmp_path / "fr.csv"
    _write_norm_fr_csv(fr_csv, [_fr_row(norm_id=r[0], ts=r[1]) for r in rows_data])

    state = _build_p6_state(tmp_path, monkeypatch, fr_path=fr_csv)
    result = p6.run_phase_6(state)

    tl_path = Path(result.phase_outputs[p6._PHASE_NAME]["flights"][0]["stored_path"])
    events = json.loads(tl_path.read_text(encoding="utf-8"))["events"]

    event_labels = [e["event"] for e in events]
    assert "Log started" in event_labels
    assert "Log ended" in event_labels
    timestamps = [e["timestamp"] for e in events if e["timestamp"]]
    assert timestamps == sorted(timestamps)


def test_events_chronological(tmp_path: Path, monkeypatch) -> None:
    """FR + drone candidate → 4 events in chronological order."""
    rows_data = _overlapping_rows(n=30, interval_s=3)
    fr_csv = tmp_path / "fr.csv"
    drone_csv = tmp_path / "drone.csv"
    _write_norm_fr_csv(fr_csv, [_fr_row(norm_id=r[0], ts=r[1], lat=r[2], lon=r[3]) for r in rows_data])
    _write_norm_drone_csv(drone_csv, [_drone_row(norm_id=r[0], ts=r[1], lat=r[2], lon=r[3]) for r in rows_data])

    state = _build_p6_state(tmp_path, monkeypatch, fr_path=fr_csv, drone_path=drone_csv)
    result = p6.run_phase_6(state)

    tl_path = Path(result.phase_outputs[p6._PHASE_NAME]["flights"][0]["stored_path"])
    events = json.loads(tl_path.read_text(encoding="utf-8"))["events"]

    timestamps = [e["timestamp"] for e in events if e["timestamp"]]
    assert timestamps == sorted(timestamps)


# ---------------------------------------------------------------------------
# Unit tests — peak height, motor, fly-mode event generators
# ---------------------------------------------------------------------------

def _make_cand(rows: list[list[str]], header: list[str], ts_col: str,
               lat_col: str, lon_col: str) -> dict:
    """Minimal candidate dict for unit-testing event generators."""
    from datetime import timedelta
    ev = {"sha256": "abc123", "source_identification": "test", "artefact_category": "drone_logs"}
    row_dicts = [dict(zip(header, r + [""] * max(0, len(header) - len(r)))) for r in rows]
    cand = p6._build_candidate(ev, row_dicts, ts_col, lat_col, lon_col, header)
    assert cand is not None
    return cand


def test_peak_height_event_drone(tmp_path: Path) -> None:
    """Drone candidate → single 'Reached peak height' event at the max height row."""
    from datetime import timedelta
    base = datetime(2018, 4, 19, 11, 25, 0, tzinfo=timezone.utc)
    heights = ["1.0", "8.0", "3.0"]
    rows = [
        _drone_row(norm_id=str(i), ts=(base + timedelta(seconds=i)).isoformat(), height=h)
        for i, h in enumerate(heights)
    ]
    cand = _make_cand(rows, _NORM_DRONE_HEADER, p6._DRONE_TS_COL, p6._DRONE_LAT_COL, p6._DRONE_LON_COL)
    ev = p6._peak_height_event(cand, p6._event_data_drone, p6._DRONE_TS_COL, p6._DRONE_HEIGHT_COL)
    assert ev is not None
    assert ev["event"] == "Reached peak height"
    assert ev["data"]["relative_height"] == 8.0


def test_peak_height_event_fr(tmp_path: Path) -> None:
    """FR candidate → 'Reached peak height' event at the max OSD.height row."""
    from datetime import timedelta
    base = datetime(2018, 4, 19, 11, 25, 0, tzinfo=timezone.utc)
    heights = ["2.0", "4.0", "9.5", "1.0"]
    rows = [
        _fr_row(norm_id=str(i), ts=(base + timedelta(seconds=i)).isoformat(), height=h)
        for i, h in enumerate(heights)
    ]
    cand = _make_cand(rows, _NORM_FR_HEADER, p6._FR_TS_COL, p6._FR_LAT_COL, p6._FR_LON_COL)
    ev = p6._peak_height_event(cand, p6._event_data_fr, p6._FR_TS_COL, p6._FR_HEIGHT_COL)
    assert ev is not None
    assert ev["data"]["relative_height"] == 9.5


def test_motor_events_drone(tmp_path: Path) -> None:
    """Drone log: initial state + one off→on transition → 2 motor events."""
    from datetime import timedelta
    base = datetime(2018, 4, 19, 11, 25, 0, tzinfo=timezone.utc)
    motors = ["0", "0", "1", "1"]
    rows = [
        _drone_row(norm_id=str(i), ts=(base + timedelta(seconds=i)).isoformat(), motor=m)
        for i, m in enumerate(motors)
    ]
    cand = _make_cand(rows, _NORM_DRONE_HEADER, p6._DRONE_TS_COL, p6._DRONE_LAT_COL, p6._DRONE_LON_COL)
    evs = p6._motor_events(cand, p6._event_data_drone, p6._DRONE_TS_COL, p6._DRONE_MOTOR_COL, "1", "0")
    labels = [e["event"] for e in evs]
    assert labels == ["Motor turned off", "Motor turned on"]


def test_motor_events_fr(tmp_path: Path) -> None:
    """FR: TRUE→FALSE→TRUE transitions → 3 motor events."""
    from datetime import timedelta
    base = datetime(2018, 4, 19, 11, 25, 0, tzinfo=timezone.utc)
    motors = ["TRUE", "FALSE", "TRUE"]
    rows = [
        _fr_row(norm_id=str(i), ts=(base + timedelta(seconds=i)).isoformat(), motor=m)
        for i, m in enumerate(motors)
    ]
    cand = _make_cand(rows, _NORM_FR_HEADER, p6._FR_TS_COL, p6._FR_LAT_COL, p6._FR_LON_COL)
    evs = p6._motor_events(cand, p6._event_data_fr, p6._FR_TS_COL, p6._FR_MOTOR_COL, "TRUE", "FALSE")
    labels = [e["event"] for e in evs]
    assert labels == ["Motor turned on", "Motor turned off", "Motor turned on"]


def test_fly_mode_events(tmp_path: Path) -> None:
    """Fly-mode changes: 3 distinct values → 3 events."""
    from datetime import timedelta
    base = datetime(2018, 4, 19, 11, 25, 0, tzinfo=timezone.utc)
    modes = ["GPS", "GPS", "ATTI", "ATTI", "Sport"]
    rows = [
        _drone_row(norm_id=str(i), ts=(base + timedelta(seconds=i)).isoformat(), mode=m)
        for i, m in enumerate(modes)
    ]
    cand = _make_cand(rows, _NORM_DRONE_HEADER, p6._DRONE_TS_COL, p6._DRONE_LAT_COL, p6._DRONE_LON_COL)
    evs = p6._fly_mode_events(cand, p6._event_data_drone, p6._DRONE_TS_COL, p6._DRONE_MODE_COL)
    assert len(evs) == 3
    assert [e["data"]["fly_mode"] for e in evs] == ["GPS", "ATTI", "Sport"]


def test_motor_data_includes_base_fields(tmp_path: Path) -> None:
    """Motor event data block contains the four standard fields."""
    from datetime import timedelta
    base = datetime(2018, 4, 19, 11, 25, 0, tzinfo=timezone.utc)
    rows = [_drone_row(norm_id="0", ts=base.isoformat(), motor="1")]
    cand = _make_cand(rows, _NORM_DRONE_HEADER, p6._DRONE_TS_COL, p6._DRONE_LAT_COL, p6._DRONE_LON_COL)
    evs = p6._motor_events(cand, p6._event_data_drone, p6._DRONE_TS_COL, p6._DRONE_MOTOR_COL, "1", "0")
    assert len(evs) == 1
    data = evs[0]["data"]
    assert {"latitude", "longitude", "altitude", "motor_state"} <= set(data)
    assert "fly_mode" not in data


def _fr_cand_from_rows(rows: list[list[str]]) -> dict:
    row_dicts = [dict(zip(_NORM_FR_HEADER, r + [""] * max(0, len(_NORM_FR_HEADER) - len(r)))) for r in rows]
    ev = {"sha256": "abc123", "source_identification": "test", "artefact_category": "flight_records"}
    cand = p6._build_candidate(ev, row_dicts, p6._FR_TS_COL, p6._FR_LAT_COL, p6._FR_LON_COL, _NORM_FR_HEADER)
    assert cand is not None
    return cand


def test_log_message_events(tmp_path: Path) -> None:
    """Non-empty APP_WARN.warn → one 'Log message' event per populated row."""
    from datetime import timedelta
    base = datetime(2018, 4, 19, 11, 25, 0, tzinfo=timezone.utc)
    warns = ["", "low battery", "", "signal lost"]
    rows = [_fr_row(norm_id=str(i), ts=(base + timedelta(seconds=i)).isoformat(), warn=w)
            for i, w in enumerate(warns)]
    cand = _fr_cand_from_rows(rows)
    evs = p6._log_message_events(cand, p6._event_data_fr, p6._FR_TS_COL, p6._FR_WARN_COL)
    assert len(evs) == 2
    assert evs[0]["event"] == "Log message"
    assert evs[0]["data"]["log_message"] == "low battery"
    assert evs[1]["data"]["log_message"] == "signal lost"


def test_state_change_events_record_mode_with_initial(tmp_path: Path) -> None:
    """Record mode: initial value + transitions both emitted."""
    from datetime import timedelta
    base = datetime(2018, 4, 19, 11, 25, 0, tzinfo=timezone.utc)
    states = ["idle", "idle", "recording", "idle"]
    rows = [_fr_row(norm_id=str(i), ts=(base + timedelta(seconds=i)).isoformat(), rec=s)
            for i, s in enumerate(states)]
    cand = _fr_cand_from_rows(rows)
    evs = p6._state_change_events(cand, p6._FR_REC_STATE_COL, "Record mode changed", "record_mode", True)
    assert len(evs) == 3
    assert [e["data"]["record_mode"] for e in evs] == ["idle", "recording", "idle"]


def test_state_change_events_photo_mode_with_initial(tmp_path: Path) -> None:
    """Photo mode: initial value included."""
    from datetime import timedelta
    base = datetime(2018, 4, 19, 11, 25, 0, tzinfo=timezone.utc)
    states = ["burst", "burst", "single"]
    rows = [_fr_row(norm_id=str(i), ts=(base + timedelta(seconds=i)).isoformat(), photo=s)
            for i, s in enumerate(states)]
    cand = _fr_cand_from_rows(rows)
    evs = p6._state_change_events(cand, p6._FR_PHOTO_COL, "Photo mode changed", "photo_mode", True)
    assert len(evs) == 2
    assert [e["data"]["photo_mode"] for e in evs] == ["burst", "single"]


def test_state_change_events_sd_no_initial(tmp_path: Path) -> None:
    """SD state: first occurrence NOT emitted; only transitions."""
    from datetime import timedelta
    base = datetime(2018, 4, 19, 11, 25, 0, tzinfo=timezone.utc)
    states = ["normal", "normal", "full", "full"]
    rows = [_fr_row(norm_id=str(i), ts=(base + timedelta(seconds=i)).isoformat(), sd=s)
            for i, s in enumerate(states)]
    cand = _fr_cand_from_rows(rows)
    evs = p6._state_change_events(cand, p6._FR_SD_COL, "SD storage is full", "sd_state", False)
    assert len(evs) == 1
    assert evs[0]["data"]["sd_state"] == "full"


def test_tip_log_message_events(tmp_path: Path) -> None:
    """Non-empty APP_TIP.tip → one 'Log message' event per populated row."""
    from datetime import timedelta
    base = datetime(2018, 4, 19, 11, 25, 0, tzinfo=timezone.utc)
    tips = ["", "return to home", "", "obstacle detected"]
    rows = [_fr_row(norm_id=str(i), ts=(base + timedelta(seconds=i)).isoformat(), tip=t)
            for i, t in enumerate(tips)]
    cand = _fr_cand_from_rows(rows)
    evs = p6._log_message_events(cand, p6._event_data_fr, p6._FR_TS_COL, p6._FR_TIP_COL)
    assert len(evs) == 2
    assert evs[0]["event"] == "Log message"
    assert evs[0]["data"]["log_message"] == "return to home"
    assert evs[1]["data"]["log_message"] == "obstacle detected"


# ---------------------------------------------------------------------------
# Unit tests — exif observation correlation helpers
# ---------------------------------------------------------------------------

def test_exif_obs_datetime_valid() -> None:
    obs = {"norm_date": "2018-04-19", "norm_time": "11:25:10"}
    dt = p6._exif_obs_datetime(obs)
    assert dt == datetime(2018, 4, 19, 11, 25, 10, tzinfo=timezone.utc)


def test_exif_obs_datetime_missing_time() -> None:
    assert p6._exif_obs_datetime({"norm_date": "2018-04-19"}) is None


def test_exif_obs_datetime_missing_date() -> None:
    assert p6._exif_obs_datetime({"norm_time": "11:25:10"}) is None


def test_flight_covers_dt_inside() -> None:
    flight = {"flights_identified": [
        {"start": "2018-04-19T11:00:00+00:00", "end": "2018-04-19T12:00:00+00:00"},
    ]}
    dt = datetime(2018, 4, 19, 11, 30, 0, tzinfo=timezone.utc)
    assert p6._flight_covers_dt(flight, dt) is True


def test_flight_covers_dt_outside() -> None:
    flight = {"flights_identified": [
        {"start": "2018-04-19T11:00:00+00:00", "end": "2018-04-19T12:00:00+00:00"},
    ]}
    dt = datetime(2018, 4, 19, 13, 0, 0, tzinfo=timezone.utc)
    assert p6._flight_covers_dt(flight, dt) is False


# ---------------------------------------------------------------------------
# Integration tests — exif observation correlation in run_phase_6
# ---------------------------------------------------------------------------

def _build_p6_state_with_exif(
    tmp_path: Path,
    monkeypatch,
    fr_path: Path,
    fr_identification: str,
    exif_obs_data: dict,
    exif_sha: str,
    exif_category: str,
    p4_artefact_sha: str,
    p4_artefact_source_id: str,
) -> State:
    """Build state with a FR candidate + one P5 EXIF observation + P4 artefact lookup."""
    state = _build_p6_state(
        tmp_path, monkeypatch,
        fr_path=fr_path, fr_identification=fr_identification,
    )
    obs = make_observation(
        stored_path=str(fr_path),
        evidence_sha256=exif_sha,
        evidence_category=exif_category,
        acquisition_method=config.ACQUISITION_NORMALISE,
        observations=[exif_obs_data],
    )
    state.phase_outputs["p5_normalisation_and_anomaly_checking"]["derived_anomalies"].append(
        obs.to_dict()
    )
    state.phase_outputs["p4_decision_and_orchestration"] = {
        "decision_and_orchestration_artefacts": [
            {
                "sha256": p4_artefact_sha,
                "source_identification": p4_artefact_source_id,
                "artefact_category": exif_category,
            }
        ],
        "derived_observations": [],
    }
    return state


def test_exif_correlation_event_added(tmp_path: Path, monkeypatch) -> None:
    """EXIF obs timestamp inside flight window → event added + plausibly_correlated populated."""
    rows_data = _overlapping_rows(n=30, interval_s=3)
    fr_csv = tmp_path / "fr.csv"
    _write_norm_fr_csv(fr_csv, [_fr_row(norm_id=r[0], ts=r[1], lat=r[2], lon=r[3]) for r in rows_data])

    # Timestamp inside the flight window (row 10 = base + 30s)
    inside_ts = datetime.fromisoformat("2018-04-19T11:25:30+00:00")
    exif_sha = "aabbcc" * 10 + "aabb"
    state = _build_p6_state_with_exif(
        tmp_path, monkeypatch,
        fr_path=fr_csv,
        fr_identification=config.IDENTIFICATION_CONTROLLER_IOS,
        exif_obs_data={
            "norm_date": inside_ts.strftime("%Y-%m-%d"),
            "norm_time": inside_ts.strftime("%H:%M:%S"),
            "gps_latitude": 39.9612,
            "gps_longitude": -106.2165,
        },
        exif_sha=exif_sha,
        exif_category=config.IMAGES,
        p4_artefact_sha=exif_sha,
        p4_artefact_source_id=config.IDENTIFICATION_CONTROLLER_IOS,
    )
    result = p6.run_phase_6(state)

    flight = result.phase_outputs[p6._PHASE_NAME]["flights"][0]
    assert f"p5:{exif_sha}" in flight["plausibly_correlated"]

    tl = json.loads(Path(flight["stored_path"]).read_text(encoding="utf-8"))
    media_events = [e for e in tl["events"] if e["event"] == "Plausible media metadata correlation found"]
    assert len(media_events) == 1
    ev = media_events[0]
    assert ev["data"]["media_type"] == config.IMAGES
    assert ev["data"]["date"] == inside_ts.strftime("%Y-%m-%d")
    assert ev["data"]["time"] == inside_ts.strftime("%H:%M:%S")
    assert ev["timezone"] == "UTC"


def test_exif_correlation_no_match(tmp_path: Path, monkeypatch) -> None:
    """EXIF obs timestamp outside flight window → no event, plausibly_correlated empty."""
    rows_data = _overlapping_rows(n=10, interval_s=3)
    fr_csv = tmp_path / "fr.csv"
    _write_norm_fr_csv(fr_csv, [_fr_row(norm_id=r[0], ts=r[1], lat=r[2], lon=r[3]) for r in rows_data])

    exif_sha = "deadbeef" * 8
    state = _build_p6_state_with_exif(
        tmp_path, monkeypatch,
        fr_path=fr_csv,
        fr_identification=config.IDENTIFICATION_CONTROLLER_IOS,
        exif_obs_data={
            "norm_date": "2020-01-01",
            "norm_time": "00:00:00",
        },
        exif_sha=exif_sha,
        exif_category=config.IMAGES,
        p4_artefact_sha=exif_sha,
        p4_artefact_source_id=config.IDENTIFICATION_CONTROLLER_IOS,
    )
    result = p6.run_phase_6(state)

    flight = result.phase_outputs[p6._PHASE_NAME]["flights"][0]
    assert flight["plausibly_correlated"] == []
    tl = json.loads(Path(flight["stored_path"]).read_text(encoding="utf-8"))
    media_events = [e for e in tl["events"] if e["event"] == "Plausible media metadata correlation found"]
    assert media_events == []


def test_exif_correlation_gps_only_in_bbox(tmp_path: Path, monkeypatch) -> None:
    """GPS-only obs inside flight bbox → pointer in possibly_correlated only, not plausibly_correlated."""
    rows_data = _overlapping_rows(n=10, interval_s=3, lat="39.9612", lon="-106.2165")
    fr_csv = tmp_path / "fr.csv"
    _write_norm_fr_csv(fr_csv, [_fr_row(norm_id=r[0], ts=r[1], lat=r[2], lon=r[3]) for r in rows_data])

    exif_sha = "cafe" * 15 + "cafe"
    state = _build_p6_state_with_exif(
        tmp_path, monkeypatch,
        fr_path=fr_csv,
        fr_identification=config.IDENTIFICATION_CONTROLLER_IOS,
        exif_obs_data={
            "gps_latitude": 39.9612,
            "gps_longitude": -106.2165,
        },
        exif_sha=exif_sha,
        exif_category=config.IMAGES,
        p4_artefact_sha=exif_sha,
        p4_artefact_source_id=config.IDENTIFICATION_CONTROLLER_IOS,
    )
    result = p6.run_phase_6(state)

    flight = result.phase_outputs[p6._PHASE_NAME]["flights"][0]
    assert f"p5:{exif_sha}" not in flight["plausibly_correlated"]
    assert len(flight["possibly_correlated"]) == 1
    entry = flight["possibly_correlated"][0]
    assert entry["source_pointer"] == f"p5:{exif_sha}"
    assert entry["data"]["latitude"] == 39.9612

    tl = json.loads(Path(flight["stored_path"]).read_text(encoding="utf-8"))
    media_events = [e for e in tl["events"] if e["event"] == "Plausible media metadata correlation found"]
    assert media_events == []


def test_exif_correlation_gps_only_outside_bbox(tmp_path: Path, monkeypatch) -> None:
    """GPS-only obs outside flight bbox → nothing added."""
    rows_data = _overlapping_rows(n=10, interval_s=3, lat="39.9612", lon="-106.2165")
    fr_csv = tmp_path / "fr.csv"
    _write_norm_fr_csv(fr_csv, [_fr_row(norm_id=r[0], ts=r[1], lat=r[2], lon=r[3]) for r in rows_data])

    exif_sha = "f00d" * 15 + "f00d"
    state = _build_p6_state_with_exif(
        tmp_path, monkeypatch,
        fr_path=fr_csv,
        fr_identification=config.IDENTIFICATION_CONTROLLER_IOS,
        exif_obs_data={
            "gps_latitude": 51.5074,   # London — far from Colorado
            "gps_longitude": -0.1278,
        },
        exif_sha=exif_sha,
        exif_category=config.IMAGES,
        p4_artefact_sha=exif_sha,
        p4_artefact_source_id=config.IDENTIFICATION_CONTROLLER_IOS,
    )
    result = p6.run_phase_6(state)

    flight = result.phase_outputs[p6._PHASE_NAME]["flights"][0]
    assert flight["plausibly_correlated"] == []
    assert flight["possibly_correlated"] == []


# ---------------------------------------------------------------------------
# Unit tests — _norm_msg
# ---------------------------------------------------------------------------

def test_norm_msg_strips_level_prefix() -> None:
    """[Warning] prefix and Warning: prefix normalise to the same string."""
    assert p6._norm_msg("[Warning] compass interference") == p6._norm_msg("Warning: compass interference")


def test_norm_msg_nbsp_and_replacement() -> None:
    """Non-breaking space (\xa0) and Unicode replacement char (�) both normalise to space."""
    assert p6._norm_msg("RTH Altitude:\xa0 30m") == p6._norm_msg("RTH Altitude:� 30m")


# ---------------------------------------------------------------------------
# Integration tests — flight_log observation correlation in run_phase_6
# ---------------------------------------------------------------------------

def _build_p6_state_with_flight_log_obs(
    tmp_path: Path,
    monkeypatch,
    fr_path: Path,
    fr_identification: str,
    fl_obs_data: dict,
    fl_sha: str,
    fl_source_id: str,
) -> State:
    """Build state with a FR candidate + one P5 flight_log observation (P3 source)."""
    state = _build_p6_state(
        tmp_path, monkeypatch,
        fr_path=fr_path, fr_identification=fr_identification,
    )
    obs = make_observation(
        stored_path="dummy_flight_log.dat",
        evidence_sha256=fl_sha,
        evidence_category=config.FLIGHT_LOGS,
        acquisition_method=config.ACQUISITION_NORMALISE,
        observations=[fl_obs_data],
    )
    state.phase_outputs["p5_normalisation_and_anomaly_checking"]["derived_anomalies"].append(
        obs.to_dict()
    )
    # Flight_log observations reference P3 sha256s — supply via p3 artefacts.
    state.phase_outputs["p3_artefact_extraction"] = {
        "extracted_artefacts": [
            {
                "sha256": fl_sha,
                "source_identification": fl_source_id,
                "artefact_category": config.FLIGHT_LOGS,
            }
        ]
    }
    return state


def test_flight_log_correlation_subset_match(tmp_path: Path, monkeypatch) -> None:
    """Flight_log messages match after normalisation → possibly_correlated populated.

    The CSV warn column uses 'Warning:compass interference.' (colon, period),
    while the iOS log entry uses '[Warning] compass interference,' (brackets, comma).
    Exact strings differ; normalised strings match — exercises _norm_msg path.
    """
    rows_data = _overlapping_rows(n=10, interval_s=3, base_ts="2018-04-19T11:25:00+00:00")
    fr_csv = tmp_path / "fr.csv"
    csv_warn = "Warning:compass interference."   # FlightRecord CSV format
    ios_warn = "[Warning] compass interference,"  # iOS json_array_log format
    assert csv_warn != ios_warn                   # exact strings must differ to prove normalisation
    _write_norm_fr_csv(fr_csv, [
        _fr_row(norm_id=r[0], ts=r[1], lat=r[2], lon=r[3], warn=csv_warn if i == 3 else "")
        for i, r in enumerate(rows_data)
    ])

    fl_sha = "aa" * 32
    state = _build_p6_state_with_flight_log_obs(
        tmp_path, monkeypatch,
        fr_path=fr_csv,
        fr_identification=config.IDENTIFICATION_CONTROLLER_IOS,
        fl_obs_data={
            "format": "json_array_log",
            "entries": [{"timestamp": "2018-04-19 11:25:09", "message": ios_warn}],
        },
        fl_sha=fl_sha,
        fl_source_id=config.IDENTIFICATION_CONTROLLER_IOS,
    )
    result = p6.run_phase_6(state)

    flight = result.phase_outputs[p6._PHASE_NAME]["flights"][0]
    pointers = [pc["source_pointer"] for pc in flight["possibly_correlated"]]
    assert f"p5:{fl_sha}" in pointers
    entry = next(pc for pc in flight["possibly_correlated"] if pc["source_pointer"] == f"p5:{fl_sha}")
    assert entry["data"]["format"] == "json_array_log"
    assert entry["data"]["entry_count"] == 1


def test_flight_log_correlation_not_subset(tmp_path: Path, monkeypatch) -> None:
    """Flight_log message not in timeline events → no correlation."""
    rows_data = _overlapping_rows(n=10, interval_s=3, base_ts="2018-04-19T11:25:00+00:00")
    fr_csv = tmp_path / "fr.csv"
    _write_norm_fr_csv(fr_csv, [_fr_row(norm_id=r[0], ts=r[1]) for r in rows_data])

    fl_sha = "bb" * 32
    state = _build_p6_state_with_flight_log_obs(
        tmp_path, monkeypatch,
        fr_path=fr_csv,
        fr_identification=config.IDENTIFICATION_CONTROLLER_IOS,
        fl_obs_data={
            "format": "bracketed_log",
            "entries": [{"timestamp": "2018-04-19 11:25:09", "message": "not in timeline"}],
        },
        fl_sha=fl_sha,
        fl_source_id=config.IDENTIFICATION_CONTROLLER_IOS,
    )
    result = p6.run_phase_6(state)

    flight = result.phase_outputs[p6._PHASE_NAME]["flights"][0]
    pointers = [pc["source_pointer"] for pc in flight["possibly_correlated"]]
    assert f"p5:{fl_sha}" not in pointers


def test_flight_log_correlation_crash_dump_skipped(tmp_path: Path, monkeypatch) -> None:
    """crash_dump format is excluded from flight_log correlation."""
    rows_data = _overlapping_rows(n=10, interval_s=3)
    fr_csv = tmp_path / "fr.csv"
    _write_norm_fr_csv(fr_csv, [_fr_row(norm_id=r[0], ts=r[1]) for r in rows_data])

    fl_sha = "dd" * 32
    state = _build_p6_state_with_flight_log_obs(
        tmp_path, monkeypatch,
        fr_path=fr_csv,
        fr_identification=config.IDENTIFICATION_CONTROLLER_IOS,
        fl_obs_data={
            "format": "crash_dump",
            "entries": [{"type": "java_exception", "exception": "OOM", "message": "msg"}],
        },
        fl_sha=fl_sha,
        fl_source_id=config.IDENTIFICATION_CONTROLLER_IOS,
    )
    result = p6.run_phase_6(state)

    flight = result.phase_outputs[p6._PHASE_NAME]["flights"][0]
    pointers = [pc["source_pointer"] for pc in flight["possibly_correlated"]]
    assert f"p5:{fl_sha}" not in pointers


def test_flight_log_correlation_heading_log_time_only(tmp_path: Path, monkeypatch) -> None:
    """heading_log timestamps are time-only — subset check still matches correctly."""
    rows_data = _overlapping_rows(n=10, interval_s=3, base_ts="2018-04-19T11:25:00+00:00")
    fr_csv = tmp_path / "fr.csv"
    warn_msg = "Taking Off"
    _write_norm_fr_csv(fr_csv, [
        _fr_row(norm_id=r[0], ts=r[1], lat=r[2], lon=r[3], warn=warn_msg if i == 2 else "")
        for i, r in enumerate(rows_data)
    ])

    fl_sha = "ee" * 32
    state = _build_p6_state_with_flight_log_obs(
        tmp_path, monkeypatch,
        fr_path=fr_csv,
        fr_identification=config.IDENTIFICATION_CONTROLLER_IOS,
        fl_obs_data={
            "format": "heading_log",
            "entries": [{"timestamp": "11:25:06", "message": warn_msg}],
        },
        fl_sha=fl_sha,
        fl_source_id=config.IDENTIFICATION_CONTROLLER_IOS,
    )
    result = p6.run_phase_6(state)

    flight = result.phase_outputs[p6._PHASE_NAME]["flights"][0]
    pointers = [pc["source_pointer"] for pc in flight["possibly_correlated"]]
    assert f"p5:{fl_sha}" in pointers


def test_flight_log_correlation_tip_log_message_capital(tmp_path: Path, monkeypatch) -> None:
    """APP_TIP 'Log message' events are included in the flight_log subset check."""
    rows_data = _overlapping_rows(n=10, interval_s=3, base_ts="2018-04-19T11:25:00+00:00")
    fr_csv = tmp_path / "fr.csv"
    tip_msg = "Taking Off"
    _write_norm_fr_csv(fr_csv, [
        _fr_row(norm_id=r[0], ts=r[1], lat=r[2], lon=r[3], tip=tip_msg if i == 2 else "")
        for i, r in enumerate(rows_data)
    ])

    fl_sha = "ff" * 32
    state = _build_p6_state_with_flight_log_obs(
        tmp_path, monkeypatch,
        fr_path=fr_csv,
        fr_identification=config.IDENTIFICATION_CONTROLLER_IOS,
        fl_obs_data={
            "format": "json_array_log",
            "entries": [{"timestamp": "2018-04-19 11:25:06", "message": tip_msg}],
        },
        fl_sha=fl_sha,
        fl_source_id=config.IDENTIFICATION_CONTROLLER_IOS,
    )
    result = p6.run_phase_6(state)

    flight = result.phase_outputs[p6._PHASE_NAME]["flights"][0]
    pointers = [pc["source_pointer"] for pc in flight["possibly_correlated"]]
    assert f"p5:{fl_sha}" in pointers


# ---------------------------------------------------------------------------
# Unit tests — video duration correlation
# ---------------------------------------------------------------------------

def _make_flight_with_log_ended(duration_recording):
    """Minimal flight dict with a Log ended event carrying duration_recording."""
    ev_data = {}
    if duration_recording is not None:
        ev_data["duration_recording"] = duration_recording
    return {
        "events": [{"event": "Log ended", "data": ev_data}],
        "plausibly_correlated": [],
        "possibly_correlated": [],
    }


def _make_video_obs(sha, duration, source_id="controller_ios"):
    obs = {}
    if duration is not None:
        obs["Duration"] = duration
    return {
        "evidence_category": config.VIDEOS,
        "acquisition_method": config.ACQUISITION_EXIFTOOL,
        "evidence_sha256": sha,
        "observations": [obs],
    }


def test_video_duration_match() -> None:
    flight = _make_flight_with_log_ended(59.5)
    sha = "aa" * 32
    obs = _make_video_obs(sha, 60.0)
    p6._correlate_video_duration([flight], [obs], {sha: "controller_ios"})
    pointers = [pc["source_pointer"] for pc in flight["possibly_correlated"]]
    assert f"p4:{sha}" in pointers
    entry = next(pc for pc in flight["possibly_correlated"] if pc["source_pointer"] == f"p4:{sha}")
    assert entry["data"]["video_duration_s"] == 60.0
    assert entry["data"]["log_duration_s"] == 59.5


def test_video_duration_no_match() -> None:
    flight = _make_flight_with_log_ended(50.0)
    sha = "bb" * 32
    obs = _make_video_obs(sha, 60.0)
    p6._correlate_video_duration([flight], [obs], {sha: "controller_ios"})
    assert flight["possibly_correlated"] == []


def test_video_duration_missing_duration() -> None:
    flight = _make_flight_with_log_ended(60.0)
    sha = "cc" * 32
    obs = _make_video_obs(sha, None)
    p6._correlate_video_duration([flight], [obs], {sha: "controller_ios"})
    assert flight["possibly_correlated"] == []


def test_video_duration_missing_log_ended() -> None:
    flight = {"events": [], "plausibly_correlated": [], "possibly_correlated": []}
    sha = "dd" * 32
    obs = _make_video_obs(sha, 60.0)
    p6._correlate_video_duration([flight], [obs], {sha: "controller_ios"})
    assert flight["possibly_correlated"] == []


def test_video_duration_dedup() -> None:
    flight = _make_flight_with_log_ended(60.0)
    sha = "ee" * 32
    obs = _make_video_obs(sha, 60.5)
    p6._correlate_video_duration([flight], [obs], {sha: "controller_ios"})
    p6._correlate_video_duration([flight], [obs], {sha: "controller_ios"})
    assert len(flight["possibly_correlated"]) == 1


# ---------------------------------------------------------------------------
# Unit tests — _deduplicate_fr_candidates
# ---------------------------------------------------------------------------

def _make_fr_cand(
    start: datetime,
    end: datetime,
    gps_count: int = 20,
) -> dict:
    """Minimal FR candidate dict for deduplication testing."""
    return {
        "evidence_dict": {"sha256": "x" * 64, "source_identification": "controller_ios"},
        "rows": [],
        "header": [],
        "start_dt": start,
        "end_dt": end,
        "duration_s": (end - start).total_seconds(),
        "gps_count": gps_count,
        "has_usable_gps": gps_count >= 10,
        "app_version": None,
    }


def test_deduplicate_single_candidate() -> None:
    """Single candidate is returned unchanged."""
    utc = timezone.utc
    cand = _make_fr_cand(datetime(2018, 4, 19, 11, 0, tzinfo=utc),
                         datetime(2018, 4, 19, 11, 10, tzinfo=utc))
    result = p6._deduplicate_fr_candidates([cand])
    assert result == [cand]


def test_deduplicate_overlap_keeps_higher_gps() -> None:
    """Two FRs with large overlap and near-equal duration: higher GPS count survives."""
    utc = timezone.utc
    low_gps = _make_fr_cand(datetime(2018, 4, 19, 11, 0, tzinfo=utc),
                             datetime(2018, 4, 19, 11, 10, tzinfo=utc), gps_count=15)
    high_gps = _make_fr_cand(datetime(2018, 4, 19, 11, 0, tzinfo=utc),
                              datetime(2018, 4, 19, 11, 10, tzinfo=utc), gps_count=25)
    result = p6._deduplicate_fr_candidates([low_gps, high_gps])
    assert len(result) == 1
    assert result[0]["gps_count"] == 25


def test_deduplicate_overlap_tie_keeps_first() -> None:
    """Equal GPS count: first candidate is kept."""
    utc = timezone.utc
    first = _make_fr_cand(datetime(2018, 4, 19, 11, 0, tzinfo=utc),
                          datetime(2018, 4, 19, 11, 10, tzinfo=utc), gps_count=20)
    second = _make_fr_cand(datetime(2018, 4, 19, 11, 0, tzinfo=utc),
                           datetime(2018, 4, 19, 11, 10, tzinfo=utc), gps_count=20)
    result = p6._deduplicate_fr_candidates([first, second])
    assert len(result) == 1
    assert result[0] is first


def test_deduplicate_no_overlap_both_kept() -> None:
    """Two FRs with no temporal overlap → both survive."""
    utc = timezone.utc
    a = _make_fr_cand(datetime(2018, 4, 19, 11, 0, tzinfo=utc),
                      datetime(2018, 4, 19, 11, 10, tzinfo=utc))
    b = _make_fr_cand(datetime(2018, 4, 19, 12, 0, tzinfo=utc),
                      datetime(2018, 4, 19, 12, 10, tzinfo=utc))
    result = p6._deduplicate_fr_candidates([a, b])
    assert len(result) == 2


def test_deduplicate_overlap_large_duration_diff_both_kept() -> None:
    """Large overlap but duration difference >= 5 s → treated as distinct flights."""
    utc = timezone.utc
    # cand_a: 10 min; cand_b overlaps entirely but is 8 min (diff = 120s >> 5s)
    a = _make_fr_cand(datetime(2018, 4, 19, 11, 0, tzinfo=utc),
                      datetime(2018, 4, 19, 11, 10, tzinfo=utc))
    b = _make_fr_cand(datetime(2018, 4, 19, 11, 0, tzinfo=utc),
                      datetime(2018, 4, 19, 11, 8, tzinfo=utc))
    result = p6._deduplicate_fr_candidates([a, b])
    assert len(result) == 2


# ---------------------------------------------------------------------------
# Unit tests — app_version in source strings
# ---------------------------------------------------------------------------

def _fr_cand_with_version(version: str | None) -> dict:
    """FR candidate with a specific app_version (no real rows needed)."""
    utc = timezone.utc
    return {
        "evidence_dict": {
            "sha256": "b" * 64,
            "source_identification": "controller_ios",
            "artefact_category": "flight_records",
        },
        "rows": [],
        "header": [],
        "start_dt": datetime(2018, 4, 19, 11, 0, tzinfo=utc),
        "end_dt": datetime(2018, 4, 19, 11, 10, tzinfo=utc),
        "duration_s": 600.0,
        "gps_count": 0,
        "has_usable_gps": False,
        "app_version": version,
    }


def test_app_version_in_source_when_present() -> None:
    """Candidate with app_version: source string includes '(v<version>)' suffix."""
    cand = _fr_cand_with_version("4.2.12")
    # Build a single-row boundary candidate to invoke _peak_height_event
    utc = timezone.utc
    base = datetime(2018, 4, 19, 11, 0, tzinfo=utc)
    row_dicts = [dict(zip(_NORM_FR_HEADER,
                         _fr_row(norm_id="0", ts=base.isoformat(), height="5.0")
                         + [""] * max(0, len(_NORM_FR_HEADER) - len(_NORM_FR_HEADER))))]
    cand["rows"] = row_dicts
    ev = p6._peak_height_event(cand, p6._event_data_fr, p6._FR_TS_COL, p6._FR_HEIGHT_COL)
    assert ev is not None
    assert ev["source"] == "controller_ios:flight_records (v4.2.12)"


def test_app_version_absent_source_unchanged() -> None:
    """Candidate without app_version: source string has no suffix."""
    cand = _fr_cand_with_version(None)
    utc = timezone.utc
    base = datetime(2018, 4, 19, 11, 0, tzinfo=utc)
    row_dicts = [dict(zip(_NORM_FR_HEADER,
                         _fr_row(norm_id="0", ts=base.isoformat(), height="5.0")
                         + [""] * max(0, len(_NORM_FR_HEADER) - len(_NORM_FR_HEADER))))]
    cand["rows"] = row_dicts
    ev = p6._peak_height_event(cand, p6._event_data_fr, p6._FR_TS_COL, p6._FR_HEIGHT_COL)
    assert ev is not None
    assert ev["source"] == "controller_ios:flight_records"


def test_build_candidate_reads_app_version_from_rows(tmp_path: Path) -> None:
    """_build_candidate extracts dji_app_version from DETAILS rows into app_version."""
    # Build a CSV with a DETAILS.appVersion column populated
    details_header = _NORM_FR_HEADER + ["DETAILS.appVersion"]
    csv_path = tmp_path / "fr_with_details.csv"
    utc = timezone.utc
    base = datetime(2018, 4, 19, 11, 0, tzinfo=utc)
    with csv_path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(details_header)
        row = _fr_row(norm_id="0", ts=base.isoformat()) + ["4.3.26"]
        w.writerow(row)
    header, rows = p6._load_csv_rows(csv_path)
    ev_dict = {"sha256": "c" * 64, "source_identification": "controller_ios"}
    cand = p6._build_candidate(ev_dict, rows, p6._FR_TS_COL, p6._FR_LAT_COL, p6._FR_LON_COL, header)
    assert cand is not None
    assert cand["app_version"] == "4.3.26"


def test_build_candidate_no_details_app_version_is_none(tmp_path: Path) -> None:
    """_build_candidate without DETAILS columns → app_version is None."""
    csv_path = tmp_path / "fr_no_details.csv"
    utc = timezone.utc
    base = datetime(2018, 4, 19, 11, 0, tzinfo=utc)
    _write_norm_fr_csv(csv_path, [_fr_row(norm_id="0", ts=base.isoformat())])
    header, rows = p6._load_csv_rows(csv_path)
    ev_dict = {"sha256": "d" * 64, "source_identification": "controller_ios"}
    cand = p6._build_candidate(ev_dict, rows, p6._FR_TS_COL, p6._FR_LAT_COL, p6._FR_LON_COL, header)
    assert cand is not None
    assert cand["app_version"] is None
