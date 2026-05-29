"""Tests for phases/p7_analysis_and_validation.py."""
from __future__ import annotations

import json
from pathlib import Path

import config
from evidence import make_evidence
from phases import p7_analysis_and_validation as p7
from state import State


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_state(tmp_path: Path, monkeypatch, input_identifications=None) -> State:
    (tmp_path / "Documents").mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    state = State(case_id="CASE-P7-TEST", operator="Tester")
    for sid in (input_identifications or []):
        f = tmp_path / f"{sid}.zip"
        f.write_bytes(b"x")
        ev = make_evidence(
            source_path=str(f), stored_path=f, parent=None,
            acquisition_method=config.ACQUISITION_LOGICAL,
            type=config.EVIDENCE_TYPE_INPUT,
            source_identification=sid,
        )
        state.input_evidence.append(ev)
    return state


def _write_timeline(tmp_path: Path, flight_id: str, events: list[dict],
                    matched: bool = True, confidence: str = "high",
                    flights_identified=None) -> dict:
    """Write a timeline JSON and return the compact P6 flight dict."""
    tl_path = tmp_path / f"timeline_{flight_id}.json"
    fi = flights_identified or []
    tl = {
        "flight_id": flight_id,
        "flights_identified": fi,
        "correlation_metadata": {"matched": matched, "confidence": confidence},
        "plausibly_correlated": [],
        "possibly_correlated": [],
        "events": events,
    }
    tl_path.write_text(json.dumps(tl), encoding="utf-8")
    return {
        "flight_id": flight_id,
        "stored_path": str(tl_path),
        "flights_identified": fi,
        "correlation": {"matched": matched, "confidence": confidence},
        "plausibly_correlated": [],
        "possibly_correlated": [],
    }


def _log_started_ev(source: str, sp: str, stype: str = "controller",
                    serial_drone: str = None, name_drone: str = None,
                    dji_app_version: str = None) -> dict:
    data: dict = {}
    if serial_drone:
        data["serial_drone"] = serial_drone
    if name_drone:
        data["name_drone"] = name_drone
    if dji_app_version:
        data["dji_app_version"] = dji_app_version
    return {"event": "Log started", "confidence": "high",
            "source": source, "source_pointer": sp, "data": data}


# ---------------------------------------------------------------------------
# Section 1 — Source coverage
# ---------------------------------------------------------------------------

def test_source_coverage_all_detected(tmp_path, monkeypatch):
    state = _make_state(tmp_path, monkeypatch, [
        config.IDENTIFICATION_CONTROLLER_ANDROID,
        config.IDENTIFICATION_CONTROLLER_IOS,
        config.IDENTIFICATION_DRONE_SD,
        config.IDENTIFICATION_DRONE_FLIGHT_STORAGE,
    ])
    cov = p7._source_coverage(state)
    assert all(c["detected"] for c in cov)
    assert len(cov) == len(config.SOURCE_IDENTIFICATION_TYPES)


def test_source_coverage_partial(tmp_path, monkeypatch):
    state = _make_state(tmp_path, monkeypatch, [config.IDENTIFICATION_CONTROLLER_ANDROID])
    cov = p7._source_coverage(state)
    detected = [c for c in cov if c["detected"]]
    assert len(detected) == 1
    assert detected[0]["source"] == config.IDENTIFICATION_CONTROLLER_ANDROID


# ---------------------------------------------------------------------------
# Section 1 — Artefact coverage + data quality notes
# ---------------------------------------------------------------------------

def _p3a(cat: str, sha: str = "aabb", src: str = "controller_ios",
         stored: str = "/tmp/x.csv") -> dict:
    return {"artefact_category": cat, "sha256": sha,
            "source_identification": src, "stored_path": stored}


def test_artefact_coverage_counts():
    p3 = [_p3a(config.FLIGHT_RECORDS, "s1"), _p3a(config.FLIGHT_RECORDS, "s2"),
          _p3a(config.DRONE_LOGS, "s3")]
    cov = p7._artefact_coverage(p3, [])
    fr = next(c for c in cov if c["category"] == config.FLIGHT_RECORDS)
    dl = next(c for c in cov if c["category"] == config.DRONE_LOGS)
    assert fr["count"] == 2
    assert dl["count"] == 1


def test_artefact_coverage_empty_db_note():
    sha = "deadbeef"
    p3 = [_p3a(config.DATABASES, sha, "controller_ios")]
    p5 = [{"evidence_category": config.DATABASES, "evidence_sha256": sha,
            "stored_path": "/tmp/db.db", "observations": [{"database_empty": True}]}]
    cov = p7._artefact_coverage(p3, p5)
    db = next(c for c in cov if c["category"] == config.DATABASES)
    assert any("empty" in n for n in db["notes"])


def test_artefact_coverage_flight_records_row_anomaly_note():
    sha = "aaaa"
    p3 = [_p3a(config.FLIGHT_RECORDS, sha)]
    p5 = [{"evidence_category": config.FLIGHT_RECORDS, "evidence_sha256": sha,
            "stored_path": "/tmp/fr.csv",
            "observations": [{"timestamp_gap": [5, 10], "missing_gps": []}]}]
    cov = p7._artefact_coverage(p3, p5)
    fr = next(c for c in cov if c["category"] == config.FLIGHT_RECORDS)
    # timestamp_gap is non-empty → 1 file with row anomalies
    assert any("row anomal" in n for n in fr["notes"])
    assert "1 file(s) with row anomalies" in fr["notes"]


def test_artefact_coverage_flight_logs_notes():
    sha1, sha2 = "aaaa", "bbbb"
    p3 = [_p3a(config.FLIGHT_LOGS, sha1), _p3a(config.FLIGHT_LOGS, sha2)]
    p5 = [
        {"evidence_category": config.FLIGHT_LOGS, "evidence_sha256": sha1,
         "observations": [{"non_readable": True}]},
        {"evidence_category": config.FLIGHT_LOGS, "evidence_sha256": sha2,
         "observations": [{"format": "crash_dump"}]},
    ]
    cov = p7._artefact_coverage(p3, p5)
    fl = next(c for c in cov if c["category"] == config.FLIGHT_LOGS)
    note_text = " ".join(fl["notes"])
    assert "unreadable" in note_text
    assert "crash dump" in note_text


def test_artefact_coverage_images_exif_notes():
    sha = "cccc"
    p3 = [_p3a(config.IMAGES, sha)]
    p5 = [{"evidence_category": config.IMAGES, "evidence_sha256": sha,
            "observations": [{"exif_zero_date": True, "exif_missing_gps": True}]}]
    cov = p7._artefact_coverage(p3, p5)
    img = next(c for c in cov if c["category"] == config.IMAGES)
    note_text = " ".join(img["notes"])
    assert "zeroed EXIF" in note_text
    assert "missing GPS" in note_text


def test_artefact_coverage_no_duplicate_categories():
    """CONTROLLER_ARTEFACT_CATEGORIES already includes images/videos — no duplicates."""
    cov = p7._artefact_coverage([], [])
    cats = [c["category"] for c in cov]
    assert len(cats) == len(set(cats))


# ---------------------------------------------------------------------------
# Section 1 — Artefact coverage per source
# ---------------------------------------------------------------------------

def test_artefact_coverage_per_source_basic():
    p3 = [
        _p3a(config.FLIGHT_RECORDS, "s1", "controller_ios"),
        _p3a(config.FLIGHT_RECORDS, "s2", "controller_ios"),
        _p3a(config.DATABASES, "s3", "controller_android"),
    ]
    result = p7._artefact_coverage_per_source(p3)
    assert len(result) == 2
    android = next(r for r in result if r["source"] == "controller_android")
    ios = next(r for r in result if r["source"] == "controller_ios")
    assert android["artefacts"] == [{"category": config.DATABASES, "count": 1}]
    assert ios["artefacts"] == [{"category": config.FLIGHT_RECORDS, "count": 2}]


def test_artefact_coverage_per_source_source_order():
    p3 = [
        _p3a(config.IMAGES, "s1", "controller_ios"),
        _p3a(config.DATABASES, "s2", "controller_android"),
    ]
    result = p7._artefact_coverage_per_source(p3)
    sources = [r["source"] for r in result]
    assert sources.index("controller_android") < sources.index("controller_ios")


def test_artefact_coverage_per_source_empty():
    assert p7._artefact_coverage_per_source([]) == []


# ---------------------------------------------------------------------------
# Section 2 — Tool status
# ---------------------------------------------------------------------------

def test_tool_status_all_ok(tmp_path, monkeypatch):
    state = _make_state(tmp_path, monkeypatch)
    state.tool_invocation_log = [
        {"tool_name": "exiftool", "return_code": 0},
        {"tool_name": "exiftool", "return_code": 0},
    ]
    ts = p7._tool_status(state)
    assert ts[0]["status"] == "ok"
    assert ts[0]["invocation_count"] == 2


def test_tool_status_partial(tmp_path, monkeypatch):
    state = _make_state(tmp_path, monkeypatch)
    state.tool_invocation_log = [
        {"tool_name": "datcon", "return_code": 0},
        {"tool_name": "datcon", "return_code": 1},
    ]
    ts = p7._tool_status(state)
    assert ts[0]["status"] == "partial"


# ---------------------------------------------------------------------------
# Section 3 — Account and drone identity analysis
# ---------------------------------------------------------------------------

def test_collect_identity_p4_account_email(tmp_path):
    p4_obs = [{
        "evidence_category": config.ACCOUNT_DATA,
        "evidence_sha256": "sha001",
        "stored_path": "/tmp/controller_ios/account_data/com.dji.go.plist",
        "observations": [{"account_email": "test@example.com"}],
    }]
    sources = p7._collect_all_identity_sources([], p4_obs, [])
    assert len(sources["account_email"]) == 1
    assert sources["account_email"][0]["value"] == "test@example.com"
    assert sources["account_email"][0]["source_pointer"] == "p4:sha001"
    assert sources["account_email"][0]["source_type"] == "controller"


def test_collect_identity_p2_installed_apps(tmp_path):
    p2_obs = [{
        "evidence_category": config.DEVICE_AND_BACKUP_INFO,
        "evidence_sha256": "sha002",
        "stored_path": "/tmp/packages.list",
        "observations": [{"installed_dji_apps": ["dji.go.v4"]}],
    }]
    sources = p7._collect_all_identity_sources(p2_obs, [], [])
    assert len(sources["installed_dji_apps"]) == 1
    assert sources["installed_dji_apps"][0]["value"] == ["dji.go.v4"]
    assert sources["installed_dji_apps"][0]["source_pointer"] == "p2:sha002"


def test_collect_identity_timeline_drone_serial(tmp_path):
    ev = _log_started_ev(
        source="controller_ios:flight_records",
        sp="sha003:0",
        serial_drone="SN001",
    )
    flight = _write_timeline(tmp_path, "f01", [ev])
    sources = p7._collect_all_identity_sources([], [], [flight])
    assert any(e["value"] == "SN001" for e in sources["drone_serial"])
    entry = next(e for e in sources["drone_serial"] if e["value"] == "SN001")
    assert entry["source_pointer"] == "sha003:0"
    assert entry["source_type"] == "controller"


def test_collect_identity_drone_source_type(tmp_path):
    ev = _log_started_ev(
        source="drone_sd:drone_logs",
        sp="sha004:4",
        serial_drone="SN001",
    )
    flight = _write_timeline(tmp_path, "f01", [ev])
    sources = p7._collect_all_identity_sources([], [], [flight])
    entry = next(e for e in sources["drone_serial"] if e["value"] == "SN001")
    assert entry["source_type"] == "drone"


def test_build_analysis_single_source_no_drone():
    sources = {
        "drone_serial": [{"value": "SN001", "source_pointer": "p4:abc", "source_type": "controller"}],
        "account_email": [],
        "drone_name": [],
        "installed_dji_apps": [],
        "dji_app_version": [],
    }
    result = p7._build_account_and_drone_analysis(sources, [], [])
    assert result["drone_serial"]["confidence"] == "single-source"
    assert result["drone_serial"]["value"] == "SN001"


def test_build_analysis_multi_source_with_drone(tmp_path):
    # Controller + drone-side agree
    sources = {
        "drone_serial": [
            {"value": "SN001", "source_pointer": "p4:abc", "source_type": "controller"},
            {"value": "SN001", "source_pointer": "sha004:4", "source_type": "drone"},
        ],
        "account_email": [],
        "drone_name": [],
        "installed_dji_apps": [],
        "dji_app_version": [],
    }
    result = p7._build_account_and_drone_analysis(sources, [], [])
    assert result["drone_serial"]["confidence"] == "multi-source"


def test_build_analysis_inconsistent(tmp_path):
    sources = {
        "drone_serial": [
            {"value": "SN001", "source_pointer": "p4:abc", "source_type": "controller"},
            {"value": "SN999", "source_pointer": "sha004:4", "source_type": "drone"},
        ],
        "account_email": [],
        "drone_name": [],
        "installed_dji_apps": [],
        "dji_app_version": [],
    }
    result = p7._build_account_and_drone_analysis(sources, [], [])
    assert result["drone_serial"]["confidence"] == "inconsistent"
    assert isinstance(result["drone_serial"]["value"], list)


def test_build_analysis_drone_name_fuzzy(tmp_path):
    # "dronefo...-Mavic Air" vs "Mavic Air" should normalise to the same
    sources = {
        "drone_serial": [],
        "account_email": [],
        "drone_name": [
            {"value": "Mavic Air", "source_pointer": "p4:abc", "source_type": "controller"},
            {"value": "dronefo...-Mavic Air", "source_pointer": "sha004:0", "source_type": "controller"},
        ],
        "installed_dji_apps": [],
        "dji_app_version": [],
    }
    result = p7._build_account_and_drone_analysis(sources, [], [])
    assert result["drone_name"]["confidence"] != "inconsistent"


def test_build_analysis_two_controllers_still_single_source():
    # Two controller sources both have same serial — no drone source
    sources = {
        "drone_serial": [
            {"value": "SN001", "source_pointer": "p4:aaa", "source_type": "controller"},
            {"value": "SN001", "source_pointer": "p4:bbb", "source_type": "controller"},
        ],
        "account_email": [],
        "drone_name": [],
        "installed_dji_apps": [],
        "dji_app_version": [],
    }
    result = p7._build_account_and_drone_analysis(sources, [], [])
    assert result["drone_serial"]["confidence"] == "single-source"


# ---------------------------------------------------------------------------
# Section 4 — Flight analysis
# ---------------------------------------------------------------------------

def test_analyse_flight_event_counts(tmp_path):
    events = [
        {"event": "Log started", "confidence": "high", "data": {}},
        {"event": "Motor turned on", "confidence": "high", "data": {}},
        {"event": "Log ended", "confidence": "medium", "data": {}},
    ]
    sha = "aaaa"
    flight = _write_timeline(tmp_path, "f01", events, flights_identified=[{"evidence_sha256": sha}])
    result = p7._analyse_flight(flight, [])
    assert result["event_count"] == 3
    assert result["high_confidence_event_count"] == 2


def test_analyse_flight_peak_height(tmp_path):
    events = [{"event": "Reached peak height", "confidence": "high",
               "data": {"relative_height": 30.5}}]
    flight = _write_timeline(tmp_path, "f01", events)
    assert p7._analyse_flight(flight, [])["peak_height_m"] == 30.5


def test_analyse_flight_distance_travelled(tmp_path):
    events = [{"event": "Log ended", "confidence": "high",
               "data": {"distance_travelled": 2013.46}}]
    flight = _write_timeline(tmp_path, "f01", events)
    assert p7._analyse_flight(flight, [])["distance_travelled"] == 2013.46


def test_analyse_flight_video_taken(tmp_path):
    events = [{"event": "Record mode changed", "confidence": "high",
               "data": {"record_mode": "Starting"}}]
    flight = _write_timeline(tmp_path, "f01", events)
    assert p7._analyse_flight(flight, [])["video_taken"] is True


def test_analyse_flight_video_not_taken(tmp_path):
    events = [{"event": "Record mode changed", "confidence": "high",
               "data": {"record_mode": "No"}}]
    flight = _write_timeline(tmp_path, "f01", events)
    assert p7._analyse_flight(flight, [])["video_taken"] is False


def test_analyse_flight_photo_taken(tmp_path):
    events = [{"event": "Photo mode changed", "confidence": "high",
               "data": {"photo_mode": "Single"}}]
    flight = _write_timeline(tmp_path, "f01", events)
    assert p7._analyse_flight(flight, [])["photo_taken"] is True



def test_analyse_flight_no_anomaly_fields(tmp_path):
    sha = "bbbccc"
    flight = _write_timeline(tmp_path, "f01", [], flights_identified=[{"evidence_sha256": sha}])
    p5 = [{"evidence_sha256": sha, "evidence_category": config.FLIGHT_RECORDS,
            "observations": [{"timestamp_gap": [5, 10], "missing_gps": []}]}]
    result = p7._analyse_flight(flight, p5)
    assert "anomaly_count" not in result
    assert "anomaly_types_observed" not in result


# ---------------------------------------------------------------------------
# Section 5 — Lineage map + uncorrelated artefacts
# ---------------------------------------------------------------------------

def test_build_lineage_map_simple():
    p3 = [{"sha256": "p3sha", "parent_sha256": None}]
    p4 = [{"sha256": "p4sha", "parent_sha256": "p3sha"}]
    p5 = [{"sha256": "p5sha", "parent_sha256": "p4sha"}]
    lm = p7._build_lineage_map(p3, p4, p5)
    # All three shas should be in the same chain
    chain = lm["p3sha"]
    assert "p3sha" in chain
    assert "p4sha" in chain
    assert "p5sha" in chain
    assert lm["p4sha"] == lm["p3sha"] == lm["p5sha"]


def test_uncorrelated_artefacts_chain_referenced(tmp_path):
    """P3 sha not directly in P6 but P5 sha is → not uncorrelated."""
    p3 = [{"sha256": "p3sha", "parent_sha256": None,
            "artefact_category": config.FLIGHT_RECORDS, "stored_path": "/tmp/fr.txt"}]
    p4 = [{"sha256": "p4sha", "parent_sha256": "p3sha"}]
    p5 = [{"sha256": "p5sha", "parent_sha256": "p4sha"}]
    # P6 references p5sha (the normalised version)
    flight = _write_timeline(tmp_path, "f01", [], flights_identified=[{"evidence_sha256": "p5sha"}])
    result = p7._uncorrelated_artefacts(p3, p4, p5, [flight], {})
    assert result == []


def test_uncorrelated_artefacts_truly_uncorrelated(tmp_path):
    p3 = [{"sha256": "p3sha", "parent_sha256": None,
            "artefact_category": config.FLIGHT_RECORDS, "stored_path": "/tmp/fr.txt"}]
    flight = _write_timeline(tmp_path, "f01", [], flights_identified=[{"evidence_sha256": "other_sha"}])
    result = p7._uncorrelated_artefacts(p3, [], [], [flight], {})
    assert len(result) == 1
    assert result[0] == {"evidence_sha256": "p3sha"}


def test_uncorrelated_artefacts_account_reference(tmp_path):
    """P3 artefact referenced via account_and_drone_analysis corroboration_sources."""
    p3 = [{"sha256": "p3sha", "parent_sha256": None,
            "artefact_category": config.ACCOUNT_DATA, "stored_path": "/tmp/acc.plist"}]
    account = {"drone_serial": {"value": "SN001", "corroboration_sources": ["p4:p3sha"],
                                "confidence": "single-source"}}
    result = p7._uncorrelated_artefacts(p3, [], [], [], account)
    assert result == []


def test_uncorrelated_artefacts_only_evidence_sha256_field(tmp_path):
    p3 = [{"sha256": "p3sha", "parent_sha256": None,
            "artefact_category": config.FLIGHT_LOGS, "stored_path": "/tmp/fl.txt",
            "source_identification": "controller_android"}]
    result = p7._uncorrelated_artefacts(p3, [], [], [], {})
    assert len(result) == 1
    # Only evidence_sha256 field — no other keys
    assert set(result[0].keys()) == {"evidence_sha256"}


# ---------------------------------------------------------------------------
# Section 6 — Coverage score
# ---------------------------------------------------------------------------

def test_coverage_score_values(tmp_path):
    source_cov = [
        {"source": "controller_android", "detected": True},
        {"source": "controller_ios", "detected": True},
        {"source": "drone_sd", "detected": False},
        {"source": "drone_flight_storage", "detected": False},
    ]
    artefact_cov = [
        {"category": config.FLIGHT_RECORDS, "count": 2, "notes": []},
        {"category": config.DATABASES, "count": 0, "notes": []},
    ]
    tool_stat = [
        {"tool": "exiftool", "status": "ok"},
        {"tool": "datcon", "status": "failed"},
    ]
    f1 = _write_timeline(tmp_path, "f01", [], matched=True)
    f2 = _write_timeline(tmp_path, "f02", [], matched=False)
    score = p7._coverage_score(source_cov, artefact_cov, tool_stat, [f1, f2])
    assert score["evidence_sources_detected"] == {"value": 2, "total": 4}
    assert score["artefact_categories_with_data"] == {"value": 1, "total": 2}
    assert score["flights_with_primary_correlation"] == {"value": 1, "total": 2}
    assert score["tools_succeeded"] == {"value": 1, "total": 2}


# ---------------------------------------------------------------------------
# Section 7 — Forensic conclusions
# ---------------------------------------------------------------------------

def _fa(flight_id: str, matched: bool, confidence=None) -> dict:
    return {
        "flight_id": flight_id, "matched": matched,
        "correlation_confidence": confidence,
        "event_count": 5, "high_confidence_event_count": 4,
        "flight_modes_observed": [], "peak_height_m": None,
        "distance_travelled": None, "photo_taken": False, "video_taken": False,
        "source_count": 1, "possibly_correlated_count": 0,
        "plausibly_correlated_count": 0, "corroboration_sources": [],
    }


def test_forensic_flight_count_statement():
    source_cov = [{"source": "controller_android", "detected": True}]
    safe, _ = p7._forensic_conclusions(
        source_cov, [_fa("f01", True, "high"), _fa("f02", True, "medium")], {}, [], []
    )
    assert any("2" in s and "flight" in s for s in safe)


def test_forensic_unmatched_in_further():
    source_cov = [{"source": "controller_android", "detected": True}]
    _, investigate = p7._forensic_conclusions(
        source_cov, [_fa("f01", True, "high"), _fa("f02", False)], {}, [], []
    )
    assert any("f02" in s for s in investigate)


def test_forensic_inconsistent_serial_in_further():
    source_cov = [{"source": "controller_ios", "detected": True}]
    account = {"drone_serial": {
        "value": ["SN001", "SN999"],
        "corroboration_sources": ["p4:abc", "sha:0"],
        "confidence": "inconsistent",
    }}
    _, investigate = p7._forensic_conclusions(source_cov, [], account, [], [])
    assert any("inconsistency" in s for s in investigate)


def test_forensic_multi_source_serial_in_safe():
    source_cov = [{"source": "controller_ios", "detected": True}]
    account = {"drone_serial": {
        "value": "SN001",
        "corroboration_sources": ["p4:abc", "sha004:4"],
        "confidence": "multi-source",
    }}
    safe, _ = p7._forensic_conclusions(source_cov, [], account, [], [])
    assert any("SN001" in s for s in safe)


def test_forensic_db_empty_in_safe():
    source_cov = [{"source": "controller_ios", "detected": True}]
    artefact_cov = [{"category": config.DATABASES, "count": 4,
                     "notes": ["4 database(s) empty (controller_ios)"]}]
    safe, _ = p7._forensic_conclusions(source_cov, [], {}, artefact_cov, [])
    assert any("database" in s and "empty" in s for s in safe)


def test_forensic_installed_dji_apps_in_safe():
    source_cov = [{"source": "controller_android", "detected": True}]
    account = {"installed_dji_apps": {
        "value": ["DJI Go 4", "DJI Fly"],
        "corroboration_sources": ["p2:abc"],
        "confidence": "single-source",
    }}
    safe, _ = p7._forensic_conclusions(source_cov, [], account, [], [])
    assert any("DJI Go 4" in s and "DJI Fly" in s for s in safe)


def test_forensic_installed_dji_apps_inconsistent_omitted():
    source_cov = [{"source": "controller_android", "detected": True}]
    account = {"installed_dji_apps": {
        "value": [["DJI Go 4"], ["DJI Fly"]],
        "corroboration_sources": ["p2:abc", "p2:def"],
        "confidence": "inconsistent",
    }}
    safe, _ = p7._forensic_conclusions(source_cov, [], account, [], [])
    assert not any("Installed DJI" in s for s in safe)


def test_forensic_video_taken_no_info_file():
    source_cov = [{"source": "controller_android", "detected": True}]
    fa = {**_fa("f01", True, "high"), "video_taken": True}
    _, investigate = p7._forensic_conclusions(source_cov, [fa], {}, [], [])
    assert any("video was recorded" in s for s in investigate)
    assert not any(".info" in s for s in investigate)


def test_forensic_video_taken_with_info_file():
    source_cov = [{"source": "controller_android", "detected": True}]
    fa = {**_fa("f01", True, "high"), "video_taken": True}
    info_artefact = {
        "acquisition_method": config.ACQUISITION_SELECT_ACCOUNT_DATA,
        "artefact_category": config.VIDEOS,
    }
    _, investigate = p7._forensic_conclusions(source_cov, [fa], {}, [], [info_artefact])
    assert any("video was recorded" in s and ".info" in s for s in investigate)


def test_forensic_photo_taken():
    source_cov = [{"source": "controller_android", "detected": True}]
    fa = {**_fa("f01", True, "high"), "photo_taken": True}
    _, investigate = p7._forensic_conclusions(source_cov, [fa], {}, [], [])
    assert any("photo was taken" in s for s in investigate)


def test_forensic_no_media_no_items():
    source_cov = [{"source": "controller_android", "detected": True}]
    fa = _fa("f01", True, "high")  # photo_taken=False, video_taken=False
    _, investigate = p7._forensic_conclusions(source_cov, [fa], {}, [], [])
    assert not any("video" in s or "photo" in s for s in investigate)


# ---------------------------------------------------------------------------
# Integration test
# ---------------------------------------------------------------------------

def test_run_phase_7_integration(tmp_path, monkeypatch):
    """Minimal end-to-end: stubbed phase outputs → analysis.json written, state updated."""
    (tmp_path / "Documents").mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(Path, "home", lambda: tmp_path)

    state = State(case_id="CASE-P7-INT", operator="Tester")

    src = tmp_path / "android.zip"
    src.write_bytes(b"x")
    ev = make_evidence(
        source_path=str(src), stored_path=src, parent=None,
        acquisition_method=config.ACQUISITION_LOGICAL,
        type=config.EVIDENCE_TYPE_INPUT,
        source_identification=config.IDENTIFICATION_CONTROLLER_ANDROID,
    )
    state.input_evidence.append(ev)

    fr_sha_p3 = "p3aaaa0000"
    fr_sha_p5 = "p5aaaa0000"

    state.phase_outputs["p2_image_parsing"] = {"derived_observations": []}
    state.phase_outputs["p3_artefact_extraction"] = {
        "extracted_artefacts": [{
            "artefact_category": config.FLIGHT_RECORDS,
            "sha256": fr_sha_p3,
            "parent_sha256": None,
            "source_identification": config.IDENTIFICATION_CONTROLLER_ANDROID,
            "stored_path": str(tmp_path / "fr.txt"),
        }]
    }
    state.phase_outputs["p4_decision_and_orchestration"] = {
        "derived_observations": [],
        "decision_and_orchestration_artefacts": [{
            "sha256": "p4aaaa0000",
            "parent_sha256": fr_sha_p3,
            "artefact_category": config.FLIGHT_RECORDS,
            "source_identification": config.IDENTIFICATION_CONTROLLER_ANDROID,
            "stored_path": str(tmp_path / "fr.csv"),
        }],
    }
    state.phase_outputs["p5_normalisation_and_anomaly_checking"] = {
        "derived_anomalies": [],
        "normalised_artefacts": [{
            "sha256": fr_sha_p5,
            "parent_sha256": "p4aaaa0000",
            "artefact_category": config.FLIGHT_RECORDS,
            "source_identification": config.IDENTIFICATION_CONTROLLER_ANDROID,
            "stored_path": str(tmp_path / "norm_fr.csv"),
        }],
    }

    # P6: flight references the P5 sha
    tl_path = tmp_path / "timeline_flight_01.json"
    tl = {
        "flight_id": "flight_01",
        "flights_identified": [{"evidence_sha256": fr_sha_p5}],
        "correlation_metadata": {"matched": True, "confidence": "high"},
        "plausibly_correlated": [],
        "possibly_correlated": [],
        "events": [{
            "event": "Log started", "confidence": "high",
            "source": "controller_android:flight_records",
            "source_pointer": f"{fr_sha_p5}:0",
            "data": {"latitude": 39.96128, "longitude": -106.21652},
        }],
    }
    tl_path.write_text(json.dumps(tl), encoding="utf-8")
    state.phase_outputs["p6_multisource_correlation"] = {
        "flights": [{
            "flight_id": "flight_01",
            "stored_path": str(tl_path),
            "flights_identified": [{"evidence_sha256": fr_sha_p5}],
            "correlation": {"matched": True, "confidence": "high"},
            "plausibly_correlated": [],
            "possibly_correlated": [],
        }],
        "flight_count": 1,
    }

    result_state = p7.run_phase_7(state)

    p7_out = result_state.phase_outputs["p7_analysis_and_validation"]

    # No separate file — all data lives in state
    assert "stored_path" not in p7_out

    assert "account_and_drone_analysis" in p7_out
    assert "data_quality" not in p7_out
    assert "serial_cross_check" not in p7_out
    assert "account_analysis" not in p7_out
    assert "safe_statements" in p7_out
    assert "further_investigation" in p7_out
    assert len(p7_out["flight_analyses"]) == 1

    # Chain-walking: P3 sha → P4 sha → P5 sha (referenced in P6) → NOT uncorrelated
    assert p7_out["uncorrelated_artefacts"] == []

    # New flight analysis fields present
    fa = p7_out["flight_analyses"][0]
    assert "distance_travelled" in fa
    assert "photo_taken" in fa
    assert "video_taken" in fa

    assert "p7_analysis_and_validation" in result_state.completed_phases
