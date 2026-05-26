from __future__ import annotations

import subprocess
import zipfile
from pathlib import Path

import config
from config import (
    ACCOUNT_DATA,
    DATABASES,
    DRONE_LOGS,
    FLIGHT_LOGS,
    FLIGHT_RECORDS,
    IMAGES,
    VIDEOS,
    DEVICE_AND_BACKUP_INFO,
)
from evidence import Evidence, make_evidence
from phases import p3_artefact_extraction as p3
from state import State


def _write_zip(zip_path: Path, members: dict[str, bytes | str]) -> None:
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, payload in members.items():
            data = payload.encode("utf-8") if isinstance(payload, str) else payload
            archive.writestr(name, data)


def _build_state(tmp_path: Path, case_id: str) -> State:
    state = State(case_id=case_id, operator="Tester")
    state.phase_outputs["p1_provenance"] = {"identified_evidence": []}
    return state


def _write_backup_info(tmp_path: Path, case_id: str, installed_apps: list) -> None:
    import json
    p2_dir = tmp_path / "Documents" / "dfdof_output" / case_id / "p2_image_parsing" / "controller_android_parsed"
    p2_dir.mkdir(parents=True, exist_ok=True)
    (p2_dir / "backup_info.json").write_text(
        json.dumps({"Installed Applications": installed_apps}), encoding="utf-8"
    )


# ---------------------------------------------------------------------------
# Android logical extraction
# ---------------------------------------------------------------------------

def test_run_phase_3_android_logical(tmp_path: Path, monkeypatch) -> None:
    """Android ZIP with all artefact categories under a discovered DJI scope root."""
    project_root = tmp_path
    (project_root / "Documents").mkdir(parents=True)
    monkeypatch.setattr(Path, "home", lambda: project_root)

    _write_backup_info(tmp_path, "CASE-P3-1", ["dji.go.v4"])

    android_zip = tmp_path / "android_backup.zip"
    # All paths are inside a dji.go.v4 scope root so _android_discover_scope_roots
    # will return that scope and category_roots will be constructed from it.
    _write_zip(
        android_zip,
        {
            "data/dji.go.v4/FlightRecord/record1.txt": "flight record",
            "data/dji.go.v4/LOG/LOG1.txt": "flight log",
            "data/dji.go.v4/FlightRecord/MCDatFlightRecords/LOG.DAT": "dat log",
            "data/dji.go.v4/CACHE_IMAGE/img1.jpg": "image",
            "data/dji.go.v4/DJI_RECORD/video1.mp4": "video",
            "data/dji.go.v4/shared_prefs/dji.go.v4.xml": "prefs",
            "data/dji.go.v4/databases/djiFMDB.db": "db",
            "data/dji.go.v4/databases/other.db": "db2",
        },
    )

    state = _build_state(tmp_path, "CASE-P3-1")
    android_evidence = make_evidence(
        source_path=android_zip,
        stored_path=android_zip,
        parent=None,
        acquisition_method=config.ACQUISITION_LOGICAL,
        type=config.EVIDENCE_TYPE_INPUT,
        source_identification=config.IDENTIFICATION_CONTROLLER_ANDROID,
        skip_hash=True,
    )
    state.input_evidence.append(android_evidence)

    result = p3.run_phase_3(state)
    phase_output = result.phase_outputs["p3_artefact_extraction"]
    artefacts = phase_output["extracted_artefacts"]
    categories = [item["artefact_category"] for item in artefacts]

    assert DRONE_LOGS in categories
    assert FLIGHT_RECORDS in categories
    assert FLIGHT_LOGS in categories
    assert IMAGES in categories
    assert VIDEOS in categories
    assert ACCOUNT_DATA in categories
    assert DATABASES in categories


def test_run_phase_3_android_logical_no_installed_apps_raises_anomaly(
    tmp_path: Path, monkeypatch
) -> None:
    """No installed apps in P2 output → anomaly, no extraction."""
    project_root = tmp_path
    (project_root / "Documents").mkdir(parents=True)
    monkeypatch.setattr(Path, "home", lambda: project_root)

    # backup_info.json with empty installed apps list
    _write_backup_info(tmp_path, "CASE-NOAPP", [])

    android_zip = tmp_path / "android_backup.zip"
    _write_zip(android_zip, {"data/dji.go.v4/LOG/log.txt": "log"})

    state = _build_state(tmp_path, "CASE-NOAPP")
    android_evidence = make_evidence(
        source_path=android_zip,
        stored_path=android_zip,
        parent=None,
        acquisition_method=config.ACQUISITION_LOGICAL,
        type=config.EVIDENCE_TYPE_INPUT,
        source_identification=config.IDENTIFICATION_CONTROLLER_ANDROID,
        skip_hash=True,
    )
    state.input_evidence.append(android_evidence)

    result = p3.run_phase_3(state)
    artefacts = result.phase_outputs["p3_artefact_extraction"]["extracted_artefacts"]
    assert artefacts == []
    assert any("installed DJI apps not found" in flag for flag in result.anomaly_flags)


def test_run_phase_3_android_logical_no_scope_root_raises_anomaly(
    tmp_path: Path, monkeypatch
) -> None:
    """Installed apps present but no matching paths in archive → anomaly, no extraction."""
    project_root = tmp_path
    (project_root / "Documents").mkdir(parents=True)
    monkeypatch.setattr(Path, "home", lambda: project_root)

    _write_backup_info(tmp_path, "CASE-NOSCOPE", ["dji.go.v4"])

    android_zip = tmp_path / "android_backup.zip"
    # Archive contains no dji.go.v4 path segment
    _write_zip(android_zip, {"other_app/LOG/log.txt": "log"})

    state = _build_state(tmp_path, "CASE-NOSCOPE")
    android_evidence = make_evidence(
        source_path=android_zip,
        stored_path=android_zip,
        parent=None,
        acquisition_method=config.ACQUISITION_LOGICAL,
        type=config.EVIDENCE_TYPE_INPUT,
        source_identification=config.IDENTIFICATION_CONTROLLER_ANDROID,
        skip_hash=True,
    )
    state.input_evidence.append(android_evidence)

    result = p3.run_phase_3(state)
    artefacts = result.phase_outputs["p3_artefact_extraction"]["extracted_artefacts"]
    assert artefacts == []
    assert any("no DJI app directories found" in flag for flag in result.anomaly_flags)


def test_run_phase_3_android_logical_skips_empty_files(tmp_path: Path, monkeypatch) -> None:
    project_root = tmp_path
    (project_root / "Documents").mkdir(parents=True)
    monkeypatch.setattr(Path, "home", lambda: project_root)

    _write_backup_info(tmp_path, "CASE-P3-EMPTY", ["dji.go.v4"])

    android_zip = tmp_path / "android_backup.zip"
    _write_zip(
        android_zip,
        {
            "data/dji.go.v4/FlightRecord/record1.txt": "flight record",
            "data/dji.go.v4/LOG/sys_log_empty.txt": b"",
            "data/dji.go.v4/databases/djiFMDB.db": "db",
        },
    )

    state = _build_state(tmp_path, "CASE-P3-EMPTY")
    android_evidence = make_evidence(
        source_path=android_zip,
        stored_path=android_zip,
        parent=None,
        acquisition_method=config.ACQUISITION_LOGICAL,
        type=config.EVIDENCE_TYPE_INPUT,
        source_identification=config.IDENTIFICATION_CONTROLLER_ANDROID,
        skip_hash=True,
    )
    state.input_evidence.append(android_evidence)

    result = p3.run_phase_3(state)
    artefacts = result.phase_outputs["p3_artefact_extraction"]["extracted_artefacts"]
    stored_names = [Path(item["stored_path"]).name for item in artefacts]
    assert "sys_log_empty.txt" not in stored_names
    assert any("empty file moved to _rejected" in flag for flag in result.anomaly_flags)


def test_run_phase_3_android_logical_extracts_same_basename_from_different_paths(
    tmp_path: Path, monkeypatch
) -> None:
    """Same basename at two different category paths must both be extracted."""
    project_root = tmp_path
    (project_root / "Documents").mkdir(parents=True)
    monkeypatch.setattr(Path, "home", lambda: project_root)

    _write_backup_info(tmp_path, "CASE-P3-DEDUP", ["com.dji.go"])

    android_zip = tmp_path / "android_backup.zip"
    _write_zip(
        android_zip,
        {
            "data/data/com.dji.go/db/djiFMDB.db": "db content first",
            "data/data/com.dji.go/files/djiFMDB.db": "db content second",
        },
    )

    state = _build_state(tmp_path, "CASE-P3-DEDUP")
    android_evidence = make_evidence(
        source_path=android_zip,
        stored_path=android_zip,
        parent=None,
        acquisition_method=config.ACQUISITION_LOGICAL,
        type=config.EVIDENCE_TYPE_INPUT,
        source_identification=config.IDENTIFICATION_CONTROLLER_ANDROID,
        skip_hash=True,
    )
    state.input_evidence.append(android_evidence)

    result = p3.run_phase_3(state)
    artefacts = result.phase_outputs["p3_artefact_extraction"]["extracted_artefacts"]
    db_artefacts = [item for item in artefacts if item["artefact_category"] == DATABASES]
    assert len(db_artefacts) == 2
    db_names = {Path(item["stored_path"]).name for item in db_artefacts}
    assert "djiFMDB.db" in db_names
    assert "djiFMDB_1.db" in db_names


def test_run_phase_3_android_no_empty_output_dirs(tmp_path: Path, monkeypatch) -> None:
    """Category output dirs must not exist if no artefacts were extracted for that category."""
    project_root = tmp_path
    (project_root / "Documents").mkdir(parents=True)
    monkeypatch.setattr(Path, "home", lambda: project_root)

    _write_backup_info(tmp_path, "CASE-EMPTY-DIR", ["dji.go.v4"])

    android_zip = tmp_path / "android_backup.zip"
    _write_zip(
        android_zip,
        {
            # Only flight_logs — no flight_records, images, videos, databases
            "data/dji.go.v4/LOG/log1.txt": "log content",
        },
    )

    state = _build_state(tmp_path, "CASE-EMPTY-DIR")
    android_evidence = make_evidence(
        source_path=android_zip,
        stored_path=android_zip,
        parent=None,
        acquisition_method=config.ACQUISITION_LOGICAL,
        type=config.EVIDENCE_TYPE_INPUT,
        source_identification=config.IDENTIFICATION_CONTROLLER_ANDROID,
        skip_hash=True,
    )
    state.input_evidence.append(android_evidence)

    p3.run_phase_3(state)

    output_root = (
        tmp_path / "Documents" / "dfdof_output" / "CASE-EMPTY-DIR"
        / "p3_artefact_extraction" / "controller_android"
    )
    assert not (output_root / "flight_records").exists()
    assert not (output_root / "images").exists()
    assert not (output_root / "videos").exists()
    assert not (output_root / "databases").exists()
    assert (output_root / "flight_logs").exists()


def test_run_phase_3_empty_file_leaves_no_empty_dir(tmp_path: Path, monkeypatch) -> None:
    """When all files in a category are rejected as empty, the category dir must not remain."""
    project_root = tmp_path
    (project_root / "Documents").mkdir(parents=True)
    monkeypatch.setattr(Path, "home", lambda: project_root)

    _write_backup_info(tmp_path, "CASE-REJECTED-DIR", ["dji.go.v4"])

    android_zip = tmp_path / "android_backup.zip"
    _write_zip(
        android_zip,
        {
            "data/dji.go.v4/LOG/empty.txt": b"",
        },
    )

    state = _build_state(tmp_path, "CASE-REJECTED-DIR")
    android_evidence = make_evidence(
        source_path=android_zip,
        stored_path=android_zip,
        parent=None,
        acquisition_method=config.ACQUISITION_LOGICAL,
        type=config.EVIDENCE_TYPE_INPUT,
        source_identification=config.IDENTIFICATION_CONTROLLER_ANDROID,
        skip_hash=True,
    )
    state.input_evidence.append(android_evidence)

    p3.run_phase_3(state)

    output_root = (
        tmp_path / "Documents" / "dfdof_output" / "CASE-REJECTED-DIR"
        / "p3_artefact_extraction" / "controller_android"
    )
    assert not (output_root / "flight_logs").exists()
    assert any("empty file moved to _rejected" in flag for flag in state.anomaly_flags)


# ---------------------------------------------------------------------------
# Android physical extraction
# ---------------------------------------------------------------------------

def test_run_phase_3_android_physical_filters_extensions(
    tmp_path: Path, monkeypatch
) -> None:
    project_root = tmp_path
    (project_root / "Documents").mkdir(parents=True)
    monkeypatch.setattr(Path, "home", lambda: project_root)

    android_image = tmp_path / "android_image.E01"
    android_image.write_bytes(b"image")

    state = _build_state(tmp_path, "CASE-P3-4")
    android_evidence = make_evidence(
        source_path=android_image,
        stored_path=android_image,
        parent=None,
        acquisition_method=config.ACQUISITION_PHYSICAL,
        type=config.EVIDENCE_TYPE_INPUT,
        source_identification=config.IDENTIFICATION_CONTROLLER_ANDROID,
        skip_hash=True,
    )
    state.input_evidence.append(android_evidence)

    def fake_extract_tsk_image(*_args, **kwargs):
        working_dir = Path(kwargs.get("working_dir") or _args[1])
        working_dir.mkdir(parents=True, exist_ok=True)
        category = kwargs.get("artefact_category")
        evidence_items: list[Evidence] = []
        if category == DATABASES:
            db_a = working_dir / "djiFMDB.db"
            db_b = working_dir / "other.db"
            bad_ext = working_dir / "config.xml"
            db_a.write_text("db", encoding="utf-8")
            db_b.write_text("db", encoding="utf-8")
            bad_ext.write_text("xml", encoding="utf-8")
            evidence_items.extend(
                [
                    make_evidence(
                        source_path=db_a.name,
                        stored_path=db_a,
                        parent=android_evidence,
                        acquisition_method=config.ACQUISITION_EXTRACT_PHYSICAL,
                        type=config.EVIDENCE_TYPE_EXTRACTED,
                        artefact_category=category,
                    ),
                    make_evidence(
                        source_path=db_b.name,
                        stored_path=db_b,
                        parent=android_evidence,
                        acquisition_method=config.ACQUISITION_EXTRACT_PHYSICAL,
                        type=config.EVIDENCE_TYPE_EXTRACTED,
                        artefact_category=category,
                    ),
                    make_evidence(
                        source_path=bad_ext.name,
                        stored_path=bad_ext,
                        parent=android_evidence,
                        acquisition_method=config.ACQUISITION_EXTRACT_PHYSICAL,
                        type=config.EVIDENCE_TYPE_EXTRACTED,
                        artefact_category=category,
                    ),
                ]
            )
        elif category == DRONE_LOGS:
            good_dat = working_dir / "LOG.DAT"
            bad_bin = working_dir / "LOG.bin"
            good_dat.write_text("dat", encoding="utf-8")
            bad_bin.write_text("bin", encoding="utf-8")
            evidence_items.extend(
                [
                    make_evidence(
                        source_path=good_dat.name,
                        stored_path=good_dat,
                        parent=android_evidence,
                        acquisition_method=config.ACQUISITION_EXTRACT_PHYSICAL,
                        type=config.EVIDENCE_TYPE_EXTRACTED,
                        artefact_category=category,
                    ),
                    make_evidence(
                        source_path=bad_bin.name,
                        stored_path=bad_bin,
                        parent=android_evidence,
                        acquisition_method=config.ACQUISITION_EXTRACT_PHYSICAL,
                        type=config.EVIDENCE_TYPE_EXTRACTED,
                        artefact_category=category,
                    ),
                ]
            )
        return evidence_items

    monkeypatch.setattr(p3, "extract_tsk_image", fake_extract_tsk_image)

    result = p3.run_phase_3(state)
    artefacts = result.phase_outputs["p3_artefact_extraction"]["extracted_artefacts"]
    stored_names = {Path(item["stored_path"]).name for item in artefacts}
    assert "djiFMDB.db" in stored_names
    assert "other.db" in stored_names
    assert "config.xml" not in stored_names
    assert "LOG.DAT" in stored_names
    assert "LOG.bin" not in stored_names


# ---------------------------------------------------------------------------
# Android scope root discovery
# ---------------------------------------------------------------------------

def test_android_discover_scope_roots() -> None:
    members = [
        "Media01/userdata/data/dji.go.v4/FlightRecords/record.txt",
        "Media01/sdcard/DJI/dji.go.v4/CACHE_IMAGE/img.jpg",
        "Media01/userdata/data/com.other.app/something.xml",
    ]
    roots = p3._android_discover_scope_roots(members, ["dji.go.v4"])
    assert "media01/userdata/data/dji.go.v4/" in roots
    assert "media01/sdcard/dji/dji.go.v4/" in roots
    assert len(roots) == 2


# ---------------------------------------------------------------------------
# iOS extraction — root discovery and category collection
# ---------------------------------------------------------------------------

def test_ios_discover_app_roots(tmp_path: Path) -> None:
    """AppDomain-com.dji.go is discovered; non-DJI and non-domain dirs are ignored."""
    domains = tmp_path / "domains"
    dji_dir = domains / "AppDomain-com.dji.go"
    other_dir = domains / "AppDomain-com.other.app"
    group_dir = domains / "AppDomainGroup-dji.pilot"
    plain_dir = domains / "SystemPreferencesDomain"
    for d in (dji_dir, other_dir, group_dir, plain_dir):
        d.mkdir(parents=True)

    roots = p3._ios_discover_app_roots(tmp_path)
    root_names = {r.name for r in roots}
    assert "AppDomain-com.dji.go" in root_names
    assert "AppDomainGroup-dji.pilot" in root_names
    assert "AppDomain-com.other.app" not in root_names
    assert "SystemPreferencesDomain" not in root_names


def test_ios_discover_app_roots_no_domains_dir(tmp_path: Path) -> None:
    """Missing domains/ directory → empty list."""
    roots = p3._ios_discover_app_roots(tmp_path)
    assert roots == []


def test_ios_collect_category_files(tmp_path: Path) -> None:
    """Files in the exact category directory are collected; files elsewhere are not."""
    app_root = tmp_path / "AppDomain-com.dji.go"
    # FLIGHT_RECORDS token is "Documents/FlightRecords/"
    flight_records_dir = app_root / "Documents" / "FlightRecords"
    flight_records_dir.mkdir(parents=True)
    valid_file = flight_records_dir / "flight.txt"
    valid_file.write_text("data")
    # file with wrong extension in the right dir — should NOT be collected
    bad_ext = flight_records_dir / "flight.db"
    bad_ext.write_text("data")
    # file in a sibling dir — should NOT be collected for FLIGHT_RECORDS
    other_dir = app_root / "Documents" / "videoCache"
    other_dir.mkdir()
    (other_dir / "doc.txt").write_text("other")

    matched = p3._ios_collect_category_files([app_root], config.FLIGHT_RECORDS)
    assert valid_file in matched
    assert bad_ext not in matched
    assert len(matched) == 1


def test_ios_collect_category_files_nested(tmp_path: Path) -> None:
    """Files nested inside a category directory at any depth are all collected."""
    app_root = tmp_path / "AppDomain-dji.pilot"
    # DATABASES token is "Documents/" and "Library/"
    docs_dir = app_root / "Documents"
    nested = docs_dir / "sub" / "deep"
    nested.mkdir(parents=True)
    f1 = docs_dir / "main.db"
    f2 = nested / "nested.db"
    f1.write_text("db1")
    f2.write_text("db2")

    matched = p3._ios_collect_category_files([app_root], config.DATABASES)
    assert f1 in matched
    assert f2 in matched


def test_run_phase_3_ios_parsed_files(tmp_path: Path, monkeypatch) -> None:
    project_root = tmp_path
    (project_root / "Documents").mkdir(parents=True)
    monkeypatch.setattr(Path, "home", lambda: project_root)

    ios_zip = tmp_path / "ios_backup.zip"
    ios_zip.write_bytes(b"ios backup")

    ios_parsed_root = (
        project_root
        / "Documents"
        / "dfdof_output"
        / "CASE-P3-2"
        / "p2_image_parsing"
        / "controller_ios_parsed"
    )
    # Build the expected domain directory structure
    app_dir = ios_parsed_root / "domains" / "AppDomain-com.dji.go"
    flight_record = app_dir / "Documents" / "FlightRecords" / "record1.txt"
    flight_record.parent.mkdir(parents=True, exist_ok=True)
    flight_record.write_text("flight record", encoding="utf-8")

    account_plist = app_dir / "Library" / "Preferences" / "com.dji.go.plist"
    account_plist.parent.mkdir(parents=True, exist_ok=True)
    account_plist.write_text("plist", encoding="utf-8")

    state = _build_state(tmp_path, "CASE-P3-2")
    ios_evidence = make_evidence(
        source_path=ios_zip,
        stored_path=ios_zip,
        parent=None,
        acquisition_method=config.ACQUISITION_LOGICAL,
        type=config.EVIDENCE_TYPE_INPUT,
        source_identification=config.IDENTIFICATION_CONTROLLER_IOS,
        skip_hash=True,
    )
    state.input_evidence.append(ios_evidence)
    state.phase_outputs["p2_image_parsing"] = {
        "parsed_evidence": [
            {
                "source_path": str(ios_zip),
                "stored_path": str(ios_parsed_root),
                "artefact_category": DEVICE_AND_BACKUP_INFO,
            }
        ]
    }

    result = p3.run_phase_3(state)
    artefacts = result.phase_outputs["p3_artefact_extraction"]["extracted_artefacts"]
    categories = {item["artefact_category"] for item in artefacts}
    assert FLIGHT_RECORDS in categories
    assert ACCOUNT_DATA in categories


def test_run_phase_3_ios_no_dji_roots_raises_anomaly(tmp_path: Path, monkeypatch) -> None:
    """Parsed iOS backup with no DJI app domains → anomaly, no extraction."""
    project_root = tmp_path
    (project_root / "Documents").mkdir(parents=True)
    monkeypatch.setattr(Path, "home", lambda: project_root)

    ios_zip = tmp_path / "ios_backup.zip"
    ios_zip.write_bytes(b"ios backup")

    ios_parsed_root = (
        project_root / "Documents" / "dfdof_output" / "CASE-NOIOS"
        / "p2_image_parsing" / "controller_ios_parsed"
    )
    # Create a domains/ dir with only non-DJI entries
    (ios_parsed_root / "domains" / "AppDomain-com.other.app").mkdir(parents=True)

    state = _build_state(tmp_path, "CASE-NOIOS")
    ios_evidence = make_evidence(
        source_path=ios_zip,
        stored_path=ios_zip,
        parent=None,
        acquisition_method=config.ACQUISITION_LOGICAL,
        type=config.EVIDENCE_TYPE_INPUT,
        source_identification=config.IDENTIFICATION_CONTROLLER_IOS,
        skip_hash=True,
    )
    state.input_evidence.append(ios_evidence)
    state.phase_outputs["p2_image_parsing"] = {
        "parsed_evidence": [
            {
                "source_path": str(ios_zip),
                "stored_path": str(ios_parsed_root),
                "artefact_category": DEVICE_AND_BACKUP_INFO,
            }
        ]
    }

    result = p3.run_phase_3(state)
    artefacts = result.phase_outputs["p3_artefact_extraction"]["extracted_artefacts"]
    assert artefacts == []
    assert any("no DJI app directories found" in flag for flag in result.anomaly_flags)


# ---------------------------------------------------------------------------
# Drone SD
# ---------------------------------------------------------------------------

def test_run_phase_3_drone_sd_physical_single_pass(tmp_path: Path, monkeypatch) -> None:
    project_root = tmp_path
    (project_root / "Documents").mkdir(parents=True)
    monkeypatch.setattr(Path, "home", lambda: project_root)

    sd_image = tmp_path / "drone_sd.E01"
    sd_image.write_bytes(b"image")

    state = _build_state(tmp_path, "CASE-P3-5")
    sd_evidence = make_evidence(
        source_path=sd_image,
        stored_path=sd_image,
        parent=None,
        acquisition_method=config.ACQUISITION_PHYSICAL,
        type=config.EVIDENCE_TYPE_INPUT,
        source_identification=config.IDENTIFICATION_DRONE_SD,
        skip_hash=True,
    )
    state.input_evidence.append(sd_evidence)
    state.phase_outputs["p1_provenance"]["image_metadata"] = {
        str(sd_image.name): {
            "offset_sectors": None,
            "entries": [
                {"kind": "r/r", "inode": 10, "path": "DCIM/100MEDIA/DJI_0001.MP4"},
                {"kind": "r/r", "inode": 11, "path": "MISC/THM/100/DJI_0001.THM"},
                {"kind": "r/r", "inode": 12, "path": "OTHER/skip.bin"},
            ],
        }
    }

    call_inodes: list[int] = []

    def fake_run_command(command, capture_output=True, stdout=None):
        call_inodes.append(int(command[-1]))
        if stdout is not None:
            stdout.write(b"data")
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    monkeypatch.setattr(p3, "run_command", fake_run_command)

    result = p3.run_phase_3(state)
    artefacts = result.phase_outputs["p3_artefact_extraction"]["extracted_artefacts"]
    stored_names = {Path(item["stored_path"]).name for item in artefacts}
    assert "DJI_0001.MP4" in stored_names
    assert "DJI_0001.THM" in stored_names
    assert call_inodes.count(10) == 1
    assert call_inodes.count(11) == 1


# ---------------------------------------------------------------------------
# Drone flight storage
# ---------------------------------------------------------------------------

def test_run_phase_3_drone_flight_storage_flat_dat(tmp_path: Path, monkeypatch) -> None:
    project_root = tmp_path
    (project_root / "Documents").mkdir(parents=True)
    monkeypatch.setattr(Path, "home", lambda: project_root)

    flight_zip = tmp_path / "flight_storage.zip"
    _write_zip(
        flight_zip,
        {
            "FLY001.DAT": "dat",
            "note.txt": "note",
        },
    )

    state = _build_state(tmp_path, "CASE-P3-3")
    flight_evidence = make_evidence(
        source_path=flight_zip,
        stored_path=flight_zip,
        parent=None,
        acquisition_method=config.ACQUISITION_LOGICAL,
        type=config.EVIDENCE_TYPE_INPUT,
        source_identification=config.IDENTIFICATION_DRONE_FLIGHT_STORAGE,
        skip_hash=True,
    )
    state.input_evidence.append(flight_evidence)

    result = p3.run_phase_3(state)
    artefacts = result.phase_outputs["p3_artefact_extraction"]["extracted_artefacts"]
    assert any(item["artefact_category"] == DRONE_LOGS for item in artefacts)
    assert not any("drone flight storage" in flag for flag in result.anomaly_flags)


def test_run_phase_3_drone_flight_storage_export_dat(tmp_path: Path, monkeypatch) -> None:
    project_root = tmp_path
    (project_root / "Documents").mkdir(parents=True)
    monkeypatch.setattr(Path, "home", lambda: project_root)

    flight_zip = tmp_path / "flight_storage.zip"
    _write_zip(
        flight_zip,
        {
            "DJI_ASSISTANT_EXPORT_FILE_001.DAT": "export dat",
            "note.txt": "note",
        },
    )

    state = _build_state(tmp_path, "CASE-P3-3B")
    flight_evidence = make_evidence(
        source_path=flight_zip,
        stored_path=flight_zip,
        parent=None,
        acquisition_method=config.ACQUISITION_LOGICAL,
        type=config.EVIDENCE_TYPE_INPUT,
        source_identification=config.IDENTIFICATION_DRONE_FLIGHT_STORAGE,
        skip_hash=True,
    )
    state.input_evidence.append(flight_evidence)

    result = p3.run_phase_3(state)
    artefacts = result.phase_outputs["p3_artefact_extraction"]["extracted_artefacts"]
    assert any(item["artefact_category"] == DRONE_LOGS for item in artefacts)
    assert any("ASSISTANT_EXPORT" in item["source_path"].upper() for item in artefacts)
    assert not any("drone flight storage" in flag for flag in result.anomaly_flags)


# ---------------------------------------------------------------------------
# Integration
# ---------------------------------------------------------------------------

def test_p1_p2_p3_android_integration(tmp_path: Path, monkeypatch) -> None:
    project_root = tmp_path
    (project_root / "Documents").mkdir(parents=True)
    monkeypatch.setattr(Path, "home", lambda: project_root)

    ev_dir = tmp_path / "evidence"
    ev_dir.mkdir()
    android_zip = ev_dir / "android_backup.zip"
    _write_zip(
        android_zip,
        {
            "data/data/com.dji.go/shared_prefs/dji.go.v4.xml": "<map/>",
            "data/data/com.dji.go/FlightRecords/flight.txt": "flight data",
        },
    )

    state = State(case_id="INTEG-01", operator="Tester", evidence_directory=str(ev_dir))

    from phases.p1_provenance import run_phase_1
    from phases.p2_image_parsing import run_phase_2
    from phases.p3_artefact_extraction import run_phase_3
    from parsing.parser_android import AndroidParserResult

    def fake_parse_android(source_ev, output_root, state):
        import json
        output_root.mkdir(parents=True, exist_ok=True)
        (output_root / "backup_info.json").write_text(
            json.dumps({"Installed Applications": ["com.dji.go"]}), encoding="utf-8"
        )
        return AndroidParserResult(output_root=output_root, parsed_evidence=[], observations=[])

    monkeypatch.setattr("phases.p2_image_parsing.parse_android_source", fake_parse_android)

    state = run_phase_1(state, confirm_all=True)
    state = run_phase_2(state)
    state = run_phase_3(state)

    assert "p1_provenance" in state.phase_outputs
    assert "p2_image_parsing" in state.phase_outputs
    assert "p3_artefact_extraction" in state.phase_outputs
    assert isinstance(state.phase_outputs["p3_artefact_extraction"]["extracted_artefacts"], list)
