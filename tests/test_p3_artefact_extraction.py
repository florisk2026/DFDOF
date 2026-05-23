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


def test_run_phase_3_android_logical(tmp_path: Path, monkeypatch) -> None:
    project_root = tmp_path
    documents_dir = project_root / "Documents"
    documents_dir.mkdir(parents=True)
    monkeypatch.setattr(Path, "home", lambda: project_root)

    android_zip = tmp_path / "android_backup.zip"
    _write_zip(
        android_zip,
        {
            "DJI/FlightRecords/record1.txt": "flight record",
            "DJI/FlightLogs/LOG1.TXT": "flight log",
            "DJI/FlightRecords/MCDatFlightRecords/LOG.DAT": "dat log",
            "DJI/CACHE_IMAGE/img1.jpg": "image",
            "DJI/DJI_RECORD/video1.MP4": "video",
            "data/data/com.dji.go/shared_prefs/dji.go.v4.xml": "prefs",
            "data/data/com.dji.go/db/djiFMDB.db": "db",
            "data/data/com.dji.go/db/other.db": "db2",
        },
    )

    state = _build_state(tmp_path, "CASE-P3-1")
    android_evidence = make_evidence(
        source_path=android_zip,
        stored_path=android_zip,
        parent=None,
        acquisition_method=config.ACQUISITION_LOGICAL,
        type=config.EVIDENCE_TYPE_INPUT,
        skip_hash=True,
    )
    state.input_evidence.append(android_evidence)
    state.phase_outputs["p1_provenance"]["identified_evidence"] = [
        {
            "source_path": str(android_zip),
            "identified": True,
            "identified_as": "controller_android",
            "operator_confirmed": True,
            "identified_by_operator_as": None,
        },
    ]

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
    assert all(
        item["artefact_category"] != DATABASES or "other.db" not in item["stored_path"]
        for item in artefacts
    )


def test_run_phase_3_ios_parsed_files(tmp_path: Path, monkeypatch) -> None:
    project_root = tmp_path
    documents_dir = project_root / "Documents"
    documents_dir.mkdir(parents=True)
    monkeypatch.setattr(Path, "home", lambda: project_root)

    ios_zip = tmp_path / "ios_backup.zip"
    ios_zip.write_bytes(b"ios backup")

    ios_parsed_root = (
        documents_dir
        / "dfdof_output"
        / "CASE-P3-2"
        / "p2_image_parsing"
        / "controller_ios_parsed"
    )
    ios_parsed_root.mkdir(parents=True, exist_ok=True)
    flight_record = (
        ios_parsed_root
        / "domains"
        / "AppDomain-com.dji.go"
        / "Documents"
        / "FlightRecords"
        / "record1.txt"
    )
    flight_record.parent.mkdir(parents=True, exist_ok=True)
    flight_record.write_text("flight record", encoding="utf-8")
    account_plist = (
        ios_parsed_root
        / "domains"
        / "AppDomain-com.dji.go"
        / "Library"
        / "Preferences"
        / "com.dji.go.plist"
    )
    account_plist.parent.mkdir(parents=True, exist_ok=True)
    account_plist.write_text("plist", encoding="utf-8")

    state = _build_state(tmp_path, "CASE-P3-2")
    ios_evidence = make_evidence(
        source_path=ios_zip,
        stored_path=ios_zip,
        parent=None,
        acquisition_method=config.ACQUISITION_LOGICAL,
        type=config.EVIDENCE_TYPE_INPUT,
        skip_hash=True,
    )
    state.input_evidence.append(ios_evidence)
    state.phase_outputs["p1_provenance"]["identified_evidence"] = [
        {
            "source_path": str(ios_zip),
            "identified": True,
            "identified_as": "controller_ios",
            "operator_confirmed": True,
            "identified_by_operator_as": None,
        }
    ]
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


def test_run_phase_3_drone_flight_storage_flat_dat(tmp_path: Path, monkeypatch) -> None:
    project_root = tmp_path
    documents_dir = project_root / "Documents"
    documents_dir.mkdir(parents=True)
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
        skip_hash=True,
    )
    state.input_evidence.append(flight_evidence)
    state.phase_outputs["p1_provenance"]["identified_evidence"] = [
        {
            "source_path": str(flight_zip),
            "identified": True,
            "identified_as": "drone_flight_storage",
            "operator_confirmed": True,
            "identified_by_operator_as": None,
        }
    ]

    result = p3.run_phase_3(state)
    artefacts = result.phase_outputs["p3_artefact_extraction"]["extracted_artefacts"]
    assert any(item["artefact_category"] == DRONE_LOGS for item in artefacts)
    assert not any("drone flight storage" in flag for flag in result.anomaly_flags)


def test_run_phase_3_drone_flight_storage_export_dat(tmp_path: Path, monkeypatch) -> None:
    project_root = tmp_path
    documents_dir = project_root / "Documents"
    documents_dir.mkdir(parents=True)
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
        skip_hash=True,
    )
    state.input_evidence.append(flight_evidence)
    state.phase_outputs["p1_provenance"]["identified_evidence"] = [
        {
            "source_path": str(flight_zip),
            "identified": True,
            "identified_as": "drone_flight_storage",
            "operator_confirmed": True,
            "identified_by_operator_as": None,
        }
    ]

    result = p3.run_phase_3(state)
    artefacts = result.phase_outputs["p3_artefact_extraction"]["extracted_artefacts"]
    assert any(item["artefact_category"] == DRONE_LOGS for item in artefacts)
    assert any("ASSISTANT_EXPORT" in item["source_path"].upper() for item in artefacts)
    assert not any("drone flight storage" in flag for flag in result.anomaly_flags)


def test_run_phase_3_android_physical_filters_extensions(
    tmp_path: Path, monkeypatch
) -> None:
    project_root = tmp_path
    documents_dir = project_root / "Documents"
    documents_dir.mkdir(parents=True)
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
        skip_hash=True,
    )
    state.input_evidence.append(android_evidence)
    state.phase_outputs["p1_provenance"]["identified_evidence"] = [
        {
            "source_path": str(android_image),
            "identified": True,
            "identified_as": "controller_android",
            "operator_confirmed": True,
            "identified_by_operator_as": None,
        }
    ]

    def fake_extract_tsk_image(*_args, **kwargs):
        working_dir = Path(kwargs.get("working_dir") or _args[1])
        _ = kwargs.get("state")
        working_dir.mkdir(parents=True, exist_ok=True)
        category = kwargs.get("artefact_category")
        evidence_items: list[Evidence] = []
        if category == DATABASES:
            good_db = working_dir / "djiFMDB.db"
            bad_db = working_dir / "other.db"
            good_db.write_text("db", encoding="utf-8")
            bad_db.write_text("db", encoding="utf-8")
            evidence_items.extend(
                [
                    make_evidence(
                        source_path=good_db.name,
                        stored_path=good_db,
                        parent=android_evidence,
                        acquisition_method=config.ACQUISITION_EXTRACT_PHYSICAL,
                        type=config.EVIDENCE_TYPE_EXTRACTED,
                        artefact_category=category,
                    ),
                    make_evidence(
                        source_path=bad_db.name,
                        stored_path=bad_db,
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
    assert "other.db" not in stored_names
    assert "LOG.DAT" in stored_names
    assert "LOG.bin" not in stored_names


def test_run_phase_3_drone_sd_physical_single_pass(tmp_path: Path, monkeypatch) -> None:
    project_root = tmp_path
    documents_dir = project_root / "Documents"
    documents_dir.mkdir(parents=True)
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
        skip_hash=True,
    )
    state.input_evidence.append(sd_evidence)
    state.phase_outputs["p1_provenance"]["identified_evidence"] = [
        {
            "source_path": str(sd_image),
            "identified": True,
            "identified_as": "drone_sd",
            "operator_confirmed": True,
            "identified_by_operator_as": None,
        }
    ]
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


def test_run_phase_3_android_logical_skips_empty_files(tmp_path: Path, monkeypatch) -> None:
    project_root = tmp_path
    documents_dir = project_root / "Documents"
    documents_dir.mkdir(parents=True)
    monkeypatch.setattr(Path, "home", lambda: project_root)

    android_zip = tmp_path / "android_backup.zip"
    _write_zip(
        android_zip,
        {
            "DJI/FlightRecords/record1.txt": "flight record",
            "DJI/FlightLogs/sys_log_empty.txt": b"",
            "data/data/com.dji.go/db/djiFMDB.db": "db",
        },
    )

    state = _build_state(tmp_path, "CASE-P3-EMPTY")
    android_evidence = make_evidence(
        source_path=android_zip,
        stored_path=android_zip,
        parent=None,
        acquisition_method=config.ACQUISITION_LOGICAL,
        type=config.EVIDENCE_TYPE_INPUT,
        skip_hash=True,
    )
    state.input_evidence.append(android_evidence)
    state.phase_outputs["p1_provenance"]["identified_evidence"] = [
        {
            "source_path": str(android_zip),
            "identified": True,
            "identified_as": "controller_android",
            "operator_confirmed": True,
            "identified_by_operator_as": None,
        },
    ]

    result = p3.run_phase_3(state)
    artefacts = result.phase_outputs["p3_artefact_extraction"]["extracted_artefacts"]
    stored_names = [Path(item["stored_path"]).name for item in artefacts]
    assert "sys_log_empty.txt" not in stored_names
    assert any("empty file skipped" in flag for flag in result.anomaly_flags)


def test_run_phase_3_android_logical_deduplicates_by_basename(tmp_path: Path, monkeypatch) -> None:
    project_root = tmp_path
    documents_dir = project_root / "Documents"
    documents_dir.mkdir(parents=True)
    monkeypatch.setattr(Path, "home", lambda: project_root)

    android_zip = tmp_path / "android_backup.zip"
    _write_zip(
        android_zip,
        {
            "data/data/com.dji.go/db/djiFMDB.db": "db content first",
            "data/data/com.dji.go/.space_db/djiFMDB.db": "db content second",
        },
    )

    state = _build_state(tmp_path, "CASE-P3-DEDUP")
    android_evidence = make_evidence(
        source_path=android_zip,
        stored_path=android_zip,
        parent=None,
        acquisition_method=config.ACQUISITION_LOGICAL,
        type=config.EVIDENCE_TYPE_INPUT,
        skip_hash=True,
    )
    state.input_evidence.append(android_evidence)
    state.phase_outputs["p1_provenance"]["identified_evidence"] = [
        {
            "source_path": str(android_zip),
            "identified": True,
            "identified_as": "controller_android",
            "operator_confirmed": True,
            "identified_by_operator_as": None,
        },
    ]

    result = p3.run_phase_3(state)
    artefacts = result.phase_outputs["p3_artefact_extraction"]["extracted_artefacts"]
    db_artefacts = [item for item in artefacts if item["artefact_category"] == DATABASES]
    db_names = [Path(item["stored_path"]).name for item in db_artefacts]
    assert db_names.count("djiFMDB.db") == 1
    assert "djiFMDB_1.db" not in db_names
