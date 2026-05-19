from __future__ import annotations

import plistlib
from pathlib import Path

import config
from evidence import Evidence, make_evidence
from observation import make_observation
from phases import p4_decision_and_orchestration as p4
from state import State


def _build_state(tmp_path: Path, case_id: str) -> State:
    state = State(case_id=case_id, operator="Tester")
    state.phase_outputs["p1_provenance"] = {"identified_evidence": []}
    return state


def _add_source(state: State, source_path: Path, identification: str) -> Evidence:
    source = make_evidence(
        source_path=source_path,
        stored_path=source_path,
        parent=None,
        acquisition_method=config.ACQUISITION_LOGICAL,
        type=config.EVIDENCE_TYPE_INPUT,
    )
    state.input_evidence.append(source)
    state.phase_outputs["p1_provenance"]["identified_evidence"].append(
        {
            "source_path": str(source_path),
            "identified": True,
            "identified_as": identification,
            "operator_confirmed": True,
            "identified_by_operator_as": None,
        }
    )
    return source


def test_run_phase_4_controller_ios_dispatches_tools(tmp_path: Path, monkeypatch) -> None:
    project_root = tmp_path
    documents_dir = project_root / "Documents"
    documents_dir.mkdir(parents=True)
    monkeypatch.setattr(Path, "home", lambda: project_root)

    state = _build_state(tmp_path, "CASE-P4-1")
    ios_zip = tmp_path / "ios_logical.zip"
    ios_zip.write_text("ios", encoding="utf-8")
    source = _add_source(state, ios_zip, config.IDENTIFICATION_CONTROLLER_IOS)
    android_zip = tmp_path / "android_logical.zip"
    android_zip.write_text("android", encoding="utf-8")
    _add_source(state, android_zip, config.IDENTIFICATION_CONTROLLER_ANDROID)
    drone_sd = tmp_path / "drone_sd.E01"
    drone_sd.write_text("drone", encoding="utf-8")
    _add_source(state, drone_sd, config.IDENTIFICATION_DRONE_SD)
    flight_storage = tmp_path / "flight_storage.zip"
    flight_storage.write_text("flight", encoding="utf-8")
    _add_source(state, flight_storage, config.IDENTIFICATION_DRONE_FLIGHT_STORAGE)

    artefact_dir = tmp_path / "artefacts"
    artefact_dir.mkdir()
    flight_record = artefact_dir / "record.txt"
    flight_record.write_text("record", encoding="utf-8")
    account_plist = artefact_dir / "com.dji.go.plist"
    account_plist.write_bytes(plistlib.dumps({"pilot": "tester"}))
    image_file = artefact_dir / "photo.jpg"
    image_file.write_text("image", encoding="utf-8")
    drone_log = artefact_dir / "log.DAT"
    drone_log.write_text("dat", encoding="utf-8")

    flight_evidence = make_evidence(
        source_path=flight_record.name,
        stored_path=flight_record,
        parent=source,
        acquisition_method=config.ACQUISITION_EXRACT_LOGICAL,
        type=config.EVIDENCE_TYPE_EXTRACTED,
        artefact_category=config.FLIGHT_RECORDS,
    )
    account_evidence = make_evidence(
        source_path=account_plist.name,
        stored_path=account_plist,
        parent=source,
        acquisition_method=config.ACQUISITION_EXRACT_LOGICAL,
        type=config.EVIDENCE_TYPE_EXTRACTED,
        artefact_category=config.ACCOUNT_DATA,
    )
    image_evidence = make_evidence(
        source_path=image_file.name,
        stored_path=image_file,
        parent=source,
        acquisition_method=config.ACQUISITION_EXRACT_LOGICAL,
        type=config.EVIDENCE_TYPE_EXTRACTED,
        artefact_category=config.IMAGES,
    )
    drone_log_evidence = make_evidence(
        source_path=drone_log.name,
        stored_path=drone_log,
        parent=source,
        acquisition_method=config.ACQUISITION_EXRACT_LOGICAL,
        type=config.EVIDENCE_TYPE_EXTRACTED,
        artefact_category=config.DRONE_LOGS,
    )

    state.phase_outputs["p3_artefact_extraction"] = {
        "extracted_artefacts": [
            flight_evidence.to_dict(),
            account_evidence.to_dict(),
            image_evidence.to_dict(),
            drone_log_evidence.to_dict(),
        ]
    }

    def fake_datcon(dat_path, output_dir, _state, parent_evidence, _identification, _index=None):
        output_dir.mkdir(parents=True, exist_ok=True)
        csv_path = output_dir / f"{dat_path.stem}.csv"
        csv_path.write_text("csv", encoding="utf-8")
        return [
            make_evidence(
                source_path=dat_path.name,
                stored_path=csv_path,
                parent=parent_evidence,
                acquisition_method=config.ACQUISITION_DATCON,
                type=config.EVIDENCE_TYPE_DECODED,
                artefact_category=config.DRONE_LOGS,
            )
        ]

    def fake_txtlogtocsv(txt_path, output_dir, _state, parent_evidence, _identification, _index=None):
        output_dir.mkdir(parents=True, exist_ok=True)
        csv_path = output_dir / f"{txt_path.stem}.csv"
        csv_path.write_text("csv", encoding="utf-8")
        return make_evidence(
            source_path=txt_path.name,
            stored_path=csv_path,
            parent=parent_evidence,
            acquisition_method=config.ACQUISITION_TXTLOGTOCSV,
            type=config.EVIDENCE_TYPE_DECODED,
            artefact_category=config.FLIGHT_RECORDS,
        )

    def fake_exiftool(file_path, output_dir, _state, parent_evidence, artefact_category, _identification, _index=None):
        output_dir.mkdir(parents=True, exist_ok=True)
        json_path = output_dir / f"{file_path.stem}_exif.json"
        json_path.write_text("{}", encoding="utf-8")
        evidence = make_evidence(
            source_path=file_path.name,
            stored_path=json_path,
            parent=parent_evidence,
            acquisition_method=config.ACQUISITION_EXIFTOOL,
            type=config.EVIDENCE_TYPE_DECODED,
            artefact_category=artefact_category,
        )
        observation = make_observation(
            evidence_sha256=parent_evidence.sha256,
            evidence_category=artefact_category,
            acquisition_method=config.ACQUISITION_EXIFTOOL,
            observations=[{"tag": "value"}],
        )
        return evidence, observation

    monkeypatch.setattr(p4, "run_datcon", fake_datcon)
    monkeypatch.setattr(p4, "run_txtlogtocsv", fake_txtlogtocsv)
    monkeypatch.setattr(p4, "run_exiftool", fake_exiftool)

    result = p4.run_phase_4(state)
    phase_output = result.phase_outputs["p4_decision_and_orchestration"]

    assert result.completed_phases[-1] == "p4_decision_and_orchestration"
    assert len(phase_output["decision_and_orchestration_artefacts"]) == 4
    assert len(phase_output["derived_observations"]) == 2


def test_run_phase_4_records_anomalies(tmp_path: Path, monkeypatch) -> None:
    project_root = tmp_path
    documents_dir = project_root / "Documents"
    documents_dir.mkdir(parents=True)
    monkeypatch.setattr(Path, "home", lambda: project_root)

    state = _build_state(tmp_path, "CASE-P4-2")
    ios_zip = tmp_path / "ios_logical.zip"
    ios_zip.write_text("ios", encoding="utf-8")
    source = _add_source(state, ios_zip, config.IDENTIFICATION_CONTROLLER_IOS)

    artefact_dir = tmp_path / "artefacts"
    artefact_dir.mkdir()
    empty_account = artefact_dir / "empty.plist"
    empty_account.write_text("", encoding="utf-8")

    empty_account_evidence = make_evidence(
        source_path=empty_account.name,
        stored_path=empty_account,
        parent=source,
        acquisition_method=config.ACQUISITION_EXRACT_LOGICAL,
        type=config.EVIDENCE_TYPE_EXTRACTED,
        artefact_category=config.ACCOUNT_DATA,
    )
    missing_payload = {
        "source_path": "missing.txt",
        "stored_path": str(artefact_dir / "missing.txt"),
        "parent_sha256": source.sha256,
        "acquisition_method": "extract_logical",
        "type": "extracted",
        "artefact_category": config.FLIGHT_RECORDS,
        "size": 1,
        "sha1": None,
        "sha256": None,
        "hash_timestamp": None,
    }

    empty_payload = empty_account_evidence.to_dict()
    empty_payload["size"] = 0

    state.phase_outputs["p3_artefact_extraction"] = {
        "extracted_artefacts": [missing_payload, empty_payload]
    }

    monkeypatch.setattr(p4, "run_datcon", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(p4, "run_txtlogtocsv", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(p4, "run_exiftool", lambda *_args, **_kwargs: (None, None))

    result = p4.run_phase_4(state)
    anomalies = result.anomaly_flags
    phase_dir = config.output_dir() / state.case_id / "p4_decision_and_orchestration"

    assert "p4 - controller ios: input artefact missing: missing.txt" in anomalies
    assert "p4 - controller ios - account data: account data file is empty: empty.plist" in anomalies
    assert "p4 - controller android: source evidence not found" in anomalies
    assert "p4 - drone sd: source evidence not found" in anomalies
    assert not (phase_dir / "controller_ios" / "account_data").exists()
