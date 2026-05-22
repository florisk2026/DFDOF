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
    export_log = artefact_dir / "DJI_ASSISTANT_EXPORT_FILE_001.DAT"
    export_log.write_text("export", encoding="utf-8")

    flight_evidence = make_evidence(
        source_path=flight_record.name,
        stored_path=flight_record,
        parent=source,
        acquisition_method=config.ACQUISITION_EXTRACT_LOGICAL,
        type=config.EVIDENCE_TYPE_EXTRACTED,
        artefact_category=config.FLIGHT_RECORDS,
    )
    account_evidence = make_evidence(
        source_path=account_plist.name,
        stored_path=account_plist,
        parent=source,
        acquisition_method=config.ACQUISITION_EXTRACT_LOGICAL,
        type=config.EVIDENCE_TYPE_EXTRACTED,
        artefact_category=config.ACCOUNT_DATA,
    )
    image_evidence = make_evidence(
        source_path=image_file.name,
        stored_path=image_file,
        parent=source,
        acquisition_method=config.ACQUISITION_EXTRACT_LOGICAL,
        type=config.EVIDENCE_TYPE_EXTRACTED,
        artefact_category=config.IMAGES,
    )
    drone_log_evidence = make_evidence(
        source_path=drone_log.name,
        stored_path=drone_log,
        parent=source,
        acquisition_method=config.ACQUISITION_EXTRACT_LOGICAL,
        type=config.EVIDENCE_TYPE_EXTRACTED,
        artefact_category=config.DRONE_LOGS,
    )
    export_log_evidence = make_evidence(
        source_path=export_log.name,
        stored_path=export_log,
        parent=source,
        acquisition_method=config.ACQUISITION_EXTRACT_LOGICAL,
        type=config.EVIDENCE_TYPE_EXTRACTED,
        artefact_category=config.DRONE_LOGS,
    )

    state.phase_outputs["p3_artefact_extraction"] = {
        "extracted_artefacts": [
            flight_evidence.to_dict(),
            account_evidence.to_dict(),
            image_evidence.to_dict(),
            drone_log_evidence.to_dict(),
            export_log_evidence.to_dict(),
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

    def fake_extractdji(dat_path, output_dir, _state, parent_evidence, _identification, _index=None):
        output_dir.mkdir(parents=True, exist_ok=True)
        converted_path = output_dir / "FLY001.DAT"
        converted_path.write_text("converted", encoding="utf-8")
        return [
            make_evidence(
                source_path=dat_path.name,
                stored_path=converted_path,
                parent=parent_evidence,
                acquisition_method=config.ACQUISITION_EXTRACT_DJI,
                type=config.EVIDENCE_TYPE_EXTRACTED,
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
    monkeypatch.setattr(p4, "run_extractdji", fake_extractdji)
    monkeypatch.setattr(p4, "run_txtlogtocsv", fake_txtlogtocsv)
    monkeypatch.setattr(p4, "run_exiftool", fake_exiftool)

    result = p4.run_phase_4(state)
    phase_output = result.phase_outputs["p4_decision_and_orchestration"]

    assert result.completed_phases[-1] == "p4_decision_and_orchestration"
    # flight_record→txtlogtocsv(1) + account(1) + image→exiftool(1)
    # + drone_log→datcon(1) + export_log→extractdji(1)+datcon(1) = 6
    assert len(phase_output["decision_and_orchestration_artefacts"]) == 6
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
    bad_account = artefact_dir / "bad.plist"
    bad_account.write_text("not a plist", encoding="utf-8")

    bad_account_evidence = make_evidence(
        source_path=bad_account.name,
        stored_path=bad_account,
        parent=source,
        acquisition_method=config.ACQUISITION_EXTRACT_LOGICAL,
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

    state.phase_outputs["p3_artefact_extraction"] = {
        "extracted_artefacts": [missing_payload, bad_account_evidence.to_dict()]
    }

    monkeypatch.setattr(p4, "run_datcon", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(p4, "run_txtlogtocsv", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(p4, "run_exiftool", lambda *_args, **_kwargs: (None, None))

    result = p4.run_phase_4(state)
    anomalies = result.anomaly_flags
    phase_dir = config.output_dir() / state.case_id / "p4_decision_and_orchestration"

    assert "[p4 - controller ios]: input artefact missing: missing.txt" in anomalies
    assert "[p4 - controller ios - account data]: account data parse failed for bad.plist" in anomalies
    assert "[p4 - controller android]: source evidence not found" in anomalies
    assert "[p4 - drone sd]: source evidence not found" in anomalies
    assert not (phase_dir / "controller_ios" / "account_data").exists()


def test_run_phase_4_android_info_file_parsed(tmp_path: Path, monkeypatch) -> None:
    project_root = tmp_path
    documents_dir = project_root / "Documents"
    documents_dir.mkdir(parents=True)
    monkeypatch.setattr(Path, "home", lambda: project_root)

    state = _build_state(tmp_path, "CASE-P4-INFO-1")
    android_zip = tmp_path / "android.zip"
    android_zip.write_text("android", encoding="utf-8")
    source = _add_source(state, android_zip, config.IDENTIFICATION_CONTROLLER_ANDROID)

    artefact_dir = tmp_path / "artefacts"
    artefact_dir.mkdir()
    info_file = artefact_dir / "2018_04_19_11_40_02.info"
    info_file.write_text(
        "#Thu Apr 19 11:40:53 MDT 2018\n"
        "CaptureDate=2018/04/19 11\\:40\\:02\n"
        "PositionRelativeAlt=86.0\n"
        "PositionGPSLat=39.96050285066674\n"
        "PositionGPSAlt=86.0\n"
        "PositionGPSLng=-106.21660977113379\n"
        "FPS_Drone=30\n"
        "DeviceMaker=DJI\n",
        encoding="utf-8",
    )
    info_evidence = make_evidence(
        source_path=info_file.name,
        stored_path=info_file,
        parent=source,
        acquisition_method=config.ACQUISITION_EXTRACT_LOGICAL,
        type=config.EVIDENCE_TYPE_EXTRACTED,
        artefact_category=config.VIDEOS,
    )
    state.phase_outputs["p3_artefact_extraction"] = {
        "extracted_artefacts": [info_evidence.to_dict()]
    }

    exiftool_called_for: list[str] = []

    def fake_exiftool(file_path, output_dir, _state, parent_ev, artefact_category, _identification, _index=None):
        exiftool_called_for.append(file_path.name)
        return None, None

    monkeypatch.setattr(p4, "run_exiftool", fake_exiftool)

    result = p4.run_phase_4(state)
    phase_output = result.phase_outputs["p4_decision_and_orchestration"]

    artefacts = phase_output["decision_and_orchestration_artefacts"]
    observations = phase_output["derived_observations"]

    assert len(artefacts) == 1
    assert artefacts[0]["stored_path"].endswith(".json")
    assert "2018_04_19_11_40_02.info" not in exiftool_called_for

    assert len(observations) == 1
    obs_fields = observations[0]["observations"][0]
    assert obs_fields["CaptureDate"] == "2018/04/19 11:40:02"
    assert obs_fields["PositionGPSLat"] == "39.96050285066674"
    assert obs_fields["PositionGPSLng"] == "-106.21660977113379"
    assert obs_fields["PositionGPSAlt"] == "86.0"
    assert obs_fields["PositionRelativeAlt"] == "86.0"
    assert "FPS_Drone" not in obs_fields
    assert "DeviceMaker" not in obs_fields


def test_run_phase_4_android_info_file_empty_raises_anomaly(tmp_path: Path, monkeypatch) -> None:
    project_root = tmp_path
    documents_dir = project_root / "Documents"
    documents_dir.mkdir(parents=True)
    monkeypatch.setattr(Path, "home", lambda: project_root)

    state = _build_state(tmp_path, "CASE-P4-INFO-2")
    android_zip = tmp_path / "android.zip"
    android_zip.write_text("android", encoding="utf-8")
    source = _add_source(state, android_zip, config.IDENTIFICATION_CONTROLLER_ANDROID)

    artefact_dir = tmp_path / "artefacts"
    artefact_dir.mkdir()
    empty_info = artefact_dir / "empty.info"
    empty_info.write_text("#only a comment\n", encoding="utf-8")
    info_evidence = make_evidence(
        source_path=empty_info.name,
        stored_path=empty_info,
        parent=source,
        acquisition_method=config.ACQUISITION_EXTRACT_LOGICAL,
        type=config.EVIDENCE_TYPE_EXTRACTED,
        artefact_category=config.VIDEOS,
    )
    state.phase_outputs["p3_artefact_extraction"] = {
        "extracted_artefacts": [info_evidence.to_dict()]
    }

    result = p4.run_phase_4(state)
    phase_output = result.phase_outputs["p4_decision_and_orchestration"]

    assert not phase_output["decision_and_orchestration_artefacts"]
    assert not phase_output["derived_observations"]
    assert any("video info parse failed" in flag for flag in result.anomaly_flags)
