from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
import plistlib
import sqlite3
import zipfile

import config
from config import DEVICE_AND_BACKUP_INFO
from evidence import Evidence
from phases import p2_image_parsing as p2_module
from state import State


@dataclass
class FakeConversionResult:
    output_root: Path
    metadata_evidence: list | None = None

    def __post_init__(self) -> None:
        if self.metadata_evidence is None:
            self.metadata_evidence = []


def test_run_phase_2_convert_controller_ios_evidence(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    project_root = tmp_path
    documents_dir = project_root / "Documents"
    documents_dir.mkdir(parents=True)

    input_archive = project_root / "ios_backup.zip"
    manifest_db = project_root / "Manifest.db"
    connection = sqlite3.connect(manifest_db)
    cursor = connection.cursor()
    cursor.execute("CREATE TABLE Files (fileID TEXT, domain TEXT, relativePath TEXT)")
    cursor.execute(
        "INSERT INTO Files (fileID, domain, relativePath) VALUES (?, ?, ?)",
        (
            hashlib.sha1(
                b"AppDomain-com.example.dji-Documents/logs/deviceinfo.xml"
            ).hexdigest(),
            "AppDomain-com.example.dji",
            "Documents/logs/deviceinfo.xml",
        ),
    )
    connection.commit()
    connection.close()
    info_plist = plistlib.dumps(
        {
            "Device Name": "Test iPhone",
            "Product Name": "iPhone15,2",
            "Product Version": "17.4",
            "Serial Number": "SERIAL-001",
            "Unique Identifier": "UID-123",
            "Last Backup Date": "2026-05-04T12:34:56Z",
            "iTunes Version": "12.13",
            "Installed Applications": ["com.dji.go", "com.example.other"],
        }
    )
    with zipfile.ZipFile(
        input_archive, "w", compression=zipfile.ZIP_DEFLATED
    ) as archive:
        archive.writestr("Info.plist", info_plist)
        archive.writestr(
            "00/00deadbeefdeadbeefdeadbeefdeadbeefdeadbeef", b"deviceinfo contents"
        )

    state = State(case_id="CASE-001", operator="Floris")
    ios_evidence = Evidence(input_archive, type="input", skip_hash=True)
    state.input_evidence.append(ios_evidence)
    state.phase_outputs["p1_provenance"] = {
        "identified_evidence": [
            {
                "source_path": str(input_archive),
                "identified": True,
                "identified_as": "controller_ios",
                "operator_confirmed": True,
                "identified_by_operator_as": None,
            },
        ]
    }

    converted_root = (
        documents_dir
        / "dfdof_output"
        / "CASE-001"
        / "p2_image_parsing"
        / "controller_ios_parsed"
    )

    # Make Path.home() return our tmp project root so config functions resolve
    # into the temporary Documents directory.
    monkeypatch.setattr(Path, "home", lambda: project_root)

    def fake_convert(archive_path, output_root=None, source_evidence=None):
        actual_root = (
            Path(output_root)
            if output_root is not None
            else (documents_dir / "dfdof_output" / "CASE-001" / "controller_ios_parsed")
        )
        actual_root.mkdir(parents=True, exist_ok=True)
        metadata_root = actual_root / "_metadata"
        metadata_root.mkdir(parents=True, exist_ok=True)
        (metadata_root / "Info.plist").write_bytes(info_plist)
        (actual_root / "backup_info.json").write_text(
            json.dumps(
                {
                    "Device Name": "Test iPhone",
                    "Product Name": "iPhone15,2",
                    "Product Version": "17.4",
                    "Serial Number": "SERIAL-001",
                    "Unique Identifier": "UID-123",
                    "Last Backup Date": "2026-05-04T12:34:56Z",
                    "iTunes Version": "12.13",
                    "Installed Applications": ["com.dji.go", "com.example.other"],
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        return FakeConversionResult(output_root=actual_root)

    monkeypatch.setattr(p2_module, "parse_ios_backup", fake_convert)

    result = p2_module.run_phase_2(state)
    output = capsys.readouterr().out

    assert converted_root.exists()
    assert "Parsing controller iOS" in output
    phase_output = result.phase_outputs["p2_image_parsing"]
    assert phase_output["parsed_evidence"]

    # First evidence should be the converted root
    derived = phase_output["parsed_evidence"][0]
    assert derived["stored_path"] == str(converted_root)
    assert derived["source_path"] == str(input_archive)
    assert derived["type"] == "parsed"
    assert derived["acquisition_method"] == "ios_parser"
    assert derived["artefact_category"] == DEVICE_AND_BACKUP_INFO

    # Second evidence should be backup_info.json with values
    backup_info_evidence = next(
        (
            item
            for item in phase_output["parsed_evidence"]
            if Path(item["stored_path"]).name == "backup_info.json"
        ),
        None,
    )
    assert backup_info_evidence is not None
    assert backup_info_evidence["source_path"] == str(input_archive)
    assert backup_info_evidence["values"]["device_name"] == "Test iPhone"
    assert backup_info_evidence["values"]["product_name"] == "iPhone15,2"
    assert backup_info_evidence["values"]["product_version"] == "17.4"
    assert backup_info_evidence["values"]["serial_number"] == "SERIAL-001"
    assert backup_info_evidence["values"]["unique_identifier"] == "UID-123"
    assert backup_info_evidence["values"]["backup_date"] == "2026-05-04T12:34:56Z"
    assert backup_info_evidence["values"]["installed_dji_apps"] == ["com.dji.go"]

    info_plist_evidence = next(
        (
            item
            for item in phase_output["parsed_evidence"]
            if Path(item["stored_path"]).name == "Info.plist"
        ),
        None,
    )
    assert info_plist_evidence is not None
    assert info_plist_evidence["source_path"] == "Info.plist"
    assert "completed_at" in phase_output
    assert isinstance(phase_output["completed_at"], str)
    assert result.completed_phases == ["p2_image_parsing"]
    assert result.tool_invocation_log
    assert result.tool_invocation_log[0]["tool_name"] == "ios_parser"


def _create_android_logical_zip(zip_path: Path) -> None:
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("backup/notes.txt", "Acquisition notes")
        archive.writestr(
            "backup/report.pdf",
            "Phone model: DJI RC 2\nAcquisition date: 2026-05-05\n",
        )
        archive.writestr(
            "property/DeviceInfo.xml",
            "Device Name: RC Controller\nModel Name: RC 2\nVersion: 1.2.3\nFirmware Version: FW-9.9.9\n",
        )
        archive.writestr(
            "property/ApplicationInfo.xml",
            "Installed apps: com.dji.go dji.go.v4\n",
        )
        archive.writestr("property/ro.serialno", "SERIAL-ANDROID-1\n")
        archive.writestr("property/net.hostname", "hostname-android\n")


def test_run_phase_2_processes_android_logical_source(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    project_root = tmp_path
    documents_dir = project_root / "Documents"
    documents_dir.mkdir(parents=True)
    input_archive = project_root / "android_backup.zip"
    _create_android_logical_zip(input_archive)

    state = State(case_id="CASE-002", operator="Floris")
    android_evidence = Evidence(
        input_archive, acquisition_method="logical", type="input", skip_hash=True
    )
    state.input_evidence.append(android_evidence)
    state.phase_outputs["p1_provenance"] = {
        "identified_evidence": [
            {
                "source_path": str(input_archive),
                "identified": True,
                "identified_as": "controller_android",
                "operator_confirmed": True,
                "identified_by_operator_as": None,
            },
        ]
    }

    monkeypatch.setattr(Path, "home", lambda: project_root)
    converted_root = (
        documents_dir
        / "dfdof_output"
        / "CASE-002"
        / "p2_image_parsing"
        / "controller_android_parsed"
    )

    result = p2_module.run_phase_2(state)
    output = capsys.readouterr().out
    phase_output = result.phase_outputs["p2_image_parsing"]

    assert converted_root.exists()
    assert "Parsing controller Android" in output

    # Check that acquisition PDF was extracted
    acquisition_pdf = next(
        (
            item
            for item in phase_output["parsed_evidence"]
            if Path(item["stored_path"]).name == "report.pdf"
        ),
        None,
    )
    assert acquisition_pdf is not None
    assert acquisition_pdf["source_path"] == "backup\\report.pdf"
    assert acquisition_pdf["values"]["phone_model"] == "DJI RC 2"
    assert acquisition_pdf["values"]["acquisition_date"] == "2026-05-05"

    backup_info_evidence = next(
        (
            item
            for item in phase_output["parsed_evidence"]
            if Path(item["stored_path"]).name == "backup_info.json"
        ),
        None,
    )
    assert backup_info_evidence is not None
    assert backup_info_evidence["values"]["device_name"] == "RC Controller"
    assert backup_info_evidence["values"]["product_name"] == "RC 2"
    assert backup_info_evidence["values"]["product_version"] == "1.2.3"
    assert backup_info_evidence["values"]["serial_number"] == "SERIAL-ANDROID-1"
    assert backup_info_evidence["values"]["backup_date"] == "2026-05-05"
    assert backup_info_evidence["values"]["installed_dji_apps"] == [
        "com.dji.go",
        "dji.go.v4",
    ]

    android_tool = next(
        item
        for item in result.tool_invocation_log
        if item["tool_name"] == "android_parser"
    )
    assert android_tool["output_paths"] == [str(converted_root)]

    # Check that device files were extracted with metadata
    deviceinfo = next(
        (
            item
            for item in phase_output["parsed_evidence"]
            if Path(item["stored_path"]).name == "DeviceInfo.xml"
        ),
        None,
    )
    assert deviceinfo is not None
    assert deviceinfo["source_path"] == "property\\DeviceInfo.xml"
    assert deviceinfo["values"]["device_name"] == "RC Controller"
    assert deviceinfo["values"]["model_name"] == "RC 2"
    assert deviceinfo["values"]["version"] == "1.2.3"
    assert deviceinfo["values"]["firmware_version"] == "FW-9.9.9"

    appinfo = next(
        (
            item
            for item in phase_output["parsed_evidence"]
            if Path(item["stored_path"]).name == "ApplicationInfo.xml"
        ),
        None,
    )
    assert appinfo is not None
    assert appinfo["values"]["installed_dji_apps"] == ["com.dji.go", "dji.go.v4"]

    serialno = next(
        (
            item
            for item in phase_output["parsed_evidence"]
            if Path(item["stored_path"]).name == "ro.serialno"
        ),
        None,
    )
    assert serialno is not None
    assert serialno["values"]["device_serial"] == "SERIAL-ANDROID-1"

    hostname = next(
        (
            item
            for item in phase_output["parsed_evidence"]
            if Path(item["stored_path"]).name == "net.hostname"
        ),
        None,
    )
    assert hostname is not None
    assert hostname["values"]["device_hostname"] == "hostname-android"
    assert any(
        Path(item["stored_path"]).name == "ApplicationInfo.xml"
        for item in phase_output["parsed_evidence"]
    )
    assert any(
        Path(item["stored_path"]).name == "ro.serialno"
        for item in phase_output["parsed_evidence"]
    )
    assert any(
        Path(item["stored_path"]).name == "net.hostname"
        for item in phase_output["parsed_evidence"]
    )


def test_run_phase_2_processes_android_physical_source(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    project_root = tmp_path
    documents_dir = project_root / "Documents"
    documents_dir.mkdir(parents=True)
    input_image = project_root / "android_image.E01"
    input_image.write_bytes(b"image fixture")

    state = State(case_id="CASE-003", operator="Floris")
    android_evidence = Evidence(
        input_image, acquisition_method="physical", type="input", skip_hash=True
    )
    state.input_evidence.append(android_evidence)
    state.phase_outputs["p1_provenance"] = {
        "identified_evidence": [
            {
                "source_path": str(input_image),
                "identified": True,
                "identified_as": "controller_android",
                "operator_confirmed": True,
                "identified_by_operator_as": None,
            },
        ]
    }

    monkeypatch.setattr(Path, "home", lambda: project_root)
    converted_root = (
        documents_dir
        / "dfdof_output"
        / "CASE-003"
        / "p2_image_parsing"
        / "controller_android_parsed"
    )

    def fake_extract_tsk_image(
        image_path,
        working_dir,
        *,
        include_paths=None,
        acquisition_method="physical_reader",
        parent=None,
        tool_log=None,
        artefact_category=None,
    ):
        _ = (
            image_path,
            include_paths,
            acquisition_method,
            parent,
            tool_log,
            artefact_category,
        )
        working_dir = Path(working_dir)
        working_dir.mkdir(parents=True, exist_ok=True)
        files = {
            "DeviceInfo.xml": "Device Name: Physical RC\nModel Name: RC Pro\nVersion: 9.1.0\nFirmware Version: FW-1.0\n",
            "ApplicationInfo.xml": "Installed: dji.pilot\n",
            "ro.serialno": "SERIAL-PHYSICAL\n",
            "net.hostname": "physical-host\n",
        }
        extracted: list[Evidence] = []
        for name, contents in files.items():
            path = working_dir / name
            path.write_text(contents, encoding="utf-8")
            extracted.append(
                Evidence(
                    source_path=name,
                    stored_path=path,
                    parent=parent,
                    acquisition_method="tsk",
                    type="extracted",
                    artefact_category=DEVICE_AND_BACKUP_INFO,
                )
            )
        return extracted

    monkeypatch.setattr(
        "parsing.extract_physical.extract_tsk_image", fake_extract_tsk_image
    )

    result = p2_module.run_phase_2(state)
    output = capsys.readouterr().out
    phase_output = result.phase_outputs["p2_image_parsing"]

    assert "Parsing controller Android" in output

    # Check that device files were extracted with metadata
    assert not any(child.is_dir() for child in converted_root.iterdir())
    deviceinfo = next(
        (
            item
            for item in phase_output["parsed_evidence"]
            if Path(item["stored_path"]).name == "DeviceInfo.xml"
        ),
        None,
    )
    assert deviceinfo is not None
    assert deviceinfo["source_path"] == "DeviceInfo.xml"
    assert deviceinfo["values"]["device_name"] == "Physical RC"
    assert deviceinfo["values"]["model_name"] == "RC Pro"
    assert deviceinfo["values"]["version"] == "9.1.0"
    assert deviceinfo["values"]["firmware_version"] == "FW-1.0"

    appinfo = next(
        (
            item
            for item in phase_output["parsed_evidence"]
            if Path(item["stored_path"]).name == "ApplicationInfo.xml"
        ),
        None,
    )
    assert appinfo is not None
    assert appinfo["values"]["installed_dji_apps"] == ["dji.pilot"]

    serialno = next(
        (
            item
            for item in phase_output["parsed_evidence"]
            if Path(item["stored_path"]).name == "ro.serialno"
        ),
        None,
    )
    assert serialno is not None
    assert serialno["values"]["device_serial"] == "SERIAL-PHYSICAL"

    hostname = next(
        (
            item
            for item in phase_output["parsed_evidence"]
            if Path(item["stored_path"]).name == "net.hostname"
        ),
        None,
    )
    assert hostname is not None
    assert hostname["values"]["device_hostname"] == "physical-host"
    assert not any(
        Path(item["stored_path"]).name == "report.pdf"
        for item in phase_output["parsed_evidence"]
    )

    backup_info_evidence = next(
        (
            item
            for item in phase_output["parsed_evidence"]
            if Path(item["stored_path"]).name == "backup_info.json"
        ),
        None,
    )
    assert backup_info_evidence is not None
    assert backup_info_evidence["values"]["device_name"] == "Physical RC"
    assert backup_info_evidence["values"]["product_name"] == "RC Pro"
    assert backup_info_evidence["values"]["product_version"] == "9.1.0"
    assert backup_info_evidence["values"]["serial_number"] == "SERIAL-PHYSICAL"
    assert backup_info_evidence["values"]["backup_date"] is None
    assert backup_info_evidence["values"]["installed_dji_apps"] == ["dji.pilot"]
    assert all(
        item["artefact_category"] == DEVICE_AND_BACKUP_INFO
        for item in phase_output["parsed_evidence"]
    )
