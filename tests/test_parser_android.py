from __future__ import annotations

import json
from pathlib import Path

import config
from config import DEVICE_AND_BACKUP_INFO
from evidence import Evidence, make_evidence
from parsing import parser_android
from state import State


def _make_source_zip(path: Path) -> None:
    path.write_bytes(b"zip fixture")


def test_parse_android_source_logical_builds_backup_info(tmp_path: Path, monkeypatch) -> None:
    source_zip = tmp_path / "android_logical.zip"
    _make_source_zip(source_zip)
    output_root = tmp_path / "parsed_android"

    source_evidence = make_evidence(
        source_path=source_zip,
        stored_path=source_zip,
        parent=None,
        acquisition_method=config.ACQUISITION_LOGICAL,
        type=config.EVIDENCE_TYPE_INPUT,
        skip_hash=True,
    )
    case_state = State(case_id="CASE-AND-1", operator="Floris")

    def fake_find_acquisition_pdf_member(_archive_path: Path) -> str | None:
        return "backup/report.pdf"

    def fake_extract_logical_files(
        _source_evidence,
        dest_root: Path,
        include_paths,
        artefact_category,
        missing_ok,
    ):
        created: list[Evidence] = []
        for token in include_paths:
            name = Path(str(token)).name
            out_path = dest_root / name
            out_path.parent.mkdir(parents=True, exist_ok=True)
            if name == "DeviceInfo.xml":
                out_path.write_text(
                    "Device Name: RC Controller\n"
                    "Model Name: RC 2\n"
                    "Version: 1.2.3\n"
                    "Firmware Version: FW-9.9.9\n",
                    encoding="utf-8",
                )
                source_path = "property\\DeviceInfo.xml"
            elif name == "ApplicationInfo.xml":
                out_path.write_text("Installed apps: com.dji.go dji.go.v4\n", encoding="utf-8")
                source_path = "property\\ApplicationInfo.xml"
            elif name == "ro.serialno":
                out_path.write_text("SERIAL-ANDROID-1\n", encoding="utf-8")
                source_path = "property\\ro.serialno"
            elif name == "net.hostname":
                out_path.write_text("hostname-android\n", encoding="utf-8")
                source_path = "property\\net.hostname"
            elif name == "packages.list":
                out_path.write_text("com.dji.go 1000 0\ndji.go.v4 1001 0\n", encoding="utf-8")
                source_path = "property\\packages.list"
            elif name == "report.pdf":
                out_path.write_text(
                    "Phone model: DJI RC 2\nAcquisition date: 2026-05-05\n",
                    encoding="utf-8",
                )
                source_path = "backup\\report.pdf"
            else:
                out_path.write_text("", encoding="utf-8")
                source_path = name

            created.append(
                make_evidence(
                    source_path=source_path,
                    stored_path=out_path,
                    parent=source_evidence,
                    acquisition_method=config.ACQUISITION_EXTRACT_LOGICAL,
                    type=config.EVIDENCE_TYPE_EXTRACTED,
                    artefact_category=artefact_category,
                    skip_hash=True,
                )
            )

        if not created and not missing_ok:
            raise AssertionError("Expected at least one extracted file")
        return created

    monkeypatch.setattr(
        parser_android,
        "find_acquisition_pdf_member",
        fake_find_acquisition_pdf_member,
    )
    monkeypatch.setattr(
        parser_android,
        "extract_logical_files",
        fake_extract_logical_files,
    )

    result = parser_android.parse_android_source(source_evidence, output_root, case_state)

    assert result.output_root == output_root
    backup_info = json.loads((output_root / "backup_info.json").read_text(encoding="utf-8"))
    assert backup_info["Device Name"] == "RC Controller"
    assert backup_info["Product Name"] == "RC 2"
    assert backup_info["Product Version"] == "1.2.3"
    assert backup_info["Build Version"] == "FW-9.9.9"
    assert backup_info["Serial Number"] == "SERIAL-ANDROID-1"
    assert backup_info["Last Backup Date"] == "2026-05-05"
    assert backup_info["Installed Applications"] == ["com.dji.go", "dji.go.v4"]

    assert any(Path(str(item.stored_path)).name == "report.pdf" for item in result.parsed_evidence)

    report_observation = next(
        obs
        for obs in result.observations
        if obs.content.observations[0].get("phone_model") == "DJI RC 2"
    )
    assert report_observation.content.observations[0]["phone_model"] == "DJI RC 2"
    assert report_observation.content.observations[0]["acquisition_date"] == "2026-05-05"

    assert case_state.tool_invocation_log
    assert case_state.tool_invocation_log[-1]["tool_name"] == "parser_android"
    assert case_state.tool_invocation_log[-1]["output_paths"] == [str(output_root)]


def test_parse_android_source_flags_missing_key_files(tmp_path: Path, monkeypatch) -> None:
    source_zip = tmp_path / "android_logical.zip"
    _make_source_zip(source_zip)

    source_evidence = make_evidence(
        source_path=source_zip,
        stored_path=source_zip,
        parent=None,
        acquisition_method=config.ACQUISITION_LOGICAL,
        type=config.EVIDENCE_TYPE_INPUT,
        skip_hash=True,
    )
    case_state = State(case_id="CASE-AND-2", operator="Floris")

    def fake_extract_only_packages(
        _source_evidence,
        dest_root: Path,
        include_paths,
        artefact_category,
        missing_ok,
    ):
        assert missing_ok is True
        assert "packages.list" in include_paths
        out_path = dest_root / "packages.list"
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text("com.dji.go 1000 0\n", encoding="utf-8")
        return [
            make_evidence(
                source_path="property\\packages.list",
                stored_path=out_path,
                parent=source_evidence,
                acquisition_method="extract_logical",
                type="extracted",
                artefact_category=artefact_category,
                skip_hash=True,
            )
        ]

    monkeypatch.setattr(parser_android, "find_acquisition_pdf_member", lambda _p: None)
    monkeypatch.setattr(parser_android, "extract_logical_files", fake_extract_only_packages)

    parser_android.parse_android_source(source_evidence, tmp_path / "out_missing", case_state)

    assert (
        f"[p2 - controller android - device and backup info]: DeviceInfo.xml not found for {source_zip.name}"
        in case_state.anomaly_flags
    )
    assert (
        f"[p2 - controller android - device and backup info]: ApplicationInfo.xml not found for {source_zip.name}"
        in case_state.anomaly_flags
    )