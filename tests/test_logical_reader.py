from __future__ import annotations

import zipfile
from pathlib import Path

from config import DEVICE_AND_BACKUP_INFO
from evidence import Evidence
from parsing.logical_reader import extract_logical_files, find_acquisition_pdf_member


def _create_logical_zip(zip_path: Path) -> None:
	with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
		archive.writestr("folder/deviceinfo.xml", b"device info contents")
		archive.writestr("logs/other.txt", b"other contents")


def test_extract_logical_files_batch_returns_derived_evidence(tmp_path: Path) -> None:
	archive_path = tmp_path / "logical.zip"
	_create_logical_zip(archive_path)

	source = Evidence(archive_path, type="input")
	output_dir = tmp_path / "Documents" / "dfdof_results" / "CASE-001"

	extracted = extract_logical_files(
		source,
		output_dir,
		["folder/deviceinfo.xml", "logs/other.txt"],
	)

	assert len(extracted) == 2
	assert (output_dir / "folder" / "deviceinfo.xml").exists()
	assert (output_dir / "logs" / "other.txt").exists()
	assert extracted[0].acquisition_method == "logical_reader"
	assert extracted[0].type == "extracted"
	assert extracted[0].artefact_category == DEVICE_AND_BACKUP_INFO
	assert extracted[0].parent_sha256 == source.sha256
	assert extracted[0].source_path == "folder/deviceinfo.xml"
	assert extracted[0].stored_path == output_dir / "folder" / "deviceinfo.xml"
	assert extracted[0].sha256
	assert extracted[0].sha1
	assert extracted[0].hash_timestamp
	assert extracted[0].size == len(b"device info contents")


def test_find_acquisition_pdf_member_prefers_depth_folder_with_txt(tmp_path: Path) -> None:
	archive_path = tmp_path / "logical.zip"
	with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
		archive.writestr("depth1/report.pdf", b"report")
		archive.writestr("depth1/notes.txt", b"notes")
		archive.writestr("depth2/nested/report.pdf", b"nested report")

	member = find_acquisition_pdf_member(archive_path)

	assert member == "depth1/report.pdf"