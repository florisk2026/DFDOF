from __future__ import annotations

import zipfile
from pathlib import Path

import pytest

import config
from config import DEVICE_AND_BACKUP_INFO
from evidence import make_evidence
from parsing.extract_logical import extract_logical_files


def _create_logical_zip(zip_path: Path) -> None:
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("folder/deviceinfo.xml", b"device info contents")
        archive.writestr("logs/other.txt", b"other contents")


def test_extract_logical_files_batch_returns_parsed_evidence(tmp_path: Path) -> None:
    archive_path = tmp_path / "logical.zip"
    _create_logical_zip(archive_path)

    source = make_evidence(
        source_path=archive_path,
        stored_path=archive_path,
        parent=None,
        acquisition_method=config.ACQUISITION_LOGICAL,
        type=config.EVIDENCE_TYPE_INPUT,
    )
    output_dir = tmp_path / "Documents" / "dfdof_results" / "CASE-001"

    extracted = extract_logical_files(
        source,
        output_dir,
        ["folder/deviceinfo.xml", "logs/other.txt"],
    )

    assert len(extracted) == 2
    assert (output_dir / "deviceinfo.xml").exists()
    assert (output_dir / "other.txt").exists()
    assert extracted[0].acquisition_method == config.ACQUISITION_EXTRACT_LOGICAL
    assert extracted[0].type == config.EVIDENCE_TYPE_EXTRACTED
    assert extracted[0].artefact_category == DEVICE_AND_BACKUP_INFO
    assert extracted[0].parent_sha256 == source.sha256
    assert extracted[0].source_path == "folder\\deviceinfo.xml"
    assert extracted[0].stored_path == output_dir / "deviceinfo.xml"
    assert extracted[0].sha256
    assert extracted[0].sha1
    assert extracted[0].hash_timestamp
    assert extracted[0].size == len(b"device info contents")


def test_extract_logical_files_hash_mismatch_raises(
    tmp_path: Path, monkeypatch
) -> None:
    archive = tmp_path / "test.zip"
    with zipfile.ZipFile(archive, "w") as z:
        z.writestr("file.txt", b"content")
    source = make_evidence(
        source_path=archive,
        stored_path=archive,
        parent=None,
        acquisition_method=config.ACQUISITION_LOGICAL,
        type=config.EVIDENCE_TYPE_INPUT,
    )
    import parsing.extract_logical as ext

    monkeypatch.setattr(ext, "hash_file", lambda _p: ("a" * 64, "b" * 40))
    with pytest.raises(RuntimeError, match="Verification failed"):
        extract_logical_files(source, tmp_path / "out", ["file.txt"])


