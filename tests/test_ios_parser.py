from __future__ import annotations

import hashlib
import plistlib
import sqlite3
import zipfile
from pathlib import Path

from parsing.ios_parser import parse_ios_backup


def _build_manifest_db(path: Path, file_id: str) -> None:
    connection = sqlite3.connect(path)
    cursor = connection.cursor()
    cursor.execute("CREATE TABLE Files (fileID TEXT, domain TEXT, relativePath TEXT)")
    cursor.execute(
        "INSERT INTO Files (fileID, domain, relativePath) VALUES (?, ?, ?)",
        (file_id, "AppDomain-com.example.dji", "Documents/logs/deviceinfo.xml"),
    )
    connection.commit()
    connection.close()


def _create_backup_zip(zip_path: Path, file_id: str) -> None:
    manifest_db = zip_path.parent / "Manifest.db"
    _build_manifest_db(manifest_db, file_id)

    info_plist = plistlib.dumps(
        {
            "Device Name": "Test iPhone",
            "GUID": "ABC-123",
            "Serial Number": "SERIAL-001",
            "Last Backup Date": "2026-05-04",
        }
    )

    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.write(manifest_db, arcname="Manifest.db")
        archive.writestr("Info.plist", info_plist)
        archive.writestr(f"{file_id[:2]}/{file_id}", b"deviceinfo contents")


def test_parse_ios_backup_exports_domain_layout(tmp_path: Path) -> None:
    file_id = hashlib.sha1(b"AppDomain-com.example.dji-Documents/logs/deviceinfo.xml").hexdigest()
    archive_path = tmp_path / "backup.zip"
    _create_backup_zip(archive_path, file_id)

    output_root = tmp_path / "results"
    result = parse_ios_backup(archive_path, output_root=output_root)

    exported_file = result.domains_root / "AppDomain-com.example.dji" / "Documents" / "logs" / "deviceinfo.xml"
    assert exported_file.exists()
    assert exported_file.read_bytes() == b"deviceinfo contents"

    assert (result.output_root / "conversion_index.json").exists()
    assert (result.output_root / "conversion_index.csv").exists()
    assert (result.output_root / "backup_info.json").exists()
    assert result.records[0].extracted is True
