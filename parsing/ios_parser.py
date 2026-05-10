"""DFDOF iOS Backup Parser.

Converts an iTunes backup via:
- mappings between hashes and domains are derived from `Manifest.db`,
- the hashed payload files live in the 00-ff directory fan-out inside the zip,
- files are exported into the case directory under `Documents/dfdof_output`.
"""

from __future__ import annotations

import csv
import hashlib
import json
import logging
import plistlib
import re
import sqlite3
import tempfile
import zipfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any
from config import EXTENSION_ZIP, output_dir
from evidence import hash_file

logger = logging.getLogger(__name__)


BACKUP_METADATA_NAMES = {"manifest.db", "manifest.plist", "info.plist", "status.plist"}


@dataclass(slots=True)
class BackupRecord:
    file_id: str
    domain: str
    relative_path: str
    source_member: str | None
    output_path: str | None
    extracted: bool


@dataclass(slots=True)
class ConversionResult:
    source_archive: Path
    output_root: Path
    metadata_root: Path
    domains_root: Path
    records: list[BackupRecord]
    metadata_files: list[Path]

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_archive": str(self.source_archive),
            "output_root": str(self.output_root),
            "metadata_root": str(self.metadata_root),
            "domains_root": str(self.domains_root),
            "metadata_files": [str(path) for path in self.metadata_files],
            "records": [asdict(record) for record in self.records],
        }


def _safe_segment(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", value.strip()).strip("._")
    return cleaned or "unnamed"


def _safe_relative_path(value: str) -> Path:
    parts: list[str] = []
    for raw_part in Path(value.replace("\\", "/")).parts:
        if raw_part in {"", ".", "/", ".."}:
            continue
        parts.append(_safe_segment(raw_part))
    return Path(*parts) if parts else Path("unnamed_file")


def _sha1_backup_key(domain: str, relative_path: str) -> str:
    """Derive the classic iTunes backup file identifier when the manifest lacks one."""

    # Encode defensively and warn if any characters are replaced during encoding.
    raw = f"{domain}-{relative_path}"
    payload = raw.encode("utf-8", errors="replace")
    # Detect replacement by round-tripping and comparing
    roundtrip = payload.decode("utf-8", errors="replace")
    if roundtrip != raw:
        logger.warning(
            "Encoding replacement occurred while deriving backup key: domain=%s relative_path=%s",
            domain,
            relative_path,
        )
    return hashlib.sha1(payload).hexdigest()


def _manifest_db_member(zip_file: zipfile.ZipFile) -> str:
    for name in zip_file.namelist():
        if Path(name).name.lower() == "manifest.db":
            return name
    raise FileNotFoundError("Manifest.db not found in the provided archive")


def _metadata_members(zip_file: zipfile.ZipFile) -> list[str]:
    return [name for name in zip_file.namelist() if Path(name).name.lower() in BACKUP_METADATA_NAMES]


def _extract_zip_member(zip_file: zipfile.ZipFile, member: str, output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with zip_file.open(member) as source_handle, output_path.open("wb") as target_handle:
        while True:
            chunk = source_handle.read(1024 * 1024)
            if not chunk:
                break
            target_handle.write(chunk)


def _copy_metadata(zip_file: zipfile.ZipFile, metadata_root: Path) -> list[Path]:
    copied: list[Path] = []
    for member in _metadata_members(zip_file):
        output_path = metadata_root / _safe_segment(Path(member).name)
        # Extract while computing SHA-256 of the archive member
        output_path.parent.mkdir(parents=True, exist_ok=True)
        archive_hasher = hashlib.sha256()
        with zip_file.open(member) as source_handle, output_path.open("wb") as target_handle:
            while True:
                chunk = source_handle.read(1024 * 1024)
                if not chunk:
                    break
                archive_hasher.update(chunk)
                target_handle.write(chunk)

        archive_hash = archive_hasher.hexdigest()

        # Re-hash the written file and compare to ensure the write matched the archive bytes
        file_hash = hash_file(output_path)[0]

        if archive_hash != file_hash:
            output_str = str(output_path)
            logger.warning(
                "Metadata hash mismatch for %s -> written file %s: archive_sha256=%s file_sha256=%s",
                member,
                output_str,
                archive_hash,
                file_hash,
            )
            raise RuntimeError(
                f"Metadata verification failed for {member} (written to {output_str}): archive_sha256={archive_hash} file_sha256={file_hash}"
            )

        copied.append(output_path)
    return copied


def _extract_manifest_db(zip_file: zipfile.ZipFile, manifest_member: str, manifest_root: Path) -> Path:
    manifest_path = manifest_root / "Manifest.db"
    _extract_zip_member(zip_file, manifest_member, manifest_path)
    return manifest_path


def _candidate_tables(cursor: sqlite3.Cursor) -> list[str]:
    rows = cursor.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name").fetchall()
    return [row[0] for row in rows]


def _column_map(cursor: sqlite3.Cursor, table_name: str) -> dict[str, str]:
    rows = cursor.execute(f'PRAGMA table_info("{table_name.replace("\"", "\"\"")}")').fetchall()
    return {row[1].lower(): row[1] for row in rows}


def _manifest_rows(manifest_db_path: Path) -> list[BackupRecord]:
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as temp_handle:
        temp_copy = Path(temp_handle.name)

    try:
        temp_copy.write_bytes(manifest_db_path.read_bytes())
        connection = sqlite3.connect(temp_copy)
        connection.row_factory = sqlite3.Row
        cursor = connection.cursor()

        for table_name in _candidate_tables(cursor):
            columns = _column_map(cursor, table_name)
            file_id_col = columns.get("fileid") or columns.get("file_id")
            domain_col = columns.get("domain")
            relative_path_col = columns.get("relativepath") or columns.get("relative_path") or columns.get("path")
            if not (file_id_col and domain_col and relative_path_col):
                continue

            query = (
                f'SELECT "{file_id_col}" AS file_id, '
                f'"{domain_col}" AS domain, '
                f'"{relative_path_col}" AS relative_path '
                f'FROM "{table_name}" '
                f'ORDER BY domain, relative_path'
            )
            records: list[BackupRecord] = []
            for row in cursor.execute(query):
                file_id = str(row["file_id"] or "").strip().lower()
                domain = str(row["domain"] or "").strip()
                relative_path = str(row["relative_path"] or "").strip()
                if not file_id:
                    file_id = _sha1_backup_key(domain, relative_path)
                records.append(BackupRecord(file_id=file_id, domain=domain, relative_path=relative_path, source_member=None, output_path=None, extracted=False))

            if records:
                connection.close()
                return records

        connection.close()
        return []
    finally:
        if temp_copy.exists():
            temp_copy.unlink(missing_ok=True)


def _member_for_file_id(zip_file: zipfile.ZipFile, file_id: str) -> str | None:
    file_id = file_id.lower()
    direct_candidates = [file_id, f"{file_id[:2]}/{file_id}", f"{file_id[:2].upper()}/{file_id}"]
    names = zip_file.namelist()
    lower_lookup = {name.lower(): name for name in names}

    for candidate in direct_candidates:
        if candidate.lower() in lower_lookup:
            return lower_lookup[candidate.lower()]

    for name in names:
        if Path(name).name.lower() == file_id:
            return name
    return None


def _write_index(result: ConversionResult) -> None:
    json_path = result.output_root / "conversion_index.json"
    csv_path = result.output_root / "conversion_index.csv"

    json_path.write_text(json.dumps(result.to_dict(), indent=2, sort_keys=True), encoding="utf-8")

    with csv_path.open("w", encoding="utf-8", newline="") as csv_handle:
        writer = csv.DictWriter(
            csv_handle,
            fieldnames=["file_id", "domain", "relative_path", "source_member", "output_path", "extracted"],
        )
        writer.writeheader()
        for record in result.records:
            writer.writerow(asdict(record))


def _parse_info_plist(metadata_root: Path) -> dict[str, Any]:
    info_path = metadata_root / "Info.plist"
    if not info_path.exists():
        return {}
    try:
        return plistlib.loads(info_path.read_bytes())
    except Exception:
        return {}


def _json_safe(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(key): _json_safe(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_json_safe(item) for item in value]
    if isinstance(value, tuple):
        return [_json_safe(item) for item in value]
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    if hasattr(value, "isoformat"):
        try:
            return value.isoformat()
        except Exception:
            return str(value)
    return value


def convert_ios_backup(archive_path: Path | str, output_root: Path | str | None = None) -> ConversionResult:
    """Convert a zipped iTunes-style iOS backup into a readable domain tree."""

    archive_path = Path(archive_path)
    if not archive_path.exists():
        raise FileNotFoundError(f"Archive not found: {archive_path}")
    if archive_path.suffix.lower() != EXTENSION_ZIP[0]:
        raise ValueError("This converter expects a zipped iTunes backup")

    result_root = Path(output_root) if output_root is not None else output_dir() / "controller_ios_parsed"
    result_root = Path(result_root)
    metadata_root = result_root / "_metadata"
    domains_root = result_root / "domains"
    metadata_root.mkdir(parents=True, exist_ok=True)
    domains_root.mkdir(parents=True, exist_ok=True)

    with zipfile.ZipFile(archive_path) as zip_file:
        manifest_member = _manifest_db_member(zip_file)
        metadata_files = _copy_metadata(zip_file, metadata_root)
        manifest_db_path = _extract_manifest_db(zip_file, manifest_member, metadata_root)
        records = _manifest_rows(manifest_db_path)

        for record in records:
            domain_dir = domains_root / _safe_segment(record.domain or "_unknown")
            relative_target = _safe_relative_path(record.relative_path) if record.relative_path else Path(record.file_id)
            output_path = domain_dir / relative_target
            member = _member_for_file_id(zip_file, record.file_id)
            record.source_member = member
            record.output_path = str(output_path)
            if member is None:
                continue
            _extract_zip_member(zip_file, member, output_path)
            record.extracted = True

    result = ConversionResult(
        source_archive=archive_path,
        output_root=result_root,
        metadata_root=metadata_root,
        domains_root=domains_root,
        records=records,
        metadata_files=metadata_files,
    )

    _write_index(result)

    backup_info = _parse_info_plist(metadata_root)
    if backup_info:
        (result_root / "backup_info.json").write_text(
            json.dumps(_json_safe(backup_info), indent=2, sort_keys=True),
            encoding="utf-8",
        )

    return result
