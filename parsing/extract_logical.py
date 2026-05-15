"""DFDOF Logical Image Reader.

Contains functions handling ZIP archives such as extracting and searching.
"""

from __future__ import annotations

import hashlib
import zipfile
from pathlib import Path, PurePosixPath
from typing import Iterable

from config import (
    DEVICE_AND_BACKUP_INFO,
    ACQUISITION_EXRACT_LOGICAL,
    EVIDENCE_TYPE_EXTRACTED,
    EXTENSION_ZIP,
)
from evidence import Evidence, hash_file
from parsing.utils_parse import normalise_path, to_windows_path, normalise_path_to_posix


def ensure_unique_path(target: Path) -> Path:
    """Return a non-colliding path by appending a numeric suffix if the target exists."""
    if not target.exists():
        return target
    stem, suffix = target.stem, target.suffix
    for idx in range(1, 1000):
        candidate = target.with_name(f"{stem}_{idx}{suffix}")
        if not candidate.exists():
            return candidate
    return target.with_name(f"{stem}_overflow{suffix}")


def copy_zip_member(zip_file: zipfile.ZipFile, member: str, output_path: Path) -> str:
    """Copy a member from the ZIP archive to the output path, returning the SHA256 hash of the extracted file."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    hasher = hashlib.sha256()
    with zip_file.open(member) as source_handle, output_path.open(
        "wb"
    ) as target_handle:
        while True:
            chunk = source_handle.read(1024 * 1024)
            if not chunk:
                break
            hasher.update(chunk)
            target_handle.write(chunk)
    return hasher.hexdigest()


def _resolve_member_name(archive_names: list[str], requested: str) -> str:
    """Resolve a requested member name against the archive's namelist with flexible matching."""
    requested_normalised = normalise_path(requested, to_lower=True)
    exact_lookup: dict[str, str] = {}
    basename_lookup: dict[str, list[str]] = {}
    for name in archive_names:
        normalised = normalise_path(name, to_lower=True)
        exact_lookup.setdefault(normalised, name)
        basename_lookup.setdefault(Path(normalised).name, []).append(name)

    resolved = exact_lookup.get(requested_normalised)
    if resolved is not None:
        return resolved

    basename_matches = basename_lookup.get(Path(requested_normalised).name, [])
    if len(basename_matches) == 1:
        return basename_matches[0]

    raise FileNotFoundError(f"Archive member not found: {requested}")


def find_acquisition_pdf_member(archive_path: Path | str) -> str | None:
    """Return the best acquisition PDF member from a ZIP archive."""

    archive_path = Path(archive_path)
    with zipfile.ZipFile(archive_path) as archive:
        member_paths = [
            normalise_path_to_posix(name)
            for name in archive.namelist()
            if not name.endswith("/")
        ]
        folder_candidates: dict[PurePosixPath, list[PurePosixPath]] = {}
        for member_path in member_paths:
            depth = len(member_path.parts) - 1
            if depth not in {1, 2}:
                continue
            if member_path.suffix.lower() not in {".pdf", ".txt"}:
                continue
            folder_candidates.setdefault(member_path.parent, []).append(member_path)

        best_score: tuple[int, int, str] | None = None
        best_member: str | None = None
        for folder, members in folder_candidates.items():
            pdf_members = [
                member for member in members if member.suffix.lower() == ".pdf"
            ]
            if not pdf_members:
                continue
            has_txt = any(member.suffix.lower() == ".txt" for member in members)
            score = (0 if has_txt else 1, len(folder.parts), str(folder))
            if best_score is None or score < best_score:
                best_score = score
                best_member = pdf_members[0].as_posix()

        return best_member


def extract_logical_files(
    source_evidence: Evidence,
    output_dir: Path | str,
    search_members: Iterable[str],
    *,
    artefact_category: str = DEVICE_AND_BACKUP_INFO,
    missing_ok: bool = False,
) -> list[Evidence]:
    """Extract a batch of files from a ZIP-backed logical source and return derived Evidence objects.

    Each file is written flat into output_dir using only its basename. The original
    archive-relative path is preserved in Evidence.source_path for provenance. Filename
    collisions are resolved by appending a numeric suffix.
    """

    archive_path = Path(str(source_evidence.stored_path))
    if archive_path.suffix.lower() != EXTENSION_ZIP[0]:
        raise ValueError(f"Logical extraction expects a ZIP archive: {archive_path}")

    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    requested_members = list(search_members)
    extracted: list[Evidence] = []

    with zipfile.ZipFile(archive_path) as archive:
        archive_names = archive.namelist()
        for requested in requested_members:
            try:
                member_name = _resolve_member_name(archive_names, requested)
            except FileNotFoundError:
                if missing_ok:
                    continue
                raise

            # Write flat: only the basename, no archive subdirectories.
            output_path = ensure_unique_path(output_dir / Path(member_name).name)
            archive_hash = copy_zip_member(archive, member_name, output_path)
            file_hash = hash_file(output_path)[0]

            if archive_hash != file_hash:
                raise RuntimeError(
                    f"Verification failed for {member_name}: "
                    f"archive_sha256={archive_hash} file_sha256={file_hash}"
                )

            extracted.append(
                Evidence(
                    source_path=to_windows_path(member_name),
                    stored_path=output_path,
                    parent=source_evidence,
                    acquisition_method=ACQUISITION_EXRACT_LOGICAL,
                    type=EVIDENCE_TYPE_EXTRACTED,
                    artefact_category=artefact_category,
                )
            )

    return extracted
