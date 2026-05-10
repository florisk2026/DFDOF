"""DFDOF Logical Image Reader.

Contains functions handling ZIP archives such as extracting and searching.
"""

from __future__ import annotations

import hashlib
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, cast

from config import (
	DEVICE_AND_BACKUP_INFO,
	ACQUISITION_LOGICAL_READER,
	EVIDENCE_TYPE_EXTRACTED,
	EXTENSION_ZIP,
)
from evidence import Evidence, hash_file
from parsing.path_utils import normalise_path, sanitise_path


def _copy_zip_member(zip_file: zipfile.ZipFile, member: str, output_path: Path) -> str:
	output_path.parent.mkdir(parents=True, exist_ok=True)
	hasher = hashlib.sha256()
	with zip_file.open(member) as source_handle, output_path.open("wb") as target_handle:
		while True:
			chunk = source_handle.read(1024 * 1024)
			if not chunk:
				break
			hasher.update(chunk)
			target_handle.write(chunk)
	return hasher.hexdigest()


def _resolve_member_name(archive_names: list[str], requested: str) -> str:
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
		member_paths = [PurePosixPath(name.replace("\\", "/")) for name in archive.namelist() if not name.endswith("/")]
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
			pdf_members = [member for member in members if member.suffix.lower() == ".pdf"]
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
	"""Extract a batch of files from a ZIP-backed logical source and return derived Evidence objects."""

	archive_path = cast(Path, source_evidence.stored_path)
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
			copied_path = output_dir / sanitise_path(member_name)
			archive_hash = _copy_zip_member(archive, member_name, copied_path)
			file_hash = hash_file(copied_path)[0]
			if archive_hash != file_hash:
				raise RuntimeError(
					f"Verification failed for {member_name}: archive_sha256={archive_hash} file_sha256={file_hash}"
				)
			extracted.append(Evidence(
				source_path=member_name,
				stored_path=copied_path,
				parent=source_evidence,
			acquisition_method=ACQUISITION_LOGICAL_READER,
			type=EVIDENCE_TYPE_EXTRACTED,
				artefact_category=artefact_category,
			))

	return extracted


def extract_logical_member(
	source_evidence: Evidence,
	output_dir: Path | str,
	member_name: str,
	*,
	output_name: str | None = None,
	artefact_category: str = DEVICE_AND_BACKUP_INFO,
	values: dict[str, Any] | None = None,
) -> Evidence:
	"""Extract one ZIP member into the destination directory and return derived Evidence."""

	archive_path = cast(Path, source_evidence.stored_path)
	if archive_path.suffix.lower() != EXTENSION_ZIP[0]:
		raise ValueError(f"Logical extraction expects a ZIP archive: {archive_path}")

	output_dir = Path(output_dir)
	output_dir.mkdir(parents=True, exist_ok=True)

	with zipfile.ZipFile(archive_path) as archive:
		archive_names = archive.namelist()
		resolved_member = _resolve_member_name(archive_names, member_name)
		copied_path = output_dir / (output_name or Path(resolved_member).name)
		archive_hash = _copy_zip_member(archive, resolved_member, copied_path)
		file_hash = hash_file(copied_path)[0]
		if archive_hash != file_hash:
			raise RuntimeError(
				f"Verification failed for {resolved_member}: archive_sha256={archive_hash} file_sha256={file_hash}"
			)

	evidence = Evidence(
		source_path=resolved_member,
		stored_path=copied_path,
		parent=source_evidence,
		acquisition_method=ACQUISITION_LOGICAL_READER,
		type=EVIDENCE_TYPE_EXTRACTED,
		artefact_category=artefact_category,
		values=values,
	)
	return evidence
