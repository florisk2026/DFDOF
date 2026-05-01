"""TSK-based mounting and extraction helpers for DFDOF.

This stays intentionally small: identify the offset, enumerate files, and
extract matching targets into a working directory.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Iterable

from config import TSK_FLS, TSK_ICAT, TSK_MMLS
from evidence import Evidence

_FLS_LINE_RE = re.compile(r"^([rd]/[rd])\s+(\d+)(?:-\d+)?:\s+(.+)$")
_MMLS_ROW_RE = re.compile(r"^\s*\d+:\s+\S+\s+(\d+)\s+(\d+)\s+(\d+)\s+\S+\s+(.+)$")


def _run_command(command: list[str], *, capture_output: bool = True, stdout=None) -> subprocess.CompletedProcess[str]:
	return subprocess.run(command, capture_output=capture_output, text=True, check=False, stdout=stdout)


def _command_summary(result: subprocess.CompletedProcess[str]) -> dict[str, Any]:
	return {
		"return_code": result.returncode,
		"stdout": (result.stdout or "")[:1000],
		"stderr": (result.stderr or "")[:1000],
	}


def parse_mmls_offset(output: str) -> int:
	"""Return the best sector offset from mmls output.

	The parser prefers data-bearing rows and then falls back to the largest
	plausible partition if the output is sparse.
	"""

	candidates: list[tuple[int, int, int]] = []
	for line in output.splitlines():
		match = _MMLS_ROW_RE.match(line)
		if not match:
			continue
		start_sector = int(match.group(1))
		length = int(match.group(3))
		description = match.group(4).strip()
		if start_sector == 0:
			continue
		lowered = description.lower()
		if any(marker in lowered for marker in ("unallocated", "meta")):
			continue
		priority = 0 if any(marker in lowered for marker in ("primary", "logical")) else 1
		candidates.append((priority, -length, start_sector))

	if not candidates:
		raise ValueError("Unable to determine filesystem offset from mmls output")

	candidates.sort()
	return candidates[0][2]


def list_fls_entries(output: str) -> list[tuple[str, int, str]]:
	"""Parse fls output into a list of (kind, inode, relative_path) tuples."""

	entries: list[tuple[str, int, str]] = []
	for line in output.splitlines():
		match = _FLS_LINE_RE.match(line)
		if not match:
			continue
		kind = match.group(1)
		inode = int(match.group(2))
		relative_path = match.group(3).strip()
		entries.append((kind, inode, relative_path))
	return entries


def sanitise_path(relative_path: str) -> Path:
	"""Normalise a forensic path into a safe relative filesystem path."""

	parts: list[str] = []
	for raw_part in PurePosixPath(relative_path.replace("\\", "/")).parts:
		if raw_part in ("", ".", "/"):
			continue
		if raw_part == "..":
			continue
		cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", raw_part).strip("._")
		if cleaned:
			parts.append(cleaned)
	return Path(*parts) if parts else Path("unnamed_file")


def extract_tsk_image(
	image_path: Path | str,
	working_dir: Path | str,
	*,
	include_paths: Iterable[str] | None = None,
	provenance: str = "tsk_mounter",
	parent: Evidence | None = None,
	tool_log: Callable[[dict[str, Any]], None] | None = None,
) -> list[Evidence]:
	"""Extract matching files from a raw image using mmls, fls, and icat."""

	image_path = Path(image_path)
	working_dir = Path(working_dir)
	working_dir.mkdir(parents=True, exist_ok=True)

	mmls_result = _run_command([str(TSK_MMLS), str(image_path)])
	if mmls_result.returncode != 0:
		raise RuntimeError(f"mmls failed for {image_path}: {mmls_result.stderr or mmls_result.stdout}")
	if tool_log is not None:
		tool_log({"tool_name": "mmls", "source_path": str(image_path), **_command_summary(mmls_result)})
	offset_sectors = parse_mmls_offset(mmls_result.stdout or "")

	fls_result = _run_command([
		str(TSK_FLS),
		"-r",
		"-p",
		"-o",
		str(offset_sectors),
		str(image_path),
	])
	if fls_result.returncode != 0:
		raise RuntimeError(f"fls failed for {image_path}: {fls_result.stderr or fls_result.stdout}")
	if tool_log is not None:
		tool_log({"tool_name": "fls", "source_path": str(image_path), "offset_sectors": offset_sectors, **_command_summary(fls_result)})
	entries = [entry for entry in list_fls_entries(fls_result.stdout or "") if entry[0].startswith("r")]
	if not entries:
		raise RuntimeError(f"fls returned no file entries for {image_path}; the offset may be incorrect")

	if include_paths:
		include_tokens = tuple(include_paths)
		entries = [entry for entry in entries if any(token.lower() in entry[2].lower() for token in include_tokens)]

	extracted: list[Evidence] = []
	for _, inode, relative_path in entries:
		out_path = working_dir / sanitise_path(relative_path)
		out_path.parent.mkdir(parents=True, exist_ok=True)
		with out_path.open("wb") as output_handle:
			icat_result = _run_command(
				[str(TSK_ICAT), "-o", str(offset_sectors), str(image_path), str(inode)],
				capture_output=False,
				stdout=output_handle,
			)
		if icat_result.returncode != 0:
			raise RuntimeError(f"icat failed for inode {inode} in {image_path}")
		if tool_log is not None:
			tool_log({"tool_name": "icat", "source_path": str(image_path), "inode": inode, "output_path": str(out_path), **_command_summary(icat_result)})
		extracted.append(
			Evidence(
				out_path,
				provenance=f"{provenance}:{relative_path}",
				parent=parent,
				source_role="derived",
				acquisition_method="tsk",
				artefact_category=None,
			)
		)

	return extracted

