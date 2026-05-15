"""DFDOF Physical Image Reader.

Contains functions handling physical image files such as extracting and searching.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path
from typing import Any, Callable, Iterable

from config import (
    TSK_FLS,
    TSK_ICAT,
    TSK_MMLS,
    ACQUISITION_PHYSICAL_READER,
    EVIDENCE_TYPE_EXTRACTED,
    summarise_text,
)
from evidence import Evidence
from parsing.logical_reader import ensure_unique_path
from parsing.parse_utils import sanitise_path, to_windows_path

_FLS_LINE_RE = re.compile(r"^([rd]/[rd])\s+(\d+)(?:-\d+)?:\s+(.+)$")
_MMLS_ROW_RE = re.compile(r"^\s*\d+:\s+\S+\s+(\d+)\s+(\d+)\s+(\d+)\s+\S+\s+(.+)$")


def run_command(
    command: list[str], *, capture_output: bool = True, stdout=None
) -> subprocess.CompletedProcess[str]:
    """Run a command and return the completed process with text output."""
    return subprocess.run(
        command, capture_output=capture_output, text=True, check=False, stdout=stdout
    )


def _command_summary(result: subprocess.CompletedProcess[str]) -> dict[str, Any]:
    """Summarise a subprocess result for logging."""
    return {
        "return_code": result.returncode,
        "stdout": (summarise_text(result.stdout) if result.stdout else None),
        "stderr": (summarise_text(result.stderr) if result.stderr else None),
    }


def parse_mmls_offset(output: str) -> int:
    """Return the best sector offset from mmls output."""

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
        priority = (
            0 if any(marker in lowered for marker in ("primary", "logical")) else 1
        )
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


def extract_tsk_image(
    image_path: Path | str,
    working_dir: Path | str,
    *,
    include_paths: Iterable[str] | None = None,
    acquisition_method: str = ACQUISITION_PHYSICAL_READER,
    parent: Evidence | None = None,
    tool_log: Callable[[dict[str, Any]], None] | None = None,
    artefact_category: str | None = None,
    precomputed_entries: Iterable[tuple[str, int, str]] | None = None,
    offset_sectors: int | None = None,
) -> list[Evidence]:
    """Extract matching files from a raw image using mmls, fls, and icat.

    If `precomputed_entries` is provided, `mmls`/`fls` are not executed and those
    entries are used directly. If `offset_sectors` is provided, it is used for
    `fls`/`icat` calls instead of probing via `mmls`.
    """

    image_path = Path(image_path)
    working_dir = Path(working_dir)
    working_dir.mkdir(parents=True, exist_ok=True)

    # If precomputed entries are provided, use them and skip mmls/fls entirely.
    if precomputed_entries is not None:
        entries = [entry for entry in precomputed_entries if entry[0].startswith("r")]
        if not entries:
            raise RuntimeError(
                f"No regular file entries in precomputed entries for {image_path}"
            )
    else:
        # Determine offset either from provided value or by probing with mmls.
        if offset_sectors is None:
            mmls_result = run_command([str(TSK_MMLS), str(image_path)])
            if mmls_result.returncode != 0:
                raise RuntimeError(
                    f"mmls failed for {image_path}: {mmls_result.stderr or mmls_result.stdout}"
                )
            if tool_log is not None:
                tool_log(
                    {
                        "tool_name": "mmls",
                        "source_path": str(image_path),
                        **_command_summary(mmls_result),
                    }
                )
            offset_sectors = parse_mmls_offset(mmls_result.stdout or "")

        # Run fls with the resolved offset
        fls_result = run_command(
            [
                str(TSK_FLS),
                "-r",
                "-p",
                "-o",
                str(offset_sectors),
                str(image_path),
            ]
        )
        if fls_result.returncode != 0:
            raise RuntimeError(
                f"fls failed for {image_path}: {fls_result.stderr or fls_result.stdout}"
            )
        if tool_log is not None:
            tool_log(
                {
                    "tool_name": "fls",
                    "source_path": str(image_path),
                    "offset_sectors": offset_sectors,
                    **_command_summary(fls_result),
                }
            )
        entries = [
            entry
            for entry in list_fls_entries(fls_result.stdout or "")
            if entry[0].startswith("r")
        ]
        if not entries:
            raise RuntimeError(
                f"fls returned no file entries for {image_path}; the offset may be incorrect"
            )

    # Apply include_paths filter to both precomputed and dynamically-enumerated entries
    if include_paths:
        include_tokens = tuple(include_paths)
        entries = [
            entry
            for entry in entries
            if any(token.lower() in entry[2].lower() for token in include_tokens)
        ]

    extracted: list[Evidence] = []
    for _, inode, relative_path in entries:
        sanitised_relative = sanitise_path(relative_path)
        out_path = ensure_unique_path(working_dir / sanitised_relative.name)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with out_path.open("wb") as output_handle:
            icat_result = run_command(
                [
                    str(TSK_ICAT),
                    "-o",
                    str(offset_sectors or 0),
                    str(image_path),
                    str(inode),
                ],
                capture_output=False,
                stdout=output_handle,
            )
        if icat_result.returncode != 0:
            raise RuntimeError(f"icat failed for inode {inode} in {image_path}")
        if tool_log is not None:
            tool_log(
                {
                    "tool_name": "icat",
                    "source_path": str(image_path),
                    "offset_sectors": offset_sectors,
                    "inode": inode,
                    "output_path": str(out_path),
                    "cmd": str(TSK_ICAT),
                    **_command_summary(icat_result),
                }
            )
        extracted.append(
            Evidence(
                source_path=to_windows_path(relative_path),
                stored_path=out_path,
                parent=parent,
                acquisition_method=acquisition_method,
                type=EVIDENCE_TYPE_EXTRACTED,
                artefact_category=artefact_category,
            )
        )

    return extracted
