"""Path normalization utilities for forensic extraction.

Unified handling of path sanitization across ZIP member names, fls output,
and filesystem paths to ensure consistent, safe relative paths.
"""

from __future__ import annotations

import re
from pathlib import Path, PurePosixPath


def normalise_path(value: str, *, to_lower: bool = False) -> str:
	"""Normalize a path-like string to forward-slash format.
	
	Args:
		value: Input path string (may contain backslashes or mixed separators).
		to_lower: If True, convert to lowercase.
	
	Returns:
		Normalized posix path string.
	"""
	normalized = PurePosixPath(value.replace("\\", "/")).as_posix().lstrip("./")
	return normalized.lower() if to_lower else normalized


# Provide an American-spelling alias for callers using `normalize_path`.
def normalize_path(value: str, *, to_lower: bool = False) -> str:
	return normalise_path(value, to_lower=to_lower)


def sanitise_path(relative_path: str) -> Path:
	"""Normalize a forensic path into a safe relative filesystem path.
	
	Removes traversal attempts, normalizes separators, and sanitizes characters
	to ensure safe on-disk storage without path injection risks.
	
	Args:
		relative_path: Forensic path from extraction tool (fls, ZIP member, etc).
	
	Returns:
		Safe Path object suitable for filesystem operations.
	"""
	parts: list[str] = []
	for raw_part in PurePosixPath(relative_path.replace("\\", "/")).parts:
		if raw_part in ("", ".", "/"):
			continue
		if raw_part == "..":
			continue
		# Replace non-alphanumeric chars (except . _ -) with underscore
		cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", raw_part).strip("._")
		if cleaned:
			parts.append(cleaned)
	return Path(*parts) if parts else Path("unnamed_file")
