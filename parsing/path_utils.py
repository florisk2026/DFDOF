"""Path normalization utilities for forensic extraction.

Unified handling of path sanitization to ensure consistency.
"""

from __future__ import annotations

import re
from pathlib import Path, PurePosixPath
from typing import Any


def sanitise_path(relative_path: str) -> Path:
    """Normalise a forensic path into a safe relative filesystem path."""
    parts: list[str] = []
    for raw_part in PurePosixPath(relative_path.replace("\\", "/")).parts:
        if raw_part == "..":
            continue
        cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", raw_part).strip("._")
        if cleaned:
            parts.append(cleaned)
    return Path(*parts) if parts else Path("unnamed_file")


def to_windows_path(path: str) -> str:
    """Convert forward slashes to backslashes for unified forensic path notation in JSON."""
    return path.replace("/", "\\")


def safe_segment(value: str) -> str:
    """Sanitise a single path segment (filename or folder name)."""
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", value.strip()).strip("._")
    return cleaned or "unnamed"


def normalise_path_to_posix(value: str) -> PurePosixPath:
    """Convert a path string to PurePosixPath for structural analysis."""
    return PurePosixPath(value.replace("\\", "/"))


def normalise_scalar(value: Any) -> str | None:
    """Normalise a scalar value to a stripped string, or return None if empty."""
    if value is None:
        return None
    if isinstance(value, str):
        value = value.strip()
        return value or None
    text = str(value).strip()
    return text or None


def normalise_path(value: str, *, to_lower: bool = False) -> str:
    """Normalise a path-like string to forward-slash format."""
    normalised = PurePosixPath(value.replace("\\", "/")).as_posix().lstrip("./")
    return normalised.lower() if to_lower else normalised


def normalise_acquisition_method(value: str | None) -> str:
    """Normalize acquisition method string for comparisons."""
    if value is None:
        return ""
    return str(value).strip().lower()
