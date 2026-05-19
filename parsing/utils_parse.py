"""Path normalization utilities for forensic extraction.

Unified handling of path sanitization to ensure consistency.
"""

from __future__ import annotations

import plistlib
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


def parse_plist_file(path: Path) -> dict[str, Any]:
    """Parse a plist file and return a dictionary, or an empty dict on failure."""
    if not path.exists():
        return {}
    try:
        parsed = plistlib.loads(path.read_bytes())
    except Exception:
        return {}
    return parsed if isinstance(parsed, dict) else {}


def parse_plist_strict(path: Path) -> dict[str, Any]:
    """Parse a plist file, raising on failure. Wraps non-dict roots as {"value": data}."""
    with path.open("rb") as fh:
        data = plistlib.load(fh)
    return data if isinstance(data, dict) else {"value": data}


def parse_xml_flat(path: Path) -> dict[str, Any]:
    """Parse an XML file into a flat tag→value dict; repeated tags become lists."""
    import xml.etree.ElementTree as ET
    tree = ET.parse(path)
    root = tree.getroot()
    parsed: dict[str, Any] = {}
    for element in root.iter():
        text = (element.text or "").strip()
        if not text:
            continue
        if element.tag in parsed:
            existing = parsed[element.tag]
            if isinstance(existing, list):
                existing.append(text)
            else:
                parsed[element.tag] = [existing, text]
        else:
            parsed[element.tag] = text
    return parsed


def match_labeled_value(text: str, labels: tuple[str, ...]) -> str | None:
    """Find the first value matching any label in plain or plist-style XML text."""
    patterns: list[str] = []
    for label in labels:
        escaped = re.escape(label)
        patterns.extend(
            [
                rf"{escaped}\s*[:=]\s*([^\r\n<]+)",
                rf"<key>\s*{escaped}\s*</key>\s*<(?:string|date|integer|real)>\s*(.*?)\s*</(?:string|date|integer|real)>",
            ]
        )
    for pattern in patterns:
        match = re.search(pattern, text, flags=re.IGNORECASE | re.DOTALL)
        if match:
            return normalise_scalar(match.group(1))
    return None
