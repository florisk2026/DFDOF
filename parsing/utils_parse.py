"""Path normalization utilities for forensic extraction.

Unified handling of path sanitization to ensure consistency.
"""

from __future__ import annotations

import base64
import json
import plistlib
import re
import struct
import xml.etree.ElementTree as ET
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


def decode_base64(value: str) -> str | None:
    """Decode a base64 string. Return None if decoding fails or result is empty."""
    try:
        result = base64.b64decode(value.strip()).decode("utf-8", errors="replace").strip()
        return result or None
    except Exception:
        return None


def ieee754_long_to_degrees(value: str) -> str | None:
    """Convert a Java long-as-int64 IEEE754 bit pattern to a decimal degree string."""
    try:
        raw = int(value)
        packed = struct.pack(">q", raw)
        degrees = struct.unpack(">d", packed)[0]
        return str(round(degrees, 8))
    except Exception:
        return None


def parse_android_xml_map(path: Path) -> dict[str, str]:
    """Parse Android SharedPreferences XML <map> into a flat name→value dict."""
    try:
        root = ET.parse(path).getroot()
        result: dict[str, str] = {}
        for child in root:
            name = child.get("name")
            if not name:
                continue
            if child.tag == "string":
                text = (child.text or "").strip()
                if text:
                    result[name] = text
            elif child.tag in {"boolean", "int", "long", "float"}:
                val = child.get("value")
                if val is not None:
                    result[name] = val
        return result
    except Exception:
        return {}


def decode_cllocation_bplist(value: str) -> dict[str, str] | None:
    """Decode a base64 NSKeyedArchive binary plist of CLLocation; return canonical coordinate fields."""
    _KEY_MAP = {
        "kCLLocationCodingKeyCoordinateLatitude":  "find_aircraft_last_latitude",
        "kCLLocationCodingKeyCoordinateLongitude": "find_aircraft_last_longitude",
        "kCLLocationCodingKeyAltitude":            "find_aircraft_last_altitude",
        "kCLLocationCodingKeyHorizontalAccuracy":  "find_aircraft_last_hacc",
    }
    try:
        data = base64.b64decode(value.strip())
        archive = plistlib.loads(data)
        objects = archive.get("$objects", [])
        if len(objects) < 2 or not isinstance(objects[1], dict):
            return None
        obj = objects[1]
        out = {}
        for archive_key, canonical in _KEY_MAP.items():
            val = obj.get(archive_key)
            if val is not None:
                out[canonical] = str(round(float(val), 8))
        return out or None
    except Exception:
        return None


def parse_java_properties(path: Path) -> dict[str, str]:
    """Parse a Java .properties file into a flat key→value dict.

    Strips comment lines (#/!) and blank lines. Unescapes backslash sequences
    (e.g. \\: → :). Returns {} on read failure.
    """
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except Exception:
        return {}
    result: dict[str, str] = {}
    for line in lines:
        line = line.strip()
        if not line or line[0] in ("#", "!"):
            continue
        sep = -1
        i = 0
        while i < len(line):
            if line[i] == "\\":
                i += 2
                continue
            if line[i] in ("=", ":"):
                sep = i
                break
            i += 1
        if sep == -1:
            continue
        key = line[:sep].strip()
        value = line[sep + 1:].strip()
        value = re.sub(r"\\(.)", lambda m: m.group(1), value)
        if key:
            result[key] = value
    return result


def parse_json_file(path: Path) -> dict:
    """Load a JSON file and return the top-level dict. Return {} on failure."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def extract_fields(raw: dict, field_map: dict) -> dict[str, str | None]:
    """Apply a declarative field map to a raw dict.

    field_map structure: {"canonical_name": ([key1, key2, ...], decode_fn_or_None)}
    For each canonical field: try source keys in order; take the first non-None,
    non-empty string value; apply decode_fn if not None. Never raise.
    """
    out: dict[str, str | None] = {}
    for canonical, (keys, decode_fn) in field_map.items():
        for key in keys:
            raw_val = raw.get(key)
            if raw_val is None:
                continue
            val = str(raw_val).strip() if not isinstance(raw_val, str) else raw_val.strip()
            if not val:
                continue
            if decode_fn is not None:
                try:
                    val = decode_fn(val)
                except Exception:
                    val = None
            if val:
                out[canonical] = val
                break
    return out
