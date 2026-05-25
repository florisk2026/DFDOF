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

_RE_UNSAFE_CHARS = re.compile(r"[^A-Za-z0-9._-]+")
_RE_BACKSLASH_ESCAPE = re.compile(r"\\(.)")


def sanitise_path(relative_path: str) -> Path:
    """Normalise a forensic path into a safe relative filesystem path."""
    parts: list[str] = []
    for raw_part in PurePosixPath(relative_path.replace("\\", "/")).parts:
        if raw_part == "..":
            continue
        cleaned = _RE_UNSAFE_CHARS.sub("_", raw_part).strip("._")
        if cleaned:
            parts.append(cleaned)
    return Path(*parts) if parts else Path("unnamed_file")


def to_windows_path(path: str) -> str:
    """Convert forward slashes to backslashes for unified forensic path notation in JSON."""
    return path.replace("/", "\\")


def safe_segment(value: str) -> str:
    """Sanitise a single path segment (filename or folder name)."""
    cleaned = _RE_UNSAFE_CHARS.sub("_", value.strip()).strip("._")
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



def _build_label_patterns(labels: tuple[str, ...]) -> re.Pattern[str]:
    """Return a single compiled pattern that matches any label in either key=value or plist-XML form."""
    parts: list[str] = []
    for label in labels:
        escaped = re.escape(label)
        parts.append(rf"{escaped}\s*[:=]\s*([^\r\n<]+)")
        parts.append(
            rf"<key>\s*{escaped}\s*</key>\s*<(?:string|date|integer|real)>\s*(.*?)\s*</(?:string|date|integer|real)>"
        )
    return re.compile("|".join(f"(?:{p})" for p in parts), re.IGNORECASE | re.DOTALL)


_LABEL_PATTERN_CACHE: dict[tuple[str, ...], re.Pattern[str]] = {}


def match_labeled_value(text: str, labels: tuple[str, ...]) -> str | None:
    """Find the first value matching any label in plain or plist-style XML text."""
    pattern = _LABEL_PATTERN_CACHE.get(labels)
    if pattern is None:
        pattern = _build_label_patterns(labels)
        _LABEL_PATTERN_CACHE[labels] = pattern
    match = pattern.search(text)
    if match:
        return normalise_scalar(next(g for g in match.groups() if g is not None))
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


def decode_cllocation_bplist(value: bytes | str) -> dict[str, str] | None:
    """Decode a CLLocation NSKeyedArchive binary plist; return canonical coordinate fields.

    Accepts raw bytes or a base64-encoded string.
    """
    _KEY_MAP = {
        "kCLLocationCodingKeyCoordinateLatitude":  "find_aircraft_last_latitude",
        "kCLLocationCodingKeyCoordinateLongitude": "find_aircraft_last_longitude",
        "kCLLocationCodingKeyAltitude":            "find_aircraft_last_altitude",
        "kCLLocationCodingKeyHorizontalAccuracy":  "find_aircraft_last_hacc",
    }
    try:
        data = base64.b64decode(value.strip()) if isinstance(value, str) else value
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


def decode_bytes_blobs(data: Any, _safe: Any = None) -> Any:
    """Recursively decode {"__bytes_base64": "..."} blobs produced by json_safe().

    Tries plistlib first (recursive sub-tree), then UTF-8 text.
    Falls back to leaving the blob unchanged if neither succeeds.
    _safe: optional callable (json_safe) applied to decoded plist sub-trees.
    """
    if isinstance(data, dict):
        b64 = data.get("__bytes_base64")
        if b64 and len(data) == 1:
            try:
                raw = base64.b64decode(b64)
            except Exception:
                return data
            try:
                parsed = plistlib.loads(raw)
                normalised = _safe(parsed) if _safe else parsed
                return decode_bytes_blobs(normalised, _safe)
            except Exception:
                pass
            try:
                text = raw.decode("utf-8").strip()
                if text:
                    return text
            except Exception:
                pass
            return data
        return {k: decode_bytes_blobs(v, _safe) for k, v in data.items()}
    if isinstance(data, list):
        return [decode_bytes_blobs(item, _safe) for item in data]
    return data


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
        value = _RE_BACKSLASH_ESCAPE.sub(lambda m: m.group(1), value)
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
