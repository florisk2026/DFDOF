"""Phase utilities for identification and evidence matching.

Shared helpers used across phases for evidence source matching and identification.
"""

from __future__ import annotations

import base64
import json
import math
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any

from evidence import Evidence

if TYPE_CHECKING:
    from state import State


def json_safe(value: Any) -> Any:
    """Recursively convert a value to a JSON-serializable form.

    - bytes/bytearray  → {"__bytes_base64": "<b64>"}
    - dict             → keys coerced to str, values recursed
    - list/tuple       → list with values recursed
    - objects with .isoformat() → ISO string
    - str/int/float/bool/None   → unchanged
    - anything else    → str() fallback, None on failure
    """
    if isinstance(value, (bytes, bytearray)):
        return {"__bytes_base64": base64.b64encode(bytes(value)).decode("ascii")}
    if isinstance(value, dict):
        return {str(k): json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [json_safe(v) for v in value]
    if hasattr(value, "isoformat"):
        try:
            return value.isoformat()
        except Exception:
            return str(value)
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    try:
        return str(value)
    except Exception:
        return None


def compact_json(data: Any) -> str:
    """JSON with indent=2 but integer-only arrays and P5 column-check arrays on a single line."""
    text = json.dumps(data, indent=2)

    def _collapse(m: re.Match) -> str:
        items = [x.strip() for x in m.group(1).split(",") if x.strip()]
        return "[" + ", ".join(items) + "]"

    # Collapse integer-only arrays (row-ID lists, etc.).
    text = re.sub(r"\[(\s*\d+(?:,\s*\d+)*\s*)\]", _collapse, text, flags=re.DOTALL)
    # Collapse string arrays only for the two P5 column-level check keys.
    _str_arr = r'\[(\s*"[^"]*"(?:,\s*"[^"]*")*\s*)\]'
    text = re.sub(r'(?<="contains_no_value": )' + _str_arr, _collapse, text, flags=re.DOTALL)
    text = re.sub(r'(?<="contains_constant_value": )' + _str_arr, _collapse, text, flags=re.DOTALL)
    return text


def write_json(path: Path, payload: Any) -> None:
    """Write payload to path as indented JSON, sanitizing via json_safe."""
    path.write_text(compact_json(json_safe(payload)), encoding="utf-8")


def drone_sd_label(idx: int) -> str:
    """Return the canonical directory label for a drone SD source (1-indexed)."""
    return f"drone_sd_{idx}"


def parse_datcon_date(value: str) -> str | None:
    """'20180419' → '2018-04-19'. Returns None on empty or malformed input."""
    if not value:
        return None
    v = value.strip()
    if len(v) != 8 or not v.isdigit():
        return None
    return f"{v[0:4]}-{v[4:6]}-{v[6:8]}"


def parse_datcon_time(value: str) -> str | None:
    """'172449' → '17:24:49', '172449.123' → '17:24:49.123'. Returns None on malformed input."""
    if not value:
        return None
    v = value.strip()
    if not v:
        return None
    if "." in v:
        base, frac = v.split(".", 1)
    else:
        base, frac = v, None
    if len(base) != 6 or not base.isdigit():
        return None
    hh, mm, ss = base[0:2], base[2:4], base[4:6]
    return f"{hh}:{mm}:{ss}.{frac}" if frac else f"{hh}:{mm}:{ss}"


def parse_exif_date(value: str) -> tuple[str, str] | None:
    """Parse EXIF date string to (norm_date, norm_time) in UTC.

    Input: '2018:04:19 17:24:49' or '2018:04:19 17:24:49+02:00'
    Output: ('2018-04-19', '17:24:49')
    Returns None for zero date or unparseable input.
    DJI stores timestamps in UTC; timezone suffix is ignored.
    """
    if not value:
        return None
    base = value.strip()[:19]  # YYYY:MM:DD HH:MM:SS — drop sub-seconds and TZ
    if base.startswith("0000"):
        return None
    try:
        dt = datetime.strptime(base, "%Y:%m:%d %H:%M:%S")
    except ValueError:
        return None
    return dt.strftime("%Y-%m-%d"), dt.strftime("%H:%M:%S")


def parse_iso_timestamp(value: str) -> str | None:
    """Parse any ISO 8601 datetime string to unified explicit-offset notation.

    '2018-04-19T17:24:49Z'      → '2018-04-19T17:24:49+00:00'
    '2018-04-19T17:24:49+02:00' → '2018-04-19T17:24:49+02:00'
    Sub-seconds are preserved. Returns None on empty or unparseable input.
    """
    if not value:
        return None
    v = value.strip()
    if v.endswith("Z"):
        v = v[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(v)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat()


def parse_flightrecord_timestamp(value: str) -> str | None:
    """Parse DJI FlightRecord CUSTOM.updateTime to ISO 8601 UTC.

    Input:  '2018/04/19 17:25:11.078' or '2018/04/19 17:25:11'
    Output: '2018-04-19T17:25:11.078000+00:00'

    DJI FlightRecord timestamps are in UTC — confirmed by cross-correlation with
    DatCon GPS:dateTimeStamp (Z-suffix UTC) from the same flights: both show
    the same hour value, ruling out local-time interpretation.
    """
    if not value:
        return None
    v = value.strip()
    for fmt in ("%Y/%m/%d %H:%M:%S.%f", "%Y/%m/%d %H:%M:%S"):
        try:
            return datetime.strptime(v, fmt).replace(tzinfo=timezone.utc).isoformat()
        except ValueError:
            continue
    return None


def haversine_m(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Great-circle distance in metres between two WGS84 points."""
    R = 6_371_000.0
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlam = math.radians(lon2 - lon1)
    a = math.sin(dphi / 2) ** 2 + math.cos(phi1) * math.cos(phi2) * math.sin(dlam / 2) ** 2
    return R * 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))


def find_input_evidence_list_by_identification(
    state: State, identification: str
) -> list[Evidence]:
    """Find all input evidence matching an identification from phase 1 output."""
    source_records = state.phase_outputs.get("p1_provenance", {}).get(
        "identified_evidence", []
    )
    matching_evidence: list[Evidence] = []
    for record in source_records:
        # Operator override always takes precedence when set; fall back to auto-identification.
        recorded_identification = str(
            record.get("identified_by_operator_as")
            or record.get("identified_as", "")
        )

        if recorded_identification != identification:
            continue
        source_path = str(record.get("source_path") or "")
        if not source_path:
            continue
        for evidence in state.input_evidence:
            if str(evidence.source_path) == source_path:
                matching_evidence.append(evidence)
                break  # Assuming one evidence per source_path, but collect all.
    return matching_evidence
