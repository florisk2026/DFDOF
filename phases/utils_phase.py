"""Phase utilities for identification and evidence matching.

Shared helpers used across phases for evidence source matching and identification.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any

from evidence import Evidence
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


def write_json(path: Path, payload: Any) -> None:
    """Write payload to path as indented JSON, sanitizing via json_safe."""
    path.write_text(json.dumps(json_safe(payload), indent=2), encoding="utf-8")


def find_input_evidence_list_by_identification(
    state: State, identification: str
) -> list[Evidence]:
    """Find all input evidence matching an identification from phase 1 output."""
    source_records = state.phase_outputs.get("p1_provenance", {}).get(
        "identified_evidence", []
    )
    matching_evidence: list[Evidence] = []
    for record in source_records:
        # Determine effective identification: auto if confirmed, else operator override
        if record.get("operator_confirmed"):
            recorded_identification = str(record.get("identified_as", ""))
        else:
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
                break  # Assuming one evidence per source_path, but collect all
    return matching_evidence
