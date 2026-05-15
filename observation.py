"""DFDOF Observation Management.

Observations store derived content separately from evidence so provenance remains
stable while later phases can still record parsed or inferred data.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


def _json_safe(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(key): _json_safe(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_json_safe(item) for item in value]
    if isinstance(value, tuple):
        return [_json_safe(item) for item in value]
    if hasattr(value, "isoformat"):
        try:
            return value.isoformat()
        except Exception:
            return str(value)
    return value


@dataclass
class Content:
    evidence_sha256: str
    evidence_category: str | None
    acquisition_method: str | None
    observations: list[Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "evidence_sha256": self.evidence_sha256,
            "evidence_category": self.evidence_category,
            "acquisition_method": self.acquisition_method,
            "observations": _json_safe(self.observations),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Content:
        return cls(
            evidence_sha256=str(data.get("evidence_sha256") or ""),
            evidence_category=data.get("evidence_category"),
            acquisition_method=data.get("acquisition_method"),
            observations=list(data.get("observations") or []),
        )


@dataclass
class Observation:
    content: Content

    def to_dict(self) -> dict[str, Any]:
        return self.content.to_dict()

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Observation:
        return cls(content=Content.from_dict(data))
