"""Pipeline state and persistence helpers for DFDOF.

The state file is part of the forensic audit trail, so persistence is atomic
and every entry is stored in a serialisable form.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from evidence import Evidence


def _utc_now_iso() -> str:
	return datetime.now(timezone.utc).isoformat()


def _summarise_text(value: str, limit: int = 1000) -> str:
	if len(value) <= limit:
		return value
	return value[: limit - 3] + "..."


@dataclass(slots=True)
class State:
	"""Mutable pipeline state used to resume the multi-phase workflow."""

	case_id: str
	operator: str
	evidence_directory: str | None = None
	start_time: str = field(default_factory=_utc_now_iso)
	input_evidence: list[Evidence] = field(default_factory=list)
	phase_outputs: dict[str, Any] = field(default_factory=dict)
	tool_invocation_log: list[dict[str, Any]] = field(default_factory=list)
	anomaly_flags: list[str] = field(default_factory=list)
	completed_phases: list[str] = field(default_factory=list)

	def to_dict(self) -> dict[str, Any]:
		return {
			"case_id": self.case_id,
			"operator": self.operator,
			"evidence_directory": self.evidence_directory,
			"start_time": self.start_time,
			"input_evidence": [evidence.to_dict() for evidence in self.input_evidence],
			"phase_outputs": self.phase_outputs,
			"tool_invocation_log": self.tool_invocation_log,
			"anomaly_flags": self.anomaly_flags,
			"completed_phases": self.completed_phases,
		}

	@classmethod
	def from_dict(cls, data: dict[str, Any]) -> State:
		state = cls(
			case_id=data["case_id"],
			operator=data["operator"],
			evidence_directory=data.get("evidence_directory"),
			start_time=data.get("start_time", _utc_now_iso()),
			input_evidence=[Evidence.from_dict(item) for item in data.get("input_evidence", [])],
			phase_outputs=data.get("phase_outputs", {}),
			tool_invocation_log=data.get("tool_invocation_log", []),
			anomaly_flags=data.get("anomaly_flags", []),
			completed_phases=data.get("completed_phases", []),
		)
		return state

	def save(self, path: Path | str) -> None:
		"""Persist state atomically so a crash cannot leave a partial file."""

		target_path = Path(path)
		temp_path = target_path.with_suffix(target_path.suffix + ".tmp")
		with temp_path.open("w", encoding="utf-8") as file_handle:
			json.dump(self.to_dict(), file_handle, indent=2, sort_keys=True)
			file_handle.write("\n")
		temp_path.replace(target_path)

	@classmethod
	def load(cls, path: Path | str) -> State:
		target_path = Path(path)
		with target_path.open("r", encoding="utf-8") as file_handle:
			data = json.load(file_handle)
		state = cls.from_dict(data)
		# Keep the resume metadata explicit for downstream phase control.
		state.completed_phases = list(state.completed_phases)
		return state

	def log_tool_invocation(
		self,
		*,
		tool_name: str,
		version: str | None = None,
		args: list[str] | None = None,
		return_code: int | None = None,
		stdout: str = "",
		stderr: str = "",
		duration_seconds: float | None = None,
		output_paths: list[str] | None = None,
		output_hashes: dict[str, str] | None = None,
		input_hashes: dict[str, str] | None = None,
	) -> None:
		"""Record a tool run in a compact but auditable form."""

		self.tool_invocation_log.append(
			{
				"timestamp": _utc_now_iso(),
				"tool_name": tool_name,
				"version": version,
				"args": args or [],
				"return_code": return_code,
				"stdout_summary": _summarise_text(stdout),
				"stderr_summary": _summarise_text(stderr),
				"duration_seconds": duration_seconds,
				"output_paths": output_paths or [],
				"output_hashes": output_hashes or {},
				"input_hashes": input_hashes or {},
			}
		)

