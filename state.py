"""DFDOF State Management.

The state class captures all mutable informatiom about the case
maintaining the digital chain of custody.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from config import summarise_text, utc_now_iso
from evidence import Evidence
import subprocess


@dataclass(slots=True)
class State:
	"""Mutable pipeline state used to resume the multi-phase workflow."""

	case_id: str
	operator: str
	evidence_directory: str | None = None
	start_time: str = field(default_factory=utc_now_iso)
	input_evidence: list[Evidence] = field(default_factory=list)
	phase_outputs: dict[str, Any] = field(default_factory=dict)
	tool_invocation_log: list[dict[str, Any]] = field(default_factory=list)
	anomaly_flags: list[str] = field(default_factory=list)
	completed_phases: list[str] = field(default_factory=list)

	def to_dict(self) -> dict[str, Any]:
		# Preserve a human-friendly, stable ordering for the serialized state
		# to make case-level metadata appear at the top of the file.
		return {
			"operator": self.operator,
			"case_id": self.case_id,
			"start_time": self.start_time,
			"evidence_directory": self.evidence_directory,
			"completed_phases": self.completed_phases,
			"anomaly_flags": self.anomaly_flags,
			"input_evidence": [evidence.to_dict() for evidence in self.input_evidence],
			"phase_outputs": self.phase_outputs,
			"tool_invocation_log": self.tool_invocation_log,
		}

	@classmethod
	def from_dict(cls, data: dict[str, Any]) -> State:
		state = cls(
			case_id=data["case_id"],
			operator=data["operator"],
			evidence_directory=data.get("evidence_directory"),
			start_time=data.get("start_time", utc_now_iso()),
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
			# Keep the key order produced by `to_dict()` rather than sorting
			# alphabetically so top-level case metadata remains prominent.
			json.dump(self.to_dict(), file_handle, indent=2)
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
		stdout: str | None = None,
		stderr: str | None = None,
		output_paths: list[str] | None = None,
	) -> None:
		"""Record a tool run in a compact but auditable form."""

		# Helper: probe common version flags for TSK tools if not provided
		def _probe_version(exe: str) -> str | None:
			# Minimal probe: try common version flags and return the first
			# non-empty output line (trimmed). Keep logic small and direct.
			for flag in ("-V", "--version"):
				try:
					res = subprocess.run([exe, flag], capture_output=True, text=True, check=False)
					out = (res.stdout or res.stderr or "").strip()
					if out:
						return summarise_text(out.splitlines()[0], limit=200)
				except Exception:
					return None
			return None

		resolved_version = version
		if resolved_version is None and args and len(args) > 0:
			exe = args[0]
			# Use the executable stem (filename without extension) so Windows
			# paths like 'mmls.exe' are matched as 'mmls'.
			base = Path(exe).stem.lower()
			if base in ("mmls", "fls"):
				resolved_version = _probe_version(exe)

		# Normalise empty summaries to null for clarity
		stdout_summary = summarise_text(stdout) if stdout else None
		stderr_summary = summarise_text(stderr) if stderr else None

		# Empty collections should be null to indicate absence rather than empty list/dict
		output_paths_val = output_paths if output_paths else None

		entry = {
			"timestamp": utc_now_iso(),
			"tool_name": tool_name,
			"version": (resolved_version if resolved_version is not None else None),
			"args": args or None,
			"return_code": return_code,
			"stdout_summary": stdout_summary,
			"stderr_summary": stderr_summary,
			"output_paths": output_paths_val,
		}
		self.tool_invocation_log.append(entry)
