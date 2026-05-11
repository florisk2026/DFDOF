"""DFDOF State Management.

The state class captures all mutable information about 
the case maintaining the digital chain of custody
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from config import summarise_text, utc_now_iso
from evidence import Evidence
import subprocess


def _get_tsk_tool_version(tool_path: str) -> str | None:
	"""Probe a TSK binary (mmls, fls, icat) for its version string."""
	try:
		result = subprocess.run([tool_path, "-V"], capture_output=True, text=True, timeout=5)
		combined = "\n".join(filter(None, [result.stdout or "", result.stderr or ""]))
		for line in combined.splitlines():
			line = line.strip()
			if line:
				return line
	except Exception:
		pass
	return None


@dataclass
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

		# Normalise empty summaries to null for clarity
		stdout_summary = summarise_text(stdout) if stdout else None
		stderr_summary = summarise_text(stderr) if stderr else None
		output_paths_val = output_paths if output_paths else None

		entry = {
			"timestamp": utc_now_iso(),
			"tool_name": tool_name,
			"version": version,
			"args": args or None,
			"return_code": return_code,
			"stdout_summary": stdout_summary,
			"stderr_summary": stderr_summary,
			"output_paths": output_paths_val,
		}
		self.tool_invocation_log.append(entry)

	def log_command_result(
		self,
		*,
		tool_name: str,
		result: subprocess.CompletedProcess[str],
		output_paths: list[str] | None = None,
	) -> None:
		"""Convenience method to log a completed subprocess result directly."""
		# Attempt to capture a tool version for known CLI tools when possible.
		version_val: str | None = None
		try:
			if isinstance(result.args, list) and result.args:
				cmd0 = str(result.args[0])
				base = Path(cmd0).name.lower()
				if base in {"mmls", "mmls.exe", "fls", "fls.exe", "icat", "icat.exe"}:
					version_val = _get_tsk_tool_version(cmd0)
		except Exception:
			version_val = None

		self.log_tool_invocation(
			tool_name=tool_name,
			version=version_val,
			args=result.args if isinstance(result.args, list) else None,
			return_code=result.returncode,
			stdout=result.stdout or None,
			stderr=result.stderr or None,
			output_paths=output_paths,
		)
