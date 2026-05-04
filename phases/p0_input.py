"""DFDOF Phase 0: Case Input.

This phase:
- collects operator name, case ID and evidence directory path,
- initializes the State object,
- validates evidence directory exists.
"""

from __future__ import annotations

from pathlib import Path
from state import State


def _prompt_if_missing(value: str | None, prompt_text: str) -> str:
	"""Prompt for value only if not provided or empty."""
	if value is not None and value.strip():
		return value.strip()
	return input(prompt_text).strip()


def run_phase_0(operator: str | None, case_id: str | None, evidence_dir: str | None) -> State:
	"""DFDOF Phase 0: Collect case intake information and initialize state.
	
	Returns:
		State object with case_id, operator, and evidence_directory set.
	
	Raises:
		FileNotFoundError: If evidence directory does not exist.
	"""
	operator_value = _prompt_if_missing(operator, "Operator name: ")
	case_value = _prompt_if_missing(case_id, "Case identifier: ")
	evidence_value = _prompt_if_missing(evidence_dir, "Evidence directory path: ")

	evidence_path = Path(evidence_value).resolve()
	if not evidence_path.exists() or not evidence_path.is_dir():
		raise FileNotFoundError(f"Evidence directory not found: {evidence_path}")

	state = State(
		case_id=case_value,
		operator=operator_value,
		evidence_directory=str(evidence_path),
	)
	return state
