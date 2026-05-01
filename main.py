"""DFDOF entry point.

Implements Phase 0 intake (operator, case, evidence directory) and runs
Phase 1 (provenance and integrity) only.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from phases.p1_provenance import prompt_phase_1_summary_and_confirm, run_phase_1
from state import State


def _build_parser() -> argparse.ArgumentParser:
	parser = argparse.ArgumentParser(description="DFDOF Phase 0 + Phase 1 runner")
	parser.add_argument("--operator", help="Operator name")
	parser.add_argument("--case-id", help="Case identifier")
	parser.add_argument("--evidence-dir", help="Path to evidence directory")
	parser.add_argument("--state-path", default="state.json", help="Path to output state JSON")
	return parser


def _prompt_if_missing(value: str | None, prompt_text: str) -> str:
	if value is not None and value.strip():
		return value.strip()
	return input(prompt_text).strip()


def run_cli(operator: str | None, case_id: str | None, evidence_dir: str | None, state_path: str | Path) -> State:
	"""Run Phase 0 intake and Phase 1 provenance."""

	operator_value = _prompt_if_missing(operator, "Operator name: ")
	case_value = _prompt_if_missing(case_id, "Case identifier: ")
	evidence_value = _prompt_if_missing(evidence_dir, "Evidence directory path: ")

	state = State(
		case_id=case_value,
		operator=operator_value,
		evidence_directory=str(Path(evidence_value).resolve()),
	)
	state = run_phase_1(state, confirm_all=False)

	# Hash all input evidence files sequentially with progress output
	if state.input_evidence:
		print("\nComputing evidence hashes...\n")
		for evidence in state.input_evidence:
			size_gb = evidence.file_size / (1024**3)
			print(f"  Hashing {evidence.path.name}... ({size_gb:.1f} GB)")
			evidence.compute_hash()
		print()

	if not prompt_phase_1_summary_and_confirm(state):
		raise SystemExit()

	state.save(state_path)
	print(f"Phase 1 complete. State written to {state_path}")
	return state


def main() -> None:
	parser = _build_parser()
	args = parser.parse_args()
	run_cli(args.operator, args.case_id, args.evidence_dir, args.state_path)


if __name__ == "__main__":
	main()
