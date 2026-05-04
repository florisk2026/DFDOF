"""DFDOF Main Phase Orchestrator.

Orchestrates the forensic workflow:
- Phase 0: Case Input
- Phase 1: Provenance and Integrity
- Phase 2: Image Parsing
- Phase 3: Artefact Extraction
- Phase 4: Decision and Orchestration
- Phase 5: Normalisation and Anomaly Checking
- Phase 6: Multi-source Correlation
- Phase 7: Analysis and Validation
- Phase 8: Automated Reporting
"""

from __future__ import annotations

import argparse
from pathlib import Path

from phases.p0_input import run_phase_0
from phases.p1_provenance import prompt_phase_1_summary_and_confirm, run_phase_1
from state import State


def _build_parser() -> argparse.ArgumentParser:
	parser = argparse.ArgumentParser(
		description="DFDOF: Drone Forensics Decision and Orchestration Framework"
	)
	parser.add_argument("--operator", help="Operator name (Phase 0)")
	parser.add_argument("--case-id", help="Case identifier (Phase 0)")
	parser.add_argument("--evidence-dir", help="Evidence directory path (Phase 0)")
	parser.add_argument("--state-path", default="state.json", help="Output state file")
	return parser


def _compute_evidence_hashes(state: State) -> None:
	"""Compute SHA-256/SHA-1 hashes for all input evidence files."""
	if not state.input_evidence:
		return

	print("Computing evidence hashes...")
	for evidence in state.input_evidence:
		size_gb = evidence.file_size / (1024**3)
		print(f"  Hashing {evidence.path.name}... ({size_gb:.1f} GB)")
		evidence.compute_hash()
	print()


def run_phases(
	operator: str | None,
	case_id: str | None,
	evidence_dir: str | None,
	state_path: str | Path,
) -> State:
	"""Orchestrate the forensic analysis phases."""
	
	# Phase 0: Case Intake
	print("[Phase 0] Case intake:")
	state = run_phase_0(operator, case_id, evidence_dir)
	print(f"  Case: {state.case_id} | Operator: {state.operator}")
	print(f"  Evidence: {state.evidence_directory}\n")


	# Phase 1: Provenance and Integrity
	print("[Phase 1] Provenance and integrity:")
	state = run_phase_1(state, confirm_all=False)
	_compute_evidence_hashes(state)
	if not prompt_phase_1_summary_and_confirm(state):
		raise SystemExit("Phase 1 aborted by operator.")
	state.save(state_path)
	print()

	# Future phases

	# Save final state
	state.save(state_path)
	print(f"Workflow complete. State written to {state_path}\n")
	return state


def main() -> None:
	parser = _build_parser()
	args = parser.parse_args()
	run_phases(args.operator, args.case_id, args.evidence_dir, args.state_path)


if __name__ == "__main__":
	main()
