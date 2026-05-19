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
from typing import cast

from phases.p1_provenance import prompt_phase_1_summary_and_confirm, run_phase_1
from phases.p2_image_parsing import run_phase_2
from phases.p3_artefact_extraction import run_phase_3
from phases.p4_decision_and_orchestration import run_phase_4
from state import State


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="DFDOF: Drone Forensics Decision and Orchestration Framework"
    )
    parser.add_argument("--operator", help="Operator name")
    parser.add_argument("--case-id", help="Case identifier")
    parser.add_argument("--evidence-dir", help="Evidence directory path")
    parser.add_argument("--state-path", default="state.json", help="Output state file")
    return parser


def _prompt_if_missing(value: str | None, prompt_text: str) -> str:
    """Prompt for value only if not provided or empty."""
    if value is not None and value.strip():
        return value.strip()
    return input(prompt_text).strip()


def _compute_evidence_hashes(state: State) -> None:
    """Compute SHA-256/SHA-1 hashes for all input evidence files."""
    if not state.input_evidence:
        return

    print("Computing evidence hashes...")
    for evidence in state.input_evidence:
        size_gb = evidence.size / (1024**3)
        print(
            f"  Hashing {cast(Path, evidence.stored_path).name}... ({size_gb:.1f} GB)"
        )
        evidence.compute_hash()
    print()


def run_phases(
    operator: str | None,
    case_id: str | None,
    evidence_dir: str | None,
    state_path: str | Path,
) -> State:
    """Orchestrate the forensic analysis phases."""

    # Case Intake
    print("Case intake:")
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

    # Phase 2: Image Parsing
    print("[Phase 2] Image parsing:")
    state = run_phase_2(state)
    state.save(state_path)
    print()

    # Phase 3: Artefact Extraction
    print("[Phase 3] Artefact extraction:")
    state = run_phase_3(state)
    state.save(state_path)
    print()

    # Phase 4: Decision and Orchestration
    print("[Phase 4] Decision and Orchestration:")
    state = run_phase_4(state)
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
