from __future__ import annotations

from pathlib import Path

from phases.p0_input import run_phase_0


def test_phase_0_intake_prompts_and_initializes_state(tmp_path: Path, monkeypatch) -> None:
	evidence_dir = tmp_path / "evidence"
	evidence_dir.mkdir()

	answers = iter(["Alice", "CASE-P0", str(evidence_dir)])
	monkeypatch.setattr("builtins.input", lambda _prompt: next(answers))

	state = run_phase_0(None, None, None)

	assert state.case_id == "CASE-P0"
	assert state.operator == "Alice"
	assert state.evidence_directory == str(evidence_dir.resolve())


def test_phase_0_intake_skips_prompts_with_args(tmp_path: Path) -> None:
	evidence_dir = tmp_path / "evidence"
	evidence_dir.mkdir()

	state = run_phase_0("Bob", "CASE-ARGS", str(evidence_dir))

	assert state.case_id == "CASE-ARGS"
	assert state.operator == "Bob"
	assert state.evidence_directory == str(evidence_dir.resolve())


def test_phase_0_intake_validates_evidence_directory(tmp_path: Path) -> None:
	nonexistent = tmp_path / "does_not_exist"

	try:
		run_phase_0("Op", "CASE-ERR", str(nonexistent))
		raise AssertionError("Expected FileNotFoundError")
	except FileNotFoundError as exc:
		assert "not found" in str(exc).lower()
