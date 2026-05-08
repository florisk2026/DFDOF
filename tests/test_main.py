from __future__ import annotations

from pathlib import Path

import main


def test_run_phases_orchestrates_workflow(tmp_path: Path, monkeypatch) -> None:
	evidence_dir = tmp_path / "evidence"
	evidence_dir.mkdir()
	(evidence_dir / "sample.zip").write_bytes(b"PK\x05\x06" + b"\x00" * 18)

	answers = iter(["Floris", "CASE-PHASES", str(evidence_dir), "yes"])
	monkeypatch.setattr("builtins.input", lambda _: next(answers))

	def fake_run_phase_1(state, **_kwargs):
		state.phase_outputs["p1_provenance"] = {
			"classified_evidence": [
				{
					"source_path": str(evidence_dir / "sample.zip"),
					"classified": True,
					"classification": "controller_android",
					"operator_confirmed": False,
					"operator_classification": None,
				}
			]
		}
		state.completed_phases.append("p1_provenance")
		return state

	monkeypatch.setattr("main.run_phase_1", fake_run_phase_1)

	state_path = tmp_path / "state.json"
	state = main.run_phases(None, None, None, state_path)

	assert state.case_id == "CASE-PHASES"
	assert state.operator == "Floris"
	assert state.evidence_directory == str(evidence_dir.resolve())
	assert state_path.exists()
	assert "p1_provenance" in state.completed_phases
