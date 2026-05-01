from __future__ import annotations

from pathlib import Path

import main


def test_run_cli_prompts_and_saves_state(tmp_path: Path, monkeypatch) -> None:
	evidence_dir = tmp_path / "evidence"
	evidence_dir.mkdir()
	(evidence_dir / "sample.zip").write_bytes(b"PK\x05\x06" + b"\x00" * 18)

	answers = iter(["Floris", "CASE-CLI", str(evidence_dir), "yes"])
	monkeypatch.setattr("builtins.input", lambda _prompt: next(answers))

	def fake_run_phase_1(state, confirm_all=False):
		state.phase_outputs["p1_provenance"] = {
			"sources": [
				{
					"path": str(evidence_dir / "sample.zip"),
					"classification": {
						"status": "auto",
						"auto_classification": "android_controller",
						"ranked": [("android_controller", 10), ("ios_controller", 0)],
					},
					"operator_confirmation": {"confirmed": False},
				}
			]
		}
		state.completed_phases.append("p1_provenance")
		return state

	monkeypatch.setattr("main.run_phase_1", fake_run_phase_1)

	state_path = tmp_path / "state.json"
	state = main.run_cli(None, None, None, state_path)

	assert state.case_id == "CASE-CLI"
	assert state.operator == "Floris"
	assert state.evidence_directory == str(evidence_dir.resolve())
	assert state_path.exists()
