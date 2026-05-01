from __future__ import annotations

import subprocess
import zipfile
from pathlib import Path

from phases.p1_provenance import decide_classification, prompt_phase_1_summary_and_confirm, run_phase_1, score_source_type
from state import State


def test_score_and_decision_auto_android() -> None:
	listing = [
		"/sdcard/DJI/dji.go.v4/FlightRecord/abc.txt",
		"/data/data/dji.go.v4/shared_prefs/dji.go.v4.xml",
	]
	scores = score_source_type(listing)
	decision = decide_classification(scores)
	assert decision["status"] == "auto"
	assert decision["auto_classification"] == "android_controller"


def test_run_phase_1_only_supported_inputs(tmp_path: Path, monkeypatch) -> None:
	zip_path = tmp_path / "android_logical.zip"
	with zipfile.ZipFile(zip_path, "w") as archive:
		archive.writestr("sdcard/DJI/dji.go.v4/FlightRecord/record.txt", "x")

	image_path = tmp_path / "drone.E01"
	image_path.write_bytes(b"image fixture")

	ignored = tmp_path / "notes.txt"
	ignored.write_text("ignore", encoding="utf-8")

	def fake_run(command, capture_output=True, text=True, check=False, stdout=None):
		exe = Path(command[0]).name.lower()
		if exe.startswith("mmls"):
			return subprocess.CompletedProcess(command, 0, stdout="""
DOS Partition Table
002:  000:000   0000002048   0000012345   0000010298   5.0M      Primary Table (#0)
""")
		if exe.startswith("fls"):
			return subprocess.CompletedProcess(command, 0, stdout="""
r/r 1234: DCIM/100MEDIA/DJI_0001.MP4
r/r 1235: MISC/THM/100/DJI_0001.THM
""")
		raise AssertionError(f"unexpected command: {command}")

	monkeypatch.setattr("phases.p1_provenance._run_command", fake_run)

	state = State(case_id="CASE-1", operator="op", evidence_directory=str(tmp_path))
	state = run_phase_1(state, confirm_all=True)

	assert len(state.input_evidence) == 2
	assert all(item.path.suffix.lower() in {".zip", ".e01", ".001"} for item in state.input_evidence)
	p1 = state.phase_outputs["p1_provenance"]["sources"]
	assert len(p1) == 2
	assert any(record["classification"]["status"] == "auto" for record in p1)
	assert "p1_provenance" in state.completed_phases


def test_run_phase_1_ambiguous_can_be_resolved(tmp_path: Path, monkeypatch) -> None:
	image_path = tmp_path / "mixed.001"
	image_path.write_bytes(b"image fixture")

	def fake_run(command, capture_output=True, text=True, check=False, stdout=None):
		exe = Path(command[0]).name.lower()
		if exe.startswith("mmls"):
			return subprocess.CompletedProcess(command, 0, stdout="""
DOS Partition Table
002:  000:000   0000002048   0000012345   0000010298   5.0M      Primary Table (#0)
""")
		if exe.startswith("fls"):
			return subprocess.CompletedProcess(command, 0, stdout="""
r/r 1234: sdcard/DJI/dji.go.v4/FlightRecord/abc.txt
r/r 1235: DCIM/100MEDIA/DJI_0001.MP4
""")
		raise AssertionError(f"unexpected command: {command}")

	monkeypatch.setattr("phases.p1_provenance._run_command", fake_run)

	def choose_drone_sd(_evidence, candidates):
		assert len(candidates) == 2
		return "drone_sd"

	state = State(case_id="CASE-2", operator="op", evidence_directory=str(tmp_path))
	state = run_phase_1(state, confirm_all=False, resolve_ambiguous=choose_drone_sd)

	record = state.phase_outputs["p1_provenance"]["sources"][0]
	assert record["classification"]["status"] == "ambiguous"
	assert record["operator_confirmation"]["confirmed_classification"] == "drone_sd"


def test_run_phase_1_retries_e01_with_ewf_hint(tmp_path: Path, monkeypatch) -> None:
	image_path = tmp_path / "retry.E01"
	image_path.write_bytes(b"image fixture")

	def fake_run(command, capture_output=True, text=True, check=False, stdout=None):
		exe = Path(command[0]).name.lower()
		if exe.startswith("mmls"):
			if "-i" in command and "ewf" in command:
				return subprocess.CompletedProcess(command, 0, stdout="""
DOS Partition Table
002:  000:000   0000002048   0000012345   0000010298   5.0M      Primary Table (#0)
""")
			return subprocess.CompletedProcess(command, 1, stdout="", stderr="unsupported image type")
		if exe.startswith("fls"):
			assert "-i" in command and "ewf" in command
			return subprocess.CompletedProcess(command, 0, stdout="r/r 1234: DCIM/100MEDIA/DJI_0001.MP4\n")
		raise AssertionError(f"unexpected command: {command}")

	monkeypatch.setattr("phases.p1_provenance._run_command", fake_run)

	state = State(case_id="CASE-3", operator="op", evidence_directory=str(tmp_path))
	state = run_phase_1(state, confirm_all=True)

	record = state.phase_outputs["p1_provenance"]["sources"][0]
	assert record["classification"]["status"] == "auto"


def test_run_phase_1_reports_clear_mmls_failure(tmp_path: Path, monkeypatch) -> None:
	image_path = tmp_path / "bad.E01"
	image_path.write_bytes(b"image fixture")

	def fake_run(command, capture_output=True, text=True, check=False, stdout=None):
		exe = Path(command[0]).name.lower()
		if exe.startswith("mmls"):
			return subprocess.CompletedProcess(command, 1, stdout="", stderr="unsupported image type")
		return subprocess.CompletedProcess(command, 1, stdout="", stderr="fls failed")

	monkeypatch.setattr("phases.p1_provenance._run_command", fake_run)

	state = State(case_id="CASE-4", operator="op", evidence_directory=str(tmp_path))
	try:
		run_phase_1(state, confirm_all=True)
		raise AssertionError("Expected RuntimeError")
	except RuntimeError as exc:
		message = str(exc).lower()
		assert "ewf support" in message
		assert "direct fls fallback" in message


def test_run_phase_1_fallbacks_to_fls_without_mmls(tmp_path: Path, monkeypatch) -> None:
	image_path = tmp_path / "filesystem_only.E01"
	image_path.write_bytes(b"image fixture")

	def fake_run(command, capture_output=True, text=True, check=False, stdout=None):
		exe = Path(command[0]).name.lower()
		if exe.startswith("mmls"):
			return subprocess.CompletedProcess(command, 1, stdout="", stderr="")
		if exe.startswith("fls"):
			# fallback direct fls should not include -o
			assert "-o" not in command
			return subprocess.CompletedProcess(command, 0, stdout="r/r 1234: DCIM/100MEDIA/DJI_0001.MP4\n")
		raise AssertionError(f"unexpected command: {command}")

	monkeypatch.setattr("phases.p1_provenance._run_command", fake_run)

	state = State(case_id="CASE-5", operator="op", evidence_directory=str(tmp_path))
	state = run_phase_1(state, confirm_all=True)

	record = state.phase_outputs["p1_provenance"]["sources"][0]
	assert record["classification"]["status"] == "auto"
	assert any(flag.startswith("p1_mmls_unavailable_used_fls_direct:") for flag in state.anomaly_flags)


def test_prompt_blocks_continuation_for_unclassified_sources(monkeypatch, capsys) -> None:
	state = State(case_id="CASE-6", operator="op", evidence_directory=None)
	state.phase_outputs["p1_provenance"] = {
		"sources": [
			{
				"path": "sample.zip",
				"classification": {
					"status": "unclassified",
					"auto_classification": None,
					"ranked": [("android_controller", 4), ("ios_controller", 4)],
				},
				"operator_confirmation": {"confirmed": False, "confirmed_classification": None, "timestamp": None},
			},
		]
	}

	answers = iter(["yes", "no", "abort"])
	monkeypatch.setattr("builtins.input", lambda _prompt: next(answers))

	accepted = prompt_phase_1_summary_and_confirm(state)

	output = capsys.readouterr().out
	assert accepted is False
	assert "still unclassified" in output
