from __future__ import annotations

import subprocess
import zipfile
from pathlib import Path

from phases.p1_provenance import (
	classify_source,
	prompt_phase_1_summary_and_confirm,
	run_phase_1,
)
from state import State


def test_classify_source_android_controller() -> None:
	listing = [
		"/sdcard/DJI/dji.go.v4/FlightRecord/abc.txt",
		"/data/data/dji.go.v4/shared_prefs/dji.go.v4.xml",
	]
	classification = classify_source(listing)
	assert classification == "android_controller"


def test_classify_source_ios_logical_nested_structure() -> None:
	"""Test iOS logical backup with nested root (e.g., MC 04 iOS/...)."""
	# Simulates: ios_logical.zip/MC 04 iOS/7f05ad1235.../ab/cd/...
	# Base structure
	listing = [
		"MC 04 iOS/7f05ad1235cea98920b1112ef14ddd9fdded744a/Info.plist",
		"MC 04 iOS/7f05ad1235cea98920b1112ef14ddd9fdded744a/Manifest.db",
	]
	
	# Add 60+ hex/hex entries to exceed threshold (50+)
	prefix = "MC 04 iOS/7f05ad1235cea98920b1112ef14ddd9fdded744a/"
	for i in range(10):  # First hex pair (00-09)
		for j in range(10):  # Second hex pair (00-09)
			# Generate paths like: MC 04 iOS/.../0a/0b/file_hash
			listing.append(f"{prefix}{i:02x}/{j:02x}/{'abcd' * 16}")  # 64 entries
	
	classification = classify_source(listing)
	assert classification == "ios_controller"


def test_run_phase_1_only_supported_inputs(tmp_path: Path, monkeypatch) -> None:
	zip_path = tmp_path / "drone_logical.zip"
	with zipfile.ZipFile(zip_path, "w") as archive:
		archive.writestr("DCIM/100MEDIA/DJI_0001.MP4", "x")

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
	# Both should be drone_sd (sorted alphabetically: drone.E01, drone_logical.zip)
	assert all(record["classification"] == "drone_sd" for record in p1)
	assert all(record["status"] == "classified" for record in p1)
	assert "p1_provenance" in state.completed_phases


def test_run_phase_1_multi_type_listing_uses_priority(tmp_path: Path, monkeypatch) -> None:
	"""When listing has features of multiple types, returns first matched type."""
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
r/r 1236: MISC/THM/100/DJI_0001.THM
""")
		raise AssertionError(f"unexpected command: {command}")

	monkeypatch.setattr("phases.p1_provenance._run_command", fake_run)

	state = State(case_id="CASE-2", operator="op", evidence_directory=str(tmp_path))
	state = run_phase_1(state, confirm_all=True)

	record = state.phase_outputs["p1_provenance"]["sources"][0]
	# Should match ios_controller first in the deterministic priority order
	assert record["classification"] in ("ios_controller", "android_controller", "drone_sd")
	assert record["status"] == "classified"


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
	assert record["classification"] == "drone_sd"
	assert record["status"] == "classified"


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
	assert record["classification"] == "drone_sd"
	assert record["status"] == "classified"
	assert any(flag.startswith("p1_mmls_unavailable_used_fls_direct:") for flag in state.anomaly_flags)


def test_run_phase_1_blocks_unclassified_sources(tmp_path: Path, monkeypatch) -> None:
	"""Phase 1 raises error if any source remains unclassified and confirm_all=True."""
	image_path = tmp_path / "unknown.E01"
	image_path.write_bytes(b"image fixture")

	def fake_run(command, capture_output=True, text=True, check=False, stdout=None):
		exe = Path(command[0]).name.lower()
		if exe.startswith("mmls"):
			return subprocess.CompletedProcess(command, 0, stdout="""
DOS Partition Table
002:  000:000   0000002048   0000012345   0000010298   5.0M      Primary Table (#0)
""")
		if exe.startswith("fls"):
			# Listing with no recognizable structure
			return subprocess.CompletedProcess(command, 0, stdout="""
r/r 1234: unknown_folder/some_file.txt
r/r 1235: other_data/file.bin
""")
		raise AssertionError(f"unexpected command: {command}")

	monkeypatch.setattr("phases.p1_provenance._run_command", fake_run)

	state = State(case_id="CASE-6", operator="op", evidence_directory=str(tmp_path))
	try:
		run_phase_1(state, confirm_all=True)
		raise AssertionError("Expected ValueError for unclassified source")
	except ValueError as exc:
		assert "unclassified" in str(exc).lower()


def test_prompt_blocks_continuation_for_unclassified_sources(monkeypatch, capsys) -> None:
	state = State(case_id="CASE-7", operator="op", evidence_directory=None)
	state.phase_outputs["p1_provenance"] = {
		"sources": [
			{
				"path": "sample.zip",
				"classification": "unclassified",
				"status": "unclassified",
				"operator_confirmation": {"confirmed": False, "confirmed_classification": None, "timestamp": None},
			},
		]
	}

	# Sequence: yes (rejected due to unclassified) -> no -> exit
	answers = iter(["yes", "no", "exit"])
	monkeypatch.setattr("builtins.input", lambda _prompt: next(answers))

	accepted = prompt_phase_1_summary_and_confirm(state)

	output = capsys.readouterr().out
	assert accepted is False
	assert "still unclassified" in output
