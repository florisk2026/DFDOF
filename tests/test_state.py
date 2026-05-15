from __future__ import annotations

import json
import subprocess
from pathlib import Path

import state as state_module
from state import State


def test_log_tool_invocation_prefers_stderr_summary(monkeypatch) -> None:
    monkeypatch.setattr(state_module, "utc_now_iso", lambda: "2026-05-15T00:00:00+00:00")

    case_state = State(case_id="CASE-STATE-1", operator="Floris")
    case_state.log_tool_invocation(
        tool_name="demo_tool",
        stdout="all good",
        stderr="something failed",
        output_paths=[],
    )

    entry = case_state.tool_invocation_log[0]
    assert entry["timestamp"] == "2026-05-15T00:00:00+00:00"
    assert entry["std_summary"].startswith("[ERROR]: ")
    assert "something failed" in entry["std_summary"]
    assert entry["output_paths"] is None
    assert "stdout" not in entry
    assert "stderr" not in entry


def test_log_command_result_adds_tsk_version_and_info_summary(monkeypatch) -> None:
    monkeypatch.setattr(state_module, "utc_now_iso", lambda: "2026-05-15T00:00:01+00:00")
    monkeypatch.setattr(
        state_module,
        "get_tsk_tool_version",
        lambda _tool_path: "The Sleuth Kit ver 4.15.0",
    )

    case_state = State(case_id="CASE-STATE-2", operator="Floris")
    result = subprocess.CompletedProcess(
        args=["C:/tools/fls.exe", "-r", "-p", "image.E01"],
        returncode=0,
        stdout="listed entries",
        stderr="",
    )

    case_state.log_command_result(tool_name="fls", result=result)

    entry = case_state.tool_invocation_log[0]
    assert entry["tool_name"] == "fls"
    assert entry["version"] == "The Sleuth Kit ver 4.15.0"
    assert entry["args"] == ["C:/tools/fls.exe", "-r", "-p", "image.E01"]
    assert entry["std_summary"].startswith("[INFO]: ")
    assert "listed entries" in entry["std_summary"]


def test_save_writes_state_file_and_cleans_temp(tmp_path: Path) -> None:
    case_state = State(case_id="CASE-STATE-3", operator="Floris")
    state_path = tmp_path / "state.json"

    case_state.save(state_path)

    assert state_path.exists()
    assert not (tmp_path / "state.json.tmp").exists()

    loaded = json.loads(state_path.read_text(encoding="utf-8"))
    assert loaded["case_id"] == "CASE-STATE-3"
    assert loaded["operator"] == "Floris"
    assert "tool_invocation_log" in loaded
