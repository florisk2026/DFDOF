"""Unit tests for tools/extractdji.py validation loop."""

from __future__ import annotations

import subprocess
from pathlib import Path

import config
from evidence import make_evidence
from state import State
from tools.extractdji import _extractdji_output_missing, run_extractdji


def _make_state() -> State:
    state = State(case_id="CASE-EXDJI", operator="Tester")
    state.phase_outputs["p1_provenance"] = {"identified_evidence": []}
    return state


def _make_parent(tmp_path: Path):
    dat = tmp_path / "DJI_ASSISTANT_EXPORT_FILE_001.DAT"
    dat.write_bytes(b"dat")
    return make_evidence(
        source_path=dat.name,
        stored_path=dat,
        parent=None,
        acquisition_method=config.ACQUISITION_LOGICAL,
        type=config.EVIDENCE_TYPE_EXTRACTED,
        artefact_category=config.DRONE_LOGS,
    )


def test_extractdji_output_missing_fly_present(tmp_path: Path) -> None:
    (tmp_path / "FLY001.DAT").write_bytes(b"dat")
    assert _extractdji_output_missing(tmp_path) is False


def test_extractdji_output_missing_no_fly_prefix(tmp_path: Path) -> None:
    (tmp_path / "OTHER001.DAT").write_bytes(b"dat")
    assert _extractdji_output_missing(tmp_path) is True


def test_extractdji_output_missing_empty_dir(tmp_path: Path) -> None:
    assert _extractdji_output_missing(tmp_path) is True


def test_run_extractdji_succeeds_first_try(tmp_path: Path, monkeypatch, capsys) -> None:
    state = _make_state()
    parent = _make_parent(tmp_path)
    output_dir = tmp_path / "output"
    output_dir.mkdir()
    dat_path = tmp_path / "DJI_ASSISTANT_EXPORT_FILE_001.DAT"

    (output_dir / "FLY001.DAT").write_bytes(b"converted")
    monkeypatch.setattr("builtins.input", lambda _: "done")
    monkeypatch.setattr(subprocess, "Popen", lambda *_a, **_kw: None)

    result = run_extractdji(dat_path, output_dir, state, parent, config.IDENTIFICATION_DRONE_FLIGHT_STORAGE)

    assert len(result) == 1
    assert Path(str(result[0].stored_path)).suffix.upper() == ".DAT"
    assert Path(str(result[0].stored_path)).stem.upper().startswith("FLY")
    assert not state.anomaly_flags
    captured = capsys.readouterr()
    assert "WARNING" not in captured.out


def test_run_extractdji_error_returns_empty(tmp_path: Path, monkeypatch) -> None:
    state = _make_state()
    parent = _make_parent(tmp_path)
    output_dir = tmp_path / "output"
    output_dir.mkdir()
    dat_path = tmp_path / "DJI_ASSISTANT_EXPORT_FILE_001.DAT"

    monkeypatch.setattr("builtins.input", lambda _: "error")
    monkeypatch.setattr(subprocess, "Popen", lambda *_a, **_kw: None)

    result = run_extractdji(dat_path, output_dir, state, parent, config.IDENTIFICATION_DRONE_FLIGHT_STORAGE)

    assert result == []
    assert not state.anomaly_flags


def test_run_extractdji_skip_returns_empty(tmp_path: Path, monkeypatch) -> None:
    state = _make_state()
    parent = _make_parent(tmp_path)
    output_dir = tmp_path / "output"
    output_dir.mkdir()
    dat_path = tmp_path / "DJI_ASSISTANT_EXPORT_FILE_001.DAT"

    monkeypatch.setattr("builtins.input", lambda _: "skip")
    monkeypatch.setattr(subprocess, "Popen", lambda *_a, **_kw: None)

    result = run_extractdji(dat_path, output_dir, state, parent, config.IDENTIFICATION_DRONE_FLIGHT_STORAGE)

    assert result == []
    assert not state.anomaly_flags


def test_run_extractdji_retries_on_missing_output(tmp_path: Path, monkeypatch, capsys) -> None:
    state = _make_state()
    parent = _make_parent(tmp_path)
    output_dir = tmp_path / "output"
    output_dir.mkdir()
    dat_path = tmp_path / "DJI_ASSISTANT_EXPORT_FILE_001.DAT"

    call_count = 0

    def fake_input(_prompt: str) -> str:
        nonlocal call_count
        call_count += 1
        if call_count == 2:
            (output_dir / "FLY001.DAT").write_bytes(b"converted")
        return "done"

    monkeypatch.setattr("builtins.input", fake_input)
    monkeypatch.setattr(subprocess, "Popen", lambda *_a, **_kw: None)

    result = run_extractdji(dat_path, output_dir, state, parent, config.IDENTIFICATION_DRONE_FLIGHT_STORAGE)

    assert call_count == 2
    assert len(result) == 1
    captured = capsys.readouterr()
    assert "WARNING" in captured.out
