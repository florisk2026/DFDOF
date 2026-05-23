"""Unit tests for tools/datcon.py validation loop."""

from __future__ import annotations

import subprocess
from pathlib import Path

import config
from evidence import make_evidence
from state import State
from tools.datcon import _datcon_output_missing, run_datcon


def _make_state(tmp_path: Path) -> State:
    state = State(case_id="CASE-DATCON", operator="Tester")
    state.phase_outputs["p1_provenance"] = {"identified_evidence": []}
    return state


def _make_parent(tmp_path: Path):
    dat = tmp_path / "FLY029.DAT"
    dat.write_bytes(b"dat")
    return make_evidence(
        source_path=dat.name,
        stored_path=dat,
        parent=None,
        acquisition_method=config.ACQUISITION_EXTRACT_DJI,
        type=config.EVIDENCE_TYPE_EXTRACTED,
        artefact_category=config.DRONE_LOGS,
    )


def _write_required_outputs(output_dir: Path, stem: str) -> None:
    for ext in (".csv", ".kml"):
        (output_dir / f"{stem}{ext}").write_text("data", encoding="utf-8")


def test_datcon_output_missing_all_present(tmp_path: Path) -> None:
    stem = "FLY029"
    _write_required_outputs(tmp_path, stem)
    assert _datcon_output_missing(tmp_path, stem) is False


def test_datcon_output_missing_partial(tmp_path: Path) -> None:
    stem = "FLY029"
    (tmp_path / f"{stem}.csv").write_text("data", encoding="utf-8")
    assert _datcon_output_missing(tmp_path, stem) is True


def test_datcon_output_missing_empty_dir(tmp_path: Path) -> None:
    assert _datcon_output_missing(tmp_path, "FLY029") is True


def test_run_datcon_error_returns_empty(tmp_path: Path, monkeypatch) -> None:
    state = _make_state(tmp_path)
    parent = _make_parent(tmp_path)
    output_dir = tmp_path / "output"
    output_dir.mkdir()
    stem = "FLY029"
    dat_path = tmp_path / f"{stem}.DAT"
    dat_path.write_bytes(b"dat")

    monkeypatch.setattr("builtins.input", lambda _: "error")
    monkeypatch.setattr(subprocess, "Popen", lambda *_a, **_kw: None)

    result = run_datcon(dat_path, output_dir, state, parent, config.IDENTIFICATION_CONTROLLER_ANDROID)

    assert result == []
    assert not state.anomaly_flags


def test_run_datcon_succeeds_first_try(tmp_path: Path, monkeypatch, capsys) -> None:
    state = _make_state(tmp_path)
    parent = _make_parent(tmp_path)
    output_dir = tmp_path / "output"
    output_dir.mkdir()
    stem = "FLY029"
    dat_path = tmp_path / f"{stem}.DAT"
    dat_path.write_bytes(b"dat")

    _write_required_outputs(output_dir, stem)
    monkeypatch.setattr("builtins.input", lambda _: "done")
    monkeypatch.setattr(subprocess, "Popen", lambda *_a, **_kw: None)

    result = run_datcon(dat_path, output_dir, state, parent, config.IDENTIFICATION_CONTROLLER_ANDROID)

    assert len(result) == 2
    assert not state.anomaly_flags
    captured = capsys.readouterr()
    assert "WARNING" not in captured.out


def test_run_datcon_retries_on_missing_output(tmp_path: Path, monkeypatch, capsys) -> None:
    state = _make_state(tmp_path)
    parent = _make_parent(tmp_path)
    output_dir = tmp_path / "output"
    output_dir.mkdir()
    stem = "FLY029"
    dat_path = tmp_path / f"{stem}.DAT"
    dat_path.write_bytes(b"dat")

    call_count = 0

    def fake_input(_prompt: str) -> str:
        nonlocal call_count
        call_count += 1
        if call_count == 2:
            _write_required_outputs(output_dir, stem)
        return "done"

    monkeypatch.setattr("builtins.input", fake_input)
    monkeypatch.setattr(subprocess, "Popen", lambda *_a, **_kw: None)

    result = run_datcon(dat_path, output_dir, state, parent, config.IDENTIFICATION_CONTROLLER_ANDROID)

    assert call_count == 2
    assert len(result) == 2
    captured = capsys.readouterr()
    assert "WARNING" in captured.out
