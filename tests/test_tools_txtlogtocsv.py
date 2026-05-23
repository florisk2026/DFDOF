"""Unit tests for tools/txtlogtocsv.py."""

from __future__ import annotations

import subprocess
from pathlib import Path

import config
from evidence import make_evidence
from state import State
from tools.txtlogtocsv import run_txtlogtocsv


def _make_state() -> State:
    state = State(case_id="CASE-TXTCSV", operator="Tester")
    state.phase_outputs["p1_provenance"] = {"identified_evidence": []}
    return state


def _make_parent(tmp_path: Path) -> make_evidence:
    txt = tmp_path / "DJIFlightRecord_2018-04-19.txt"
    txt.write_text("record", encoding="utf-8")
    return make_evidence(
        source_path=txt.name,
        stored_path=txt,
        parent=None,
        acquisition_method=config.ACQUISITION_LOGICAL,
        type=config.EVIDENCE_TYPE_EXTRACTED,
        artefact_category=config.FLIGHT_RECORDS,
    )


def _fake_run_success(csv_path: Path):
    """Return a factory for subprocess.run that writes a non-empty CSV."""
    def fake_run(args, **kwargs):
        csv_path.write_text("col1,col2\n1,2\n", encoding="utf-8")
        return subprocess.CompletedProcess(args, returncode=0, stdout="", stderr="")
    return fake_run


def test_run_txtlogtocsv_exe_not_found_raises_anomaly(tmp_path: Path, monkeypatch) -> None:
    state = _make_state()
    parent = _make_parent(tmp_path)
    txt_path = tmp_path / "DJIFlightRecord_2018-04-19.txt"
    output_dir = tmp_path / "output"

    monkeypatch.setattr("tools.txtlogtocsv.Path.exists", lambda self: False)
    monkeypatch.setattr("tools.txtlogtocsv.shutil.which", lambda _: None)

    result = run_txtlogtocsv(txt_path, output_dir, state, parent, config.IDENTIFICATION_CONTROLLER_IOS)

    assert result is None
    assert any("TXTlogToCSV executable not found" in f for f in state.anomaly_flags)


def test_run_txtlogtocsv_subprocess_oserror_raises_anomaly(tmp_path: Path, monkeypatch) -> None:
    state = _make_state()
    parent = _make_parent(tmp_path)
    txt_path = tmp_path / "DJIFlightRecord_2018-04-19.txt"
    output_dir = tmp_path / "output"

    monkeypatch.setattr("tools.txtlogtocsv.Path.exists", lambda self: True)
    monkeypatch.setattr("tools.txtlogtocsv.Path.is_file", lambda self: True)
    monkeypatch.setattr(subprocess, "run", lambda *_a, **_kw: (_ for _ in ()).throw(OSError("no exe")))

    result = run_txtlogtocsv(txt_path, output_dir, state, parent, config.IDENTIFICATION_CONTROLLER_IOS)

    assert result is None
    assert any("TXTlogToCSV failed" in f for f in state.anomaly_flags)


def test_run_txtlogtocsv_nonzero_returncode_raises_anomaly(tmp_path: Path, monkeypatch) -> None:
    state = _make_state()
    parent = _make_parent(tmp_path)
    txt_path = tmp_path / "DJIFlightRecord_2018-04-19.txt"
    output_dir = tmp_path / "output"
    output_dir.mkdir()

    monkeypatch.setattr("tools.txtlogtocsv.Path.exists", lambda self: True)
    monkeypatch.setattr("tools.txtlogtocsv.Path.is_file", lambda self: True)
    monkeypatch.setattr(
        subprocess, "run",
        lambda *_a, **_kw: subprocess.CompletedProcess(_a, returncode=1, stdout="", stderr="error"),
    )

    result = run_txtlogtocsv(txt_path, output_dir, state, parent, config.IDENTIFICATION_CONTROLLER_IOS)

    assert result is None
    assert any("TXTlogToCSV failed" in f for f in state.anomaly_flags)


def test_run_txtlogtocsv_empty_csv_raises_anomaly(tmp_path: Path, monkeypatch) -> None:
    state = _make_state()
    parent = _make_parent(tmp_path)
    txt_path = tmp_path / "DJIFlightRecord_2018-04-19.txt"
    output_dir = tmp_path / "output"
    output_dir.mkdir()
    csv_path = output_dir / f"{txt_path.stem}.csv"

    def fake_run(args, **kwargs):
        csv_path.write_text("", encoding="utf-8")
        return subprocess.CompletedProcess(args, returncode=0, stdout="", stderr="")

    monkeypatch.setattr("tools.txtlogtocsv.Path.exists", lambda self: True)
    monkeypatch.setattr("tools.txtlogtocsv.Path.is_file", lambda self: True)
    monkeypatch.setattr(subprocess, "run", fake_run)

    result = run_txtlogtocsv(txt_path, output_dir, state, parent, config.IDENTIFICATION_CONTROLLER_IOS)

    assert result is None
    assert any("TXTlogToCSV failed" in f for f in state.anomaly_flags)


def test_run_txtlogtocsv_success_returns_evidence(tmp_path: Path, monkeypatch) -> None:
    state = _make_state()
    parent = _make_parent(tmp_path)
    txt_path = tmp_path / "DJIFlightRecord_2018-04-19.txt"
    output_dir = tmp_path / "output"
    output_dir.mkdir()
    csv_path = output_dir / f"{txt_path.stem}.csv"

    monkeypatch.setattr("tools.txtlogtocsv.Path.exists", lambda self: True)
    monkeypatch.setattr("tools.txtlogtocsv.Path.is_file", lambda self: True)
    monkeypatch.setattr(subprocess, "run", _fake_run_success(csv_path))

    result = run_txtlogtocsv(txt_path, output_dir, state, parent, config.IDENTIFICATION_CONTROLLER_IOS)

    assert result is not None
    assert Path(str(result.stored_path)).suffix == ".csv"
    assert result.acquisition_method == config.ACQUISITION_TXTLOGTOCSV
    assert result.artefact_category == config.FLIGHT_RECORDS
    assert not state.anomaly_flags
