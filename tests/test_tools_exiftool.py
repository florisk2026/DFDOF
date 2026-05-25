"""Unit tests for tools/exiftool.py."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import config
from evidence import make_evidence
from state import State
from tools.exiftool import run_exiftool


def _make_state() -> State:
    state = State(case_id="CASE-EXIF", operator="Tester")
    state.phase_outputs["p1_provenance"] = {"identified_evidence": []}
    return state


def _make_parent(tmp_path: Path, name: str = "photo.jpg"):
    img = tmp_path / name
    img.write_bytes(b"img")
    return make_evidence(
        source_path=img.name,
        stored_path=img,
        parent=None,
        acquisition_method=config.ACQUISITION_LOGICAL,
        type=config.EVIDENCE_TYPE_EXTRACTED,
        artefact_category=config.IMAGES,
    )


def _fake_run(stdout: str, returncode: int = 0):
    def fake(args, **kwargs):
        return subprocess.CompletedProcess(args, returncode=returncode, stdout=stdout, stderr="")
    return fake


# --- run_exiftool subprocess failure ---

def test_run_exiftool_subprocess_exception_raises_anomaly(tmp_path: Path, monkeypatch) -> None:
    state = _make_state()
    parent = _make_parent(tmp_path)
    img = tmp_path / "photo.jpg"
    output_dir = tmp_path / "output"

    def _raise(*_a, **_kw): raise OSError("exiftool missing")
    monkeypatch.setattr(subprocess, "run", _raise)

    evidence, observation = run_exiftool(img, output_dir, state, parent, config.IMAGES)

    assert evidence is None
    assert observation is None
    assert any("ExifTool failed" in f for f in state.anomaly_flags)


# --- run_exiftool with real subprocess output ---

def test_run_exiftool_empty_stdout_returns_empty_observation(tmp_path: Path, monkeypatch) -> None:
    state = _make_state()
    parent = _make_parent(tmp_path)
    img = tmp_path / "photo.jpg"
    output_dir = tmp_path / "output"

    monkeypatch.setattr(subprocess, "run", _fake_run(stdout="[]"))

    evidence, observation = run_exiftool(img, output_dir, state, parent, config.IMAGES)

    assert evidence is not None
    assert observation is not None
    assert observation.content.observations == [{}]
    assert not state.anomaly_flags


def test_run_exiftool_image_fields_filtered_correctly(tmp_path: Path, monkeypatch) -> None:
    state = _make_state()
    parent = _make_parent(tmp_path)
    img = tmp_path / "photo.jpg"
    output_dir = tmp_path / "output"

    exif_data = [{
        "FileName": "photo.jpg",
        "DateTimeOriginal": "2018:04:19 11:24:49",
        "GPSLatitude": 39.96,
        "GPSLongitude": -106.21,
        "Make": "DJI",
        "UnrelatedField": "should_be_excluded",
    }]
    monkeypatch.setattr(subprocess, "run", _fake_run(stdout=json.dumps(exif_data)))

    evidence, observation = run_exiftool(img, output_dir, state, parent, config.IMAGES)
    assert observation is not None
    obs = observation.content.observations[0]
    assert obs["DateTimeOriginal"] == "2018:04:19 11:24:49"
    assert obs["GPSLatitude"] == 39.96
    assert "FileName" not in obs
    assert "UnrelatedField" not in obs
    assert observation.content.stored_path == str(img)
    assert not state.anomaly_flags


def test_run_exiftool_zero_date_excluded_from_observation(tmp_path: Path, monkeypatch) -> None:
    state = _make_state()
    parent = _make_parent(tmp_path)
    img = tmp_path / "photo.jpg"
    output_dir = tmp_path / "output"

    exif_data = [{
        "FileName": "photo.jpg",
        "DateTimeOriginal": "0000:00:00 00:00:00",
        "Make": "DJI",
    }]
    monkeypatch.setattr(subprocess, "run", _fake_run(stdout=json.dumps(exif_data)))

    evidence, observation = run_exiftool(img, output_dir, state, parent, config.IMAGES)
    assert observation is not None
    obs = observation.content.observations[0]
    assert "DateTimeOriginal" not in obs
    assert obs["Make"] == "DJI"


def test_run_exiftool_video_uses_video_field_filter(tmp_path: Path, monkeypatch) -> None:
    state = _make_state()
    vid = tmp_path / "clip.mp4"
    vid.write_bytes(b"vid")
    parent = make_evidence(
        source_path=vid.name,
        stored_path=vid,
        parent=None,
        acquisition_method=config.ACQUISITION_LOGICAL,
        type=config.EVIDENCE_TYPE_EXTRACTED,
        artefact_category=config.VIDEOS,
    )
    output_dir = tmp_path / "output"

    exif_data = [{
        "FileName": "clip.mp4",
        "Duration": 12.5,
        "DateTimeOriginal": "2018:04:19 11:24:49",  # image-only field
        "CreateDate": "2018:04:19 11:24:49",
        "GPSLatitude": 39.96,  # image-only field
    }]
    monkeypatch.setattr(subprocess, "run", _fake_run(stdout=json.dumps(exif_data)))

    evidence, observation = run_exiftool(vid, output_dir, state, parent, config.VIDEOS)
    assert observation is not None
    obs = observation.content.observations[0]
    assert obs["Duration"] == 12.5
    assert obs["CreateDate"] == "2018:04:19 11:24:49"
    assert "DateTimeOriginal" not in obs
    assert "GPSLatitude" not in obs


def test_run_exiftool_writes_json_to_disk(tmp_path: Path, monkeypatch) -> None:
    state = _make_state()
    parent = _make_parent(tmp_path)
    img = tmp_path / "photo.jpg"
    output_dir = tmp_path / "output"

    exif_data = [{"FileName": "photo.jpg", "Make": "DJI", "UnrelatedField": "kept_on_disk"}]
    monkeypatch.setattr(subprocess, "run", _fake_run(stdout=json.dumps(exif_data)))

    evidence, _ = run_exiftool(img, output_dir, state, parent, config.IMAGES)
    assert evidence is not None
    json_path = Path(str(evidence.stored_path))
    assert json_path.exists()
    written = json.loads(json_path.read_text(encoding="utf-8"))
    assert written["FileName"] == "photo.jpg"
    assert written["UnrelatedField"] == "kept_on_disk"


def test_run_exiftool_evidence_metadata(tmp_path: Path, monkeypatch) -> None:
    state = _make_state()
    parent = _make_parent(tmp_path)
    img = tmp_path / "photo.jpg"
    output_dir = tmp_path / "output"

    monkeypatch.setattr(subprocess, "run", _fake_run(stdout=json.dumps([{"FileName": "photo.jpg"}])))

    evidence, _ = run_exiftool(img, output_dir, state, parent, config.IMAGES)
    assert evidence is not None
    assert evidence.acquisition_method == config.ACQUISITION_EXIFTOOL
    assert evidence.artefact_category == config.IMAGES
    assert Path(str(evidence.stored_path)).name == "photo_exif.json"
    assert evidence.parent_sha256 == parent.sha256
