from __future__ import annotations

from pathlib import Path

import config
from config import IMAGES
from evidence import Evidence, make_evidence
from state import State


def test_evidence_round_trip(tmp_path: Path) -> None:
    sample_file = tmp_path / "mavic_air_sample.bin"
    sample_file.write_bytes(b"DFDOF evidence test fixture\n")

    parent = make_evidence(
        source_path=sample_file,
        stored_path=sample_file,
        parent=None,
        acquisition_method=config.ACQUISITION_LOGICAL,
        type=config.EVIDENCE_TYPE_INPUT,
    )
    child = make_evidence(
        source_path=sample_file,
        stored_path=sample_file,
        parent=parent,
        acquisition_method="zip",
        type=config.EVIDENCE_TYPE_EXTRACTED,
        artefact_category=IMAGES,
    )

    assert len(child.sha256) == 64
    assert child.size == sample_file.stat().st_size

    round_tripped = Evidence.from_dict(child.to_dict())

    assert round_tripped.to_dict() == child.to_dict()
    assert "values" not in child.to_dict()
    assert round_tripped.sha256 == child.sha256
    assert round_tripped.sha1 == child.sha1
    assert round_tripped.parent_sha256 == child.parent_sha256
    assert str(round_tripped.source_path) == str(child.source_path)
    assert round_tripped.stored_path == child.stored_path
    assert round_tripped.size == child.size


def test_source_identification_propagates_from_parent(tmp_path: Path) -> None:
    f = tmp_path / "file.bin"
    f.write_bytes(b"x")
    parent = make_evidence(
        source_path=f,
        stored_path=f,
        parent=None,
        acquisition_method=config.ACQUISITION_LOGICAL,
        type=config.EVIDENCE_TYPE_INPUT,
        source_identification=config.IDENTIFICATION_CONTROLLER_IOS,
    )
    child = make_evidence(
        source_path=f,
        stored_path=f,
        parent=parent,
        acquisition_method=config.ACQUISITION_EXTRACT_LOGICAL,
        type=config.EVIDENCE_TYPE_EXTRACTED,
    )
    assert child.source_identification == config.IDENTIFICATION_CONTROLLER_IOS
    # Round-trip preserves the field
    assert Evidence.from_dict(child.to_dict()).source_identification == config.IDENTIFICATION_CONTROLLER_IOS


def test_evidence_directory_size_uses_recursive_content(tmp_path: Path) -> None:
    parsed_root = tmp_path / "ios_logical_parsed"
    (parsed_root / "domains" / "app").mkdir(parents=True)
    (parsed_root / "domains" / "app" / "a.bin").write_bytes(b"12345")
    (parsed_root / "domains" / "app" / "b.bin").write_bytes(b"12")

    evidence = make_evidence(
        source_path=parsed_root,
        stored_path=parsed_root,
        parent=None,
        acquisition_method=config.ACQUISITION_PARSER_IOS,
        type=config.EVIDENCE_TYPE_PARSED,
        skip_hash=True,
    )

    assert evidence.size == 7
