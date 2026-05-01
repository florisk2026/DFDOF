from __future__ import annotations

from pathlib import Path

from evidence import Evidence
from state import State


def test_evidence_round_trip(tmp_path: Path) -> None:
	sample_file = tmp_path / "mavic_air_sample.bin"
	sample_file.write_bytes(b"DFDOF evidence test fixture\n")

	parent = Evidence(sample_file, provenance="unit-test-parent", source_role="input")
	child = Evidence(
		sample_file,
		provenance="unit-test-child",
		parent=parent,
		source_role="derived",
		acquisition_method="zip",
		artefact_category="media",
	)

	assert len(child.sha256) == 64
	assert child.file_size == sample_file.stat().st_size

	round_tripped = Evidence.from_dict(child.to_dict())

	assert round_tripped.to_dict() == child.to_dict()
	assert round_tripped.sha256 == child.sha256
	assert round_tripped.sha1 == child.sha1
	assert round_tripped.parent_sha256 == child.parent_sha256
	assert round_tripped.file_size == child.file_size


def test_state_save_load_round_trip(tmp_path: Path) -> None:
	sample_file = tmp_path / "state_fixture.bin"
	sample_file.write_bytes(b"state fixture")

	evidence = Evidence(sample_file, provenance="state-test")
	state = State(case_id="CASE-001", operator="Floris", evidence_directory=str(tmp_path), input_evidence=[evidence])
	state.completed_phases.append("p1_provenance")
	state.log_tool_invocation(tool_name="mmls", version="TSK 4.15.0", args=["mmls", "image.E01"], return_code=0)

	state_path = tmp_path / "state.json"
	state.save(state_path)
	loaded = State.load(state_path)

	assert loaded.case_id == state.case_id
	assert loaded.operator == state.operator
	assert loaded.evidence_directory == str(tmp_path)
	assert loaded.completed_phases == ["p1_provenance"]
	assert loaded.input_evidence[0].to_dict() == evidence.to_dict()
	assert loaded.tool_invocation_log[0]["tool_name"] == "mmls"

