from __future__ import annotations

import subprocess
from pathlib import Path
from typing import cast

from evidence import Evidence
from parsing.physical_reader import extract_tsk_image, parse_mmls_offset
from parsing.parse_utils import sanitise_path


def test_parse_mmls_offset_prefers_data_partition() -> None:
    sample_output = """
DOS Partition Table
Offset Sector: 0

	  Slot      Start        End          Length       Size      Description
000:  Meta      0000000000   0000000000   0000000001   512B      Table (#0)
001:  -------   0000000000   0000002047   0000002048   1.0M      Unallocated
002:  000:000   0000002048   0000012345   0000010298   5.0M      Primary Table (#0)
003:  000:001   0000012346   0000020000   0000007655   3.7M      Logical Linux (0x83)
"""

    assert parse_mmls_offset(sample_output) == 2048


def test_tsk_image_extraction_invokes_icat_for_matching_paths(
    tmp_path: Path, monkeypatch
) -> None:
    image_path = tmp_path / "mavic_air.E01"
    image_path.write_bytes(b"image fixture")
    working_dir = tmp_path / "working"

    commands: list[list[str]] = []
    tool_log: list[dict[str, object]] = []
    parent = Evidence(image_path, type="input")

    def fake_run(command, capture_output=True, text=True, check=False, stdout=None):
        _ = (capture_output, text, check)
        commands.append(command)
        executable = Path(command[0]).name.lower()
        if executable.startswith("mmls"):
            return subprocess.CompletedProcess(
                command,
                0,
                stdout="""
DOS Partition Table
	  Slot      Start        End          Length       Size      Description
002:  000:000   0000002048   0000012345   0000010298   5.0M      Primary Table (#0)
""",
            )
        if executable.startswith("fls"):
            return subprocess.CompletedProcess(
                command,
                0,
                stdout="""
r/r 1234: FlightRecord/DJIFlightRecord_2024-01-01.txt
r/r 1235: Logs/ignore.me
d/d 1236: FlightRecord/
""",
            )
        if executable.startswith("icat"):
            assert stdout is not None
            stdout.write(b"extracted flight record")
            return subprocess.CompletedProcess(command, 0, stdout="")
        raise AssertionError(f"Unexpected command: {command}")

    monkeypatch.setattr("parsing.physical_reader.subprocess.run", fake_run)

    extracted = extract_tsk_image(
        image_path,
        working_dir,
        include_paths=["FlightRecord/"],
        parent=parent,
        tool_log=tool_log.append,
    )

    assert len(extracted) == 1
    extracted_path = cast(Path, extracted[0].stored_path)
    assert extracted_path.exists()
    assert extracted_path.name == "DJIFlightRecord_2024-01-01.txt"
    assert extracted[0].parent_sha256 == parent.sha256
    assert extracted[0].source_path == "FlightRecord\\DJIFlightRecord_2024-01-01.txt"
    assert tool_log
    assert any(Path(command[0]).name.lower().startswith("icat") for command in commands)


def test_sanitise_path_blocks_traversal() -> None:
    assert sanitise_path("../../FlightRecord/../Logs/test.txt") == Path(
        "FlightRecord/Logs/test.txt"
    )
