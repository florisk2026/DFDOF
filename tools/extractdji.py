"""ExtractDJI integration helpers for DFDOF phase 4."""

from __future__ import annotations

import subprocess
from pathlib import Path

from config import (
    ACQUISITION_EXTRACT_DJI,
    DRONE_LOGS,
    EVIDENCE_TYPE_EXTRACTED,
    EXTRACT_DJI_EXE,
    VERSION_DJI_EXTRACT,
)
from evidence import Evidence, make_evidence
from parsing.extract_logical import ensure_unique_path
from parsing.utils_parse import to_windows_path
from state import State


def _extractdji_settings_block(dat_path: Path, output_dir: Path) -> str:
    return (
        "ExtractDJI is required for: {name}\n"
        "Please configure ExtractDJI with the following settings:\n"
        "  Input file:   {dat_path}\n"
        "  Output dir:   {output_dir}\n\n"
        "Ready? Click the 'GO' button in ExtractDJI to start converting!"
    ).format(name=dat_path.name, dat_path=dat_path, output_dir=output_dir)


def run_extractdji(
    dat_path: Path,
    output_dir: Path,
    state: State,
    parent_evidence: Evidence,
    identification: str,
    index: int | None = None,
) -> list[Evidence]:
    print(_extractdji_settings_block(dat_path, output_dir))
    output_dir.mkdir(parents=True, exist_ok=True)

    try:
        subprocess.Popen([str(EXTRACT_DJI_EXE), str(dat_path), str(output_dir)])
    except FileNotFoundError:
        state.log_tool_invocation(
            tool_name=ACQUISITION_EXTRACT_DJI,
            version=VERSION_DJI_EXTRACT,
            args=[str(EXTRACT_DJI_EXE), str(dat_path), str(output_dir)],
            return_code=127,
            stdout=None,
            stderr=f"Tool not found: {EXTRACT_DJI_EXE}",
            output_paths=None,
        )
        state.raise_anomaly(
            4, identification,
            f"ExtractDJI not found for {dat_path.name}",
            category=DRONE_LOGS, index=index,
        )
        return []

    input("Once the export is finished, type 'done' and press Enter: ")

    output_files = [
        p for p in output_dir.iterdir()
        if p.is_file() and p.suffix.upper() == ".DAT"
    ]
    output_paths_str = [str(p) for p in output_files]
    state.log_tool_invocation(
        tool_name=ACQUISITION_EXTRACT_DJI,
        version=VERSION_DJI_EXTRACT,
        args=[str(EXTRACT_DJI_EXE), str(dat_path), str(output_dir)],
        return_code=None,
        stdout=None,
        stderr=None,
        output_paths=output_paths_str or None,
    )

    if not output_files:
        state.raise_anomaly(
            4, identification,
            f"ExtractDJI produced no DAT files for {dat_path.name}",
            category=DRONE_LOGS, index=index,
        )
        return []

    evidence_list: list[Evidence] = []
    for file_path in output_files:
        target = ensure_unique_path(output_dir / file_path.name)
        if file_path != target:
            file_path.replace(target)
            file_path = target
        evidence_list.append(
            make_evidence(
                source_path=to_windows_path(str(dat_path)),
                stored_path=file_path,
                parent=parent_evidence,
                acquisition_method=ACQUISITION_EXTRACT_DJI,
                type=EVIDENCE_TYPE_EXTRACTED,
                artefact_category=DRONE_LOGS,
            )
        )

    return evidence_list
