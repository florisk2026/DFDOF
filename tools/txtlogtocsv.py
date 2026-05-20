"""TXTlogToCSVtool integration helpers for DFDOF phase 4."""

from __future__ import annotations

from pathlib import Path
import subprocess
import shutil

from config import (
    FLIGHT_RECORDS,
    TXTLOGTOCSV,
    ACQUISITION_TXTLOGTOCSV,
    EVIDENCE_TYPE_DECODED,
    VERSION_TXTLOGTOCSV,
)
from evidence import Evidence, make_evidence
from parsing.utils_parse import to_windows_path
from state import State


def run_txtlogtocsv(
    txt_path: Path,
    output_dir: Path,
    state: State,
    parent_evidence: Evidence,
    identification: str,
    index: int | None = None,
) -> Evidence | None:
    csv_path = output_dir / f"{txt_path.stem}.csv"

    # Resolve executable: prefer configured path, fall back to PATH lookup.
    exe_path = Path(TXTLOGTOCSV)
    resolved_exe = None

    if exe_path.exists() and exe_path.is_file():
        resolved_exe = exe_path
    else:
        which_candidate = shutil.which(exe_path.name)
        if which_candidate:
            resolved_exe = Path(which_candidate)

    if resolved_exe is None or not resolved_exe.exists():
        state.log_tool_invocation(
            tool_name=ACQUISITION_TXTLOGTOCSV,
            version=VERSION_TXTLOGTOCSV,
            args=[str(TXTLOGTOCSV), str(txt_path)],
            return_code=127,
            stdout=None,
            stderr=f"Executable not found: {TXTLOGTOCSV}",
            output_paths=None,
        )
        state.raise_anomaly(4, identification, "TXTlogToCSV executable not found", category=FLIGHT_RECORDS, index=index)
        return None

    try:
        output_dir.mkdir(parents=True, exist_ok=True)
        result = subprocess.run(
            [str(resolved_exe), str(txt_path), str(csv_path)],
            capture_output=True,
            text=True,
            check=False,
        )
    except (FileNotFoundError, OSError) as exc:
        state.log_tool_invocation(
            tool_name=ACQUISITION_TXTLOGTOCSV,
            version=VERSION_TXTLOGTOCSV,
            args=[str(resolved_exe), str(txt_path)],
            return_code=127,
            stdout=None,
            stderr=str(exc),
            output_paths=None,
        )
        if output_dir.exists() and not any(output_dir.iterdir()):
            output_dir.rmdir()
        state.raise_anomaly(4, identification, f"TXTlogToCSV failed for {txt_path.name}", category=FLIGHT_RECORDS, index=index)
        return None

    state.log_command_result(
        tool_name=ACQUISITION_TXTLOGTOCSV,
        result=result,
        output_paths=[str(csv_path)],
        version=VERSION_TXTLOGTOCSV,
    )

    if (
        result.returncode != 0
        or not csv_path.exists()
        or csv_path.stat().st_size == 0
    ):
        if output_dir.exists() and not any(output_dir.iterdir()):
            output_dir.rmdir()
        state.raise_anomaly(4, identification, f"TXTlogToCSV failed for {txt_path.name}", category=FLIGHT_RECORDS, index=index)
        return None

    return make_evidence(
        source_path=to_windows_path(str(txt_path)),
        stored_path=csv_path,
        parent=parent_evidence,
        acquisition_method=ACQUISITION_TXTLOGTOCSV,
        type=EVIDENCE_TYPE_DECODED,
        artefact_category=FLIGHT_RECORDS,
    )
