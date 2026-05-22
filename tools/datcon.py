"""DatCon integration helpers for DFDOF phase 4."""

from __future__ import annotations

from pathlib import Path
import subprocess

from config import (
    DATCON,
	ACQUISITION_DATCON,
	DRONE_LOGS,
	EVIDENCE_TYPE_DECODED,
	VERSION_DATCON,
)
from evidence import Evidence, make_evidence
from parsing.utils_parse import to_windows_path
from state import State


def _datcon_settings_block(dat_path: Path, output_dir: Path) -> str:
	return (
		"-------------------------------\n"
		"DatCon is required for: {name}\n"
		"Please configure DatCon with the following settings:\n"
		"  .DAT file:           {dat_path}\n"
		"  Output Dir:          {output_dir}\n\n"
		"  Section: Time Axis\n"
		"    Offset:            Recording Start\n"
		"    Lower:             Recording Start\n"
		"    Upper:             Recording Stop\n\n"
		"  Section: CSV\n"
		"    Sample Rate:       30 Hz\n"
		"    Event Log:         Yes (checked)\n\n"
		"  Section: Log Files\n"
		"    Event Log File:    Yes (checked)\n"
		"    Config Log File:   Yes (checked)\n"
		"    RecDefs File:      No (unchecked)\n\n"
		"  Section: KML\n"
		"    Ground Track:      Yes (checked)\n\n"
		"Ready? Click the 'GO' button in DatCon to start exporting!"
	).format(name=dat_path.name, dat_path=dat_path, output_dir=output_dir)


def run_datcon(
	dat_path: Path,
	output_dir: Path,
	state: State,
	parent_evidence: Evidence,
	identification: str,
	index: int | None = None,
) -> list[Evidence]:
	print(_datcon_settings_block(dat_path, output_dir))
	output_dir.mkdir(parents=True, exist_ok=True)

	try:
		subprocess.Popen([str(DATCON)])
	except FileNotFoundError:
		state.log_tool_invocation(
			tool_name=ACQUISITION_DATCON,
			version=VERSION_DATCON,
			args=[str(DATCON), str(dat_path)],
			return_code=127,
			stdout=None,
			stderr=f"Tool not found: {DATCON}",
			output_paths=None,
		)
		if output_dir.exists() and not any(output_dir.iterdir()):
			output_dir.rmdir()
		state.raise_anomaly(4, identification, f"DatCon not found for {dat_path.name}", category=DRONE_LOGS, index=index)
		return []

	input("Once the export is finished, close DatCon, and type 'done' and press Enter: ")

	dat_stem = dat_path.stem
	output_files = [
		path
		for path in output_dir.iterdir()
		if path.is_file() and path.stem.startswith(dat_stem)
	]
	output_paths = [str(path) for path in output_files]
	state.log_tool_invocation(
		tool_name=ACQUISITION_DATCON,
		version=VERSION_DATCON,
		args=[str(DATCON), str(dat_path)],
		return_code=None,
		stdout=None,
		stderr=None,
		output_paths=output_paths or None,
	)

	if not output_files:
		if output_dir.exists() and not any(output_dir.iterdir()):
			output_dir.rmdir()
		state.raise_anomaly(4, identification, f"DatCon produced no output for {dat_path.name}", category=DRONE_LOGS, index=index)
		return []

	evidence_list: list[Evidence] = []
	for file_path in output_files:
		evidence_list.append(
			make_evidence(
				source_path=to_windows_path(str(dat_path)),
				stored_path=file_path,
				parent=parent_evidence,
				acquisition_method=ACQUISITION_DATCON,
				type=EVIDENCE_TYPE_DECODED,
				artefact_category=DRONE_LOGS,
			)
		)

	return evidence_list
