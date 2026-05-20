"""ExifTool integration helpers for DFDOF phase 4."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

from config import (
	ACQUISITION_EXIFTOOL,
	EVIDENCE_TYPE_PARSED,
	EXIFTOOL,
	EXIF_IMAGE_FIELDS,
	EXIF_VIDEO_FIELDS,
	IMAGES,
)
from evidence import Evidence, make_evidence
from observation import Observation, make_observation
from parsing.utils_parse import to_windows_path
from state import State


def _filter_metadata(metadata: dict) -> dict:
	return {key: value for key, value in metadata.items() if value not in (None, "")}


def run_exiftool(
	file_path: Path,
	output_dir: Path,
	state: State,
	parent_evidence: Evidence,
	artefact_category: str,
	identification: str,
	index: int | None = None,
) -> tuple[Evidence | None, Observation | None]:
	json_path = output_dir / f"{file_path.stem}_exif.json"

	# Probe exiftool version
	try:
		ver_proc = subprocess.run([str(EXIFTOOL), "-ver"], capture_output=True, text=True, timeout=5)
		version = ver_proc.stdout.strip() if ver_proc.stdout else None
	except Exception:
		version = None

	# Run exiftool with JSON output and capture complete process
	try:
		proc = subprocess.run(
			[str(EXIFTOOL), "-json", str(file_path)],
			capture_output=True,
			text=True,
			timeout=30,
		)
	except Exception as exc:
		state.log_tool_invocation(
			tool_name=ACQUISITION_EXIFTOOL,
			version=version,
			args=[str(EXIFTOOL), str(file_path)],
			return_code=1,
			stdout=None,
			stderr=str(exc),
			output_paths=None,
		)
		state.raise_anomaly(4, identification, f"ExifTool failed on {file_path.name}", category=artefact_category, index=index)
		return None, None

	# Parse JSON stdout if available
	metadata_list = []
	if proc.stdout:
		try:
			metadata_list = json.loads(proc.stdout)
		except Exception:
			metadata_list = []

	metadata = _filter_metadata(metadata_list[0] if metadata_list else {})
	field_filter = EXIF_IMAGE_FIELDS if artefact_category == IMAGES else EXIF_VIDEO_FIELDS
	_ZERO_DATE = "0000:00:00 00:00:00"
	filtered_metadata = {
		key: value
		for key, value in metadata.items()
		if key in field_filter and value not in (None, "", _ZERO_DATE)
	}

	observation = make_observation(
		evidence_sha256=parent_evidence.sha256,
		evidence_category=artefact_category,
		acquisition_method=ACQUISITION_EXIFTOOL,
		observations=[filtered_metadata],
	)

	output_dir.mkdir(parents=True, exist_ok=True)
	# Write full raw metadata to disk (unfiltered)
	try:
		json_path.write_text(json.dumps(metadata, indent=2), encoding="utf-8")
	except Exception:
		pass

	# Log the subprocess result with details
	state.log_command_result(
		tool_name=ACQUISITION_EXIFTOOL,
		result=proc,
		output_paths=[str(json_path)],
		version=version,
	)

	evidence = make_evidence(
		source_path=to_windows_path(str(file_path)),
		stored_path=json_path,
		parent=parent_evidence,
		acquisition_method=ACQUISITION_EXIFTOOL,
		type=EVIDENCE_TYPE_PARSED,
		artefact_category=artefact_category,
	)
	return evidence, observation
