"""ExifTool integration helpers for DFDOF phase 4."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

from config import (
	ACQUISITION_EXIFTOOL,
	EVIDENCE_TYPE_PARSED,
	EXIFTOOL,
	IMAGES,
)
from evidence import Evidence, make_evidence
from observation import Observation, make_observation
from parsing.utils_parse import to_windows_path
from state import State

_EXIFTOOL_VERSION: str | None = None


def _get_exiftool_version() -> str | None:
    global _EXIFTOOL_VERSION
    if _EXIFTOOL_VERSION is None:
        try:
            ver_proc = subprocess.run([str(EXIFTOOL), "-ver"], capture_output=True, text=True, timeout=5)
            _EXIFTOOL_VERSION = ver_proc.stdout.strip() if ver_proc.stdout else ""
        except Exception:
            _EXIFTOOL_VERSION = ""
    return _EXIFTOOL_VERSION or None


_EXIF_IMAGE_FIELDS: set[str] = {
	"DateTimeOriginal", "CreateDate",
	"OffsetTimeOriginal", "OffsetTimeDigitized",
	"GPSLatitude", "GPSLongitude", "GPSAltitude",
	"GPSLatitudeRef", "GPSLongitudeRef", "GPSAltitudeRef",
	"Make", "Model", "Software",
	"ImageWidth", "ImageHeight", "Orientation",
	"AbsoluteAltitude", "RelativeAltitude",
	"GimbalRollDegree", "GimbalYawDegree", "GimbalPitchDegree",
	"FlightRollDegree", "FlightYawDegree", "FlightPitchDegree",
	"CalibratedFocalLength", "CalibratedOpticalCenterX", "CalibratedOpticalCenterY",
	"FileType", "MIMEType",
}

_EXIF_VIDEO_FIELDS: set[str] = {
	"CreateDate", "ModifyDate", "Duration",
	"OffsetTimeOriginal", "OffsetTimeDigitized",
	"ImageWidth", "ImageHeight",
	"Make", "Model", "Software", "GPSCoordinates",
	"AbsoluteAltitude", "RelativeAltitude",
	"GimbalRollDegree", "GimbalYawDegree", "GimbalPitchDegree",
	"FlightRollDegree", "FlightYawDegree", "FlightPitchDegree",
	"FileType", "MIMEType",
	"CompatibleBrands", "MediaDuration",
}


_ZERO_DATE = "0000:00:00 00:00:00"


def _exif_find(data: Any, field: str) -> Any:
	if isinstance(data, dict):
		value = data.get(field)
		if value not in (None, ""):
			return value
		for item in data.values():
			found = _exif_find(item, field)
			if found is not None:
				return found
	elif isinstance(data, list):
		for item in data:
			found = _exif_find(item, field)
			if found is not None:
				return found
	return None


def run_exiftool(
	file_path: Path,
	output_dir: Path,
	state: State,
	parent_evidence: Evidence,
	artefact_category: str,
	index: int | None = None,
) -> tuple[Evidence | None, Observation | None]:
	json_path = output_dir / f"{file_path.stem}_exif.json"
	version = _get_exiftool_version()
	# -b option is not used here because it emits large binary data not really relevant
	command = [str(EXIFTOOL), "-a", "-u", "-g1", "-s", "-ee", "-json", "-n", str(file_path)]

	# Run exiftool with JSON output and capture complete process.
	try:
		proc = subprocess.run(command, capture_output=True, text=True, timeout=30)
	except Exception as exc:
		state.log_tool_invocation(
			tool_name=ACQUISITION_EXIFTOOL,
			version=version,
			args=command,
			return_code=1,
			stdout=None,
			stderr=str(exc),
			output_paths=None,
		)
		state.raise_anomaly(4, parent_evidence.source_identification or "", f"ExifTool failed on {file_path.name}", category=artefact_category, index=index)
		return None, None

	# Parse JSON stdout if available.
	metadata: Any = []
	if proc.stdout:
		try:
			metadata = json.loads(proc.stdout)
		except Exception:
			metadata = []

	field_filter = _EXIF_IMAGE_FIELDS if artefact_category == IMAGES else _EXIF_VIDEO_FIELDS
	filtered_metadata = {
		key: value
		for key in field_filter
		if (value := _exif_find(metadata, key)) not in (None, "", _ZERO_DATE)
	}

	observation = make_observation(
		stored_path=str(parent_evidence.stored_path),
		evidence_sha256=parent_evidence.sha256,
		evidence_category=artefact_category,
		acquisition_method=ACQUISITION_EXIFTOOL,
		observations=[filtered_metadata],
	)

	output_dir.mkdir(parents=True, exist_ok=True)
	# Persist the command output directly as the JSON artefact.
	try:
		json_path.write_text(proc.stdout or json.dumps(metadata), encoding="utf-8")
	except Exception:
		pass

	# Log the subprocess result with details.
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
