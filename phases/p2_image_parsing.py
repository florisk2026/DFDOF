"""DFDOF Phase 2: Image Parsing.

This phase:
 - create a case output directory,
 - parse and store controller iOS backups,

 - extract controller Android acquisition and device metadata.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, cast

from config import (
	DEVICE_AND_BACKUP_INFO,
	DJI_APP_DOMAINS,
	EVIDENCE_TYPE_PARSED,
	ACQUISITION_ANDROID_PARSER,
	ACQUISITION_IOS_PARSER,
	IDENTIFICATION_CONTROLLER_IOS,
	IDENTIFICATION_CONTROLLER_ANDROID,
	output_dir,
	utc_now_iso,
	clear_and_make,
)
from evidence import Evidence
from parsing.android_parser import convert_android_source
from parsing.ios_parser import convert_ios_backup
from parsing.logical_reader import extract_logical_member
from parsing.path_utils import to_windows_path
from phases.phase_utils import find_input_evidence_list_by_identification
from state import State

try:
	from pypdf import PdfReader
except Exception:  # pragma: no cover - optional dependency fallback
	PdfReader = None

_DATE_RE = re.compile(
	r"\b\d{4}-\d{2}-\d{2}(?:[ T]\d{2}:\d{2}:\d{2}(?:Z|[+-]\d{2}:?\d{2})?)?\b"
)


def _normalise_scalar(value: Any) -> str | None:
	"""Normalise a scalar value to a stripped string, or return None if empty."""
	if value is None:
		return None
	if isinstance(value, str):
		value = value.strip()
		return value or None
	text = str(value).strip()
	return text or None


def _normalise_key(value: Any) -> str:
	"""Normalise a key to a lowercase string with non-alphanumeric chars removed."""
	return re.sub(r"[^a-z0-9]+", "", str(value).lower())


def _lookup_nested_value(data: Any, candidate_keys: tuple[str, ...]) -> Any:
	"""Recursively search for a value in nested dict/list structures matching any of the candidate keys."""
	wanted = {_normalise_key(key) for key in candidate_keys}
	for k, v in _walk_nested(data):
		if k is not None and _normalise_key(k) in wanted:
			return v
	return None


def _collect_text_fragments(value: Any) -> list[str]:
	"""Collect text fragments from a nested structure, returning a list of non-empty stripped strings."""
	fragments: list[str] = []
	
	# Handle plain strings directly
	if isinstance(value, str):
		fragment = value.strip()
		if fragment:
			fragments.append(fragment)
		return fragments
	
	# Handle nested structures
	for _k, v in _walk_nested(value):
		if isinstance(v, str):
			fragment = v.strip()
			if fragment:
				fragments.append(fragment)
	return fragments


def _walk_nested(data: Any):
	"""Generator to walk through nested dict/list structures, yielding (key, value) pairs."""
	if isinstance(data, dict):
		for key, value in data.items():
			yield key, value
			if isinstance(value, (dict, list, tuple, set)):
				yield from _walk_nested(value)
	elif isinstance(data, (list, tuple, set)):
		for item in data:
			yield None, item
			if isinstance(item, (dict, list, tuple, set)):
				yield from _walk_nested(item)


def _collect_allowed_dji_apps(value: Any, allowed_domains: dict[str, str]) -> list[str]:
	"""Collect allowed DJI app domains from a value that may contain text or nested structures."""
	allowed = list(allowed_domains.keys())
	if isinstance(value, (list, tuple, set)):
		candidates = {str(item).strip().lower() for item in value if str(item).strip()}
		return [domain for domain in allowed if domain.lower() in candidates]

	fragments = _collect_text_fragments(value)
	selected: list[str] = []
	for domain in allowed:
		pattern = rf"(?<![A-Za-z0-9_.-]){re.escape(domain)}(?![A-Za-z0-9_.-])"
		if any(re.search(pattern, fragment, flags=re.IGNORECASE) for fragment in fragments):
			selected.append(domain)
	return selected


def _installed_dji_apps_from_backup_info(backup_info: dict[str, Any]) -> list[str]:
	"""Extract installed DJI apps from iOS backup_info, using the Installed Applications section if present."""
	installed = _lookup_nested_value(backup_info, ("Installed Applications", "InstalledApplications"))
	return _collect_allowed_dji_apps(installed, DJI_APP_DOMAINS["ios"])


def _read_text(path: Path) -> str:
	"""Read text content from a file, returning it as a string with UTF-8 encoding and replacement for errors."""
	return path.read_text(encoding="utf-8", errors="replace")


def _extract_pdf_text(path: Path) -> str:
	"""Extract text from a PDF file, returning it as a single string. Falls back to raw text if PDF parsing fails."""
	if PdfReader is not None:
		try:
			reader = PdfReader(str(path))
			chunks = [(page.extract_text() or "") for page in reader.pages]
			text = "\n".join(chunks).strip()
			if text:
				return text
		except Exception:
			pass
	return _read_text(path)


def _match_labeled_value(text: str, labels: tuple[str, ...]) -> str | None:
	"""Search for labeled values in text using multiple patterns, returning the first match found."""
	patterns = []
	for label in labels:
		escaped = re.escape(label)
		patterns.extend([
			rf"{escaped}\s*[:=]\s*([^\r\n<]+)",
			rf"<key>\s*{escaped}\s*</key>\s*<(?:string|date|integer|real)>\s*(.*?)\s*</(?:string|date|integer|real)>",
		])
	for pattern in patterns:
		match = re.search(pattern, text, flags=re.IGNORECASE | re.DOTALL)
		if match:
			return _normalise_scalar(match.group(1))
	return None


def _extract_android_acquisition_metadata(pdf_path: Path) -> dict[str, Any]:
	"""Extract relevant metadata from an Android acquisition PDF, returning a dictionary of normalized values."""
	text = _extract_pdf_text(pdf_path)
	mapping = {
		"phone_model": ("Phone model", "Device model", "Model"),
		"acquisition_date": ("Acquisition date", "Acquired on", "Date"),
	}
	result = _extract_metadata_dict(text, mapping)
	if result.get("acquisition_date") is None:
		match = _DATE_RE.search(text)
		result["acquisition_date"] = _normalise_scalar(match.group(0)) if match else None
	return result


def _extract_android_device_metadata(extracted_files: list[Evidence]) -> None:
	"""Extract and populate metadata from Android device files into their Evidence objects."""
	for evidence in extracted_files:
		stored_path = cast(Path, evidence.stored_path)
		file_name = stored_path.name.lower()
		text = _read_text(stored_path)
		values: dict[str, Any] = {}

		if file_name == "deviceinfo.xml":
			values["device_name"] = _match_labeled_value(text, ("Device Name", "DeviceName", "Name"))
			values["model_name"] = _match_labeled_value(text, ("Model Name", "ModelName", "Model"))
			values["version"] = _match_labeled_value(text, ("Version", "Device Version", "Android Version"))
			values["firmware_version"] = _match_labeled_value(
				text,
				("Firmware Version", "FirmwareVersion", "Build Version", "BuildVersion"),
			)
		elif file_name == "applicationinfo.xml":
			installed = _collect_allowed_dji_apps(text, DJI_APP_DOMAINS["android"])
			if installed:
				values["installed_dji_apps"] = installed
		elif file_name == "ro.serialno":
			values["device_serial"] = _normalise_scalar(text)
		elif file_name == "net.hostname":
			values["device_hostname"] = _normalise_scalar(text)

		evidence.values = values


def _extract_metadata_dict(data: Any, mapping: dict[str, tuple[str, ...]], *, extra: dict[str, Any] | None = None) -> dict[str, Any]:
	"""Extract metadata values from data using a mapping of output keys to candidate labels."""
	out: dict[str, Any] = {}
	for out_key, candidates in mapping.items():
		if isinstance(data, str):
			out[out_key] = _normalise_scalar(_match_labeled_value(data, candidates))
		else:
			out[out_key] = _normalise_scalar(_lookup_nested_value(data, candidates))
	if extra:
		out.update(extra)
	return out


def _normalise_backup_info_values(backup_info_path: Path) -> dict[str, Any]:
	"""Normalise backup_info.json values for evidence metadata."""
	def _key(value: str) -> str:
		return re.sub(r"[^a-z0-9]+", "", value.lower())

	backup_info = json.loads(backup_info_path.read_text(encoding="utf-8"))
	if not isinstance(backup_info, dict):
		backup_info = {}

	mapping = {
		"productname": "product_name",
		"productversion": "product_version",
		"devicename": "device_name",
		"lastbackupdate": "backup_date",
		"serialnumber": "serial_number",
		"uniqueidentifier": "unique_identifier",
		"installedapplications": "installed_dji_apps",
	}

	values: dict[str, Any] = {
		"product_name": None,
		"product_version": None,
		"device_name": None,
		"backup_date": None,
		"serial_number": None,
		"unique_identifier": None,
		"installed_dji_apps": [],
	}

	allowed_domains: dict[str, str] = {}
	allowed_domains.update(DJI_APP_DOMAINS.get("ios", {}))
	allowed_domains.update(DJI_APP_DOMAINS.get("android", {}))

	for raw_key, raw_value in backup_info.items():
		key = mapping.get(_key(str(raw_key)))
		if key is None:
			continue
		if key == "installed_dji_apps":
			values[key] = _collect_allowed_dji_apps(raw_value, allowed_domains)
		else:
			values[key] = _normalise_scalar(raw_value)

	return values


def _populate_acquisition_evidence(android_source: Evidence, android_output_dir: Path, pdf_member: str, parsed_evidence: list[dict[str, Any]]) -> None:
	"""Extract acquisition metadata from the PDF member and create a derived Evidence object."""
	acquisition_file = extract_logical_member(
		android_source,
		android_output_dir,
		pdf_member,
		artefact_category=DEVICE_AND_BACKUP_INFO,
	)
	acquisition_stored_path = cast(Path, acquisition_file.stored_path)
	acquisition_metadata = _extract_android_acquisition_metadata(acquisition_stored_path)
	acquisition_file.values = acquisition_metadata
	_append_evidence(parsed_evidence, acquisition_file)


def _append_evidence(parsed_evidence: list[dict[str, Any]], evidence: Evidence) -> None:
	"""Append an Evidence object to the parsed evidence list as a dictionary."""
	parsed_evidence.append(evidence.to_dict())


def _finalize_android_device_files(device_files: list[Evidence], parsed_evidence: list[dict[str, Any]]) -> None:
	"""Extract and populate metadata into each device file, then append."""
	_extract_android_device_metadata(device_files)
	for evidence in device_files:
		_append_evidence(parsed_evidence, evidence)


def _p1_image_metadata(state: State, image_name: str) -> dict[str, Any] | None:
	"""Retrieve persisted Phase 1 image metadata (offset and fls entries)."""
	return state.phase_outputs.get("p1_provenance", {}).get("image_metadata", {}).get(image_name)


def _process_ios_source(state: State, ios_source: Evidence, ios_output_dir: Path, parsed_evidence: list[dict[str, Any]]) -> None:
	"""Process the iOS source evidence by converting the backup and extracting metadata."""
	ios_stored_path = cast(Path, ios_source.stored_path)
	result = convert_ios_backup(ios_stored_path, output_root=ios_output_dir)
	backup_info_path = result.output_root / "backup_info.json"

	converted_root_evidence = Evidence(
		source_path=ios_source.source_path,
		stored_path=result.output_root,
		parent=ios_source,
		acquisition_method=ACQUISITION_IOS_PARSER,
		type=EVIDENCE_TYPE_PARSED,
		artefact_category=DEVICE_AND_BACKUP_INFO,
		skip_hash=True,
	)
	_append_evidence(parsed_evidence, converted_root_evidence)

	if backup_info_path.exists():
		backup_info_metadata = _normalise_backup_info_values(backup_info_path)
		backup_info_evidence = Evidence(
			source_path=ios_source.source_path,
			stored_path=backup_info_path,
			parent=ios_source,
			acquisition_method=ACQUISITION_IOS_PARSER,
			type=EVIDENCE_TYPE_PARSED,
			artefact_category=DEVICE_AND_BACKUP_INFO,
			values=backup_info_metadata,
		)
		_append_evidence(parsed_evidence, backup_info_evidence)
	else:
		state.anomaly_flags.append(f"P2: Missing backup_info.json for {ios_stored_path.name}")

	state.log_tool_invocation(
		tool_name="ios_parser",
		args=[str(ios_stored_path), str(ios_output_dir)],
		return_code=0,
		stdout=f"Parsed iOS source to {result.output_root}",
		stderr=None,
		output_paths=[str(result.output_root)],
	)


def run_phase_2(state: State) -> State:
	"""Create the case output directory and convert controller evidence."""
	# Validate that Phase 1 outputs are present and usable
	p1 = state.phase_outputs.get("p1_provenance")
	if not p1 or "identified_evidence" not in p1:
		raise ValueError("Phase 2 requires Phase 1 outputs (p1_provenance.identified_evidence). Run Phase 1 first.")

	phase_dir = output_dir() / state.case_id / "p2_image_parsing"
	clear_and_make(phase_dir)

	parsed_evidence: list[dict[str, Any]] = []

	ios_sources = find_input_evidence_list_by_identification(state, IDENTIFICATION_CONTROLLER_IOS)
	ios_source = ios_sources[0] if ios_sources else None
	if ios_source is None:
		state.anomaly_flags.append("P2: No controller_ios evidence found")
	else:
		try:
			ios_output_dir = phase_dir / "controller_ios_parsed"
			clear_and_make(ios_output_dir)

			_process_ios_source(state, ios_source, ios_output_dir, parsed_evidence)
		except Exception as exc:
			state.anomaly_flags.append(f"P2: Failed to convert {cast(Path, ios_source.stored_path)}: {exc}")

	android_sources = find_input_evidence_list_by_identification(state, IDENTIFICATION_CONTROLLER_ANDROID)
	android_source = android_sources[0] if android_sources else None
	if android_source is None:
		state.anomaly_flags.append("P2: No controller_android evidence found")
	else:
		try:
			android_output_dir = phase_dir / "controller_android_parsed"
			clear_and_make(android_output_dir)

			result = convert_android_source(android_source, android_output_dir, state)
			backup_info_path = result.output_root / "backup_info.json"

			if backup_info_path.exists():
				backup_info_metadata = _normalise_backup_info_values(backup_info_path)
				backup_info_evidence = Evidence(
					source_path=to_windows_path(str(android_source.source_path)),
					stored_path=backup_info_path,
					parent=android_source,
					acquisition_method=ACQUISITION_ANDROID_PARSER,
					type=EVIDENCE_TYPE_PARSED,
					artefact_category=DEVICE_AND_BACKUP_INFO,
					values=backup_info_metadata,
				)
				_append_evidence(parsed_evidence, backup_info_evidence)
			else:
				state.anomaly_flags.append(
					f"P2: Missing backup_info.json for {cast(Path, android_source.stored_path).name}"
				)

			android_parser_output = state.phase_outputs.pop("p2_android_parser", {}).get("parsed_evidence", [])
			parsed_evidence.extend(android_parser_output)
		except Exception as exc:
			state.anomaly_flags.append(f"P2: Failed to parse {cast(Path, android_source.stored_path)}: {exc}")

	now = utc_now_iso()
	state.phase_outputs["p2_image_parsing"] = {
		"completed_at": now,
		"parsed_evidence": parsed_evidence,
	}
	if "p2_image_parsing" not in state.completed_phases:
		state.completed_phases.append("p2_image_parsing")

	return state
