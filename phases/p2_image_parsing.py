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
from parsing.android_parser import parse_android_source
from parsing.ios_parser import parse_ios_backup
from parsing.path_utils import to_windows_path
from phases.phase_utils import find_input_evidence_list_by_identification
from state import State


def _normalise_scalar(value: Any) -> str | None:
	"""Normalise a scalar value to a stripped string, or return None if empty."""
	if value is None:
		return None
	if isinstance(value, str):
		value = value.strip()
		return value or None
	text = str(value).strip()
	return text or None


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


def _append_evidence(parsed_evidence: list[dict[str, Any]], evidence: Evidence) -> None:
	"""Append an Evidence object to the parsed evidence list as a dictionary."""
	parsed_evidence.append(evidence.to_dict())


def _process_ios_source(state: State, ios_source: Evidence, ios_output_dir: Path, parsed_evidence: list[dict[str, Any]]) -> None:
	"""Process the iOS source evidence by converting the backup and extracting metadata."""
	ios_stored_path = cast(Path, ios_source.stored_path)
	result = parse_ios_backup(ios_stored_path, output_root=ios_output_dir)
	info_plist_path = result.output_root / "_metadata" / "Info.plist"
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

	if info_plist_path.exists():
		info_plist_metadata = _normalise_backup_info_values(backup_info_path) if backup_info_path.exists() else {}
		info_plist_evidence = Evidence(
			source_path=ios_source.source_path,
			stored_path=info_plist_path,
			parent=ios_source,
			acquisition_method=ACQUISITION_IOS_PARSER,
			type=EVIDENCE_TYPE_PARSED,
			artefact_category=DEVICE_AND_BACKUP_INFO,
			values=info_plist_metadata,
		)
		_append_evidence(parsed_evidence, info_plist_evidence)

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
			print("Parsing controller iOS")
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
			print("Parsing controller Android")
			android_output_dir = phase_dir / "controller_android_parsed"
			clear_and_make(android_output_dir)

			result = parse_android_source(android_source, android_output_dir, state)
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
