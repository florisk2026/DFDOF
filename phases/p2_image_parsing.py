"""DFDOF Phase 2: Image Parsing.

This phase:
 - create a case output directory,
 - parse and store controller iOS backups,
 - extract controller Android acquisition and device metadata.
"""

from __future__ import annotations

import json
import re
import shutil
from pathlib import Path
from typing import Any, cast

from config import (
	DEVICE_AND_BACKUP_INFO,
	DJI_APP_DOMAINS,
	EVIDENCE_TYPE_PARSED,
	ACQUISITION_IOS_PARSER,
	ACQUISITION_LOGICAL,
	ACQUISITION_TSK_MOUNTER,
	IDENTIFICATION_CONTROLLER_IOS,
	IDENTIFICATION_CONTROLLER_ANDROID,
	EXTENSION_ZIP,
	output_dir,
	utc_now_iso,
)
from evidence import Evidence
from parsing.ios_parser import convert_ios_backup
from parsing.logical_reader import extract_logical_files, extract_logical_member, find_acquisition_pdf_member
from parsing.physical_reader import extract_tsk_image
from phases.phase_utils import find_input_evidence_by_identification
from state import State, _get_tsk_tool_version

try:
	from pypdf import PdfReader
except Exception:  # pragma: no cover - optional dependency fallback
	PdfReader = None


_DATE_RE = re.compile(
	r"\b\d{4}-\d{2}-\d{2}(?:[ T]\d{2}:\d{2}:\d{2}(?:Z|[+-]\d{2}:?\d{2})?)?\b"
)


def _clear_and_make(path: Path) -> None:
	if path.exists():
		shutil.rmtree(path)
	path.mkdir(parents=True, exist_ok=True)


def _normalise_scalar(value: Any) -> str | None:
	if value is None:
		return None
	if isinstance(value, str):
		value = value.strip()
		return value or None
	text = str(value).strip()
	return text or None


def _normalise_key(value: Any) -> str:
	return re.sub(r"[^a-z0-9]+", "", str(value).lower())


def _lookup_nested_value(data: Any, candidate_keys: tuple[str, ...]) -> Any:
	wanted = {_normalise_key(key) for key in candidate_keys}
	for k, v in _walk_nested(data):
		if k is not None and _normalise_key(k) in wanted:
			return v
	return None


def _collect_text_fragments(value: Any) -> list[str]:
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
	"""Yield (key, value) pairs for nested dict/list structures.

	- For dict entries yields (key, value) and recursively walks value.
	- For list/tuple/set items yields (None, item) and recursively walks item.
	- Leaves that are not containers are not recursed further.
	"""
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
	installed = _lookup_nested_value(backup_info, ("Installed Applications", "InstalledApplications"))
	return _collect_allowed_dji_apps(installed, DJI_APP_DOMAINS["ios"])


def _read_text(path: Path) -> str:
	return path.read_text(encoding="utf-8", errors="replace")


def _extract_pdf_text(path: Path) -> str:
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


def _extract_ios_backup_metadata(backup_info: dict[str, Any]) -> dict[str, Any]:
	mapping = {
		"device_name": ("Device Name", "Display Name", "DeviceName"),
		"product_name": ("Product Name", "Product Type", "ProductType"),
		"ios_version": ("Product Version", "iOS Version", "ProductVersion"),
		"serial_number": ("Serial Number", "SerialNumber"),
		"uid": ("Unique Identifier", "UID", "GUID", "Target Identifier"),
		"backup_date": ("Last Backup Date", "Backup Date", "LastBackupDate"),
		"itunes_version": ("iTunes Version", "Itunes Version", "iTunesVersion"),
	}
	return _extract_metadata_dict(backup_info, mapping, extra={"installed_dji_apps": _installed_dji_apps_from_backup_info(backup_info)})


def _extract_android_acquisition_metadata(pdf_path: Path) -> dict[str, Any]:
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
	"""Extract and populate device metadata into each Evidence object's values field."""

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
	"""Generic metadata extractor.

	- `data` may be a nested mapping, a text blob or similar structure.
	- `mapping` maps output keys to a tuple of candidate labels to search for.
	- `extra` allows adding pre-computed values into the returned dict.
	"""
	out: dict[str, Any] = {}
	for out_key, candidates in mapping.items():
		if isinstance(data, str):
			out[out_key] = _normalise_scalar(_match_labeled_value(data, candidates))
		else:
			out[out_key] = _normalise_scalar(_lookup_nested_value(data, candidates))
	if extra:
		out.update(extra)
	return out


def _populate_acquisition_evidence(android_source: Evidence, android_output_dir: Path, pdf_member: str, derived_evidence: list[dict[str, Any]]) -> None:
	"""Extract acquisition PDF and populate its evidence values."""
	acquisition_file = extract_logical_member(
		android_source,
		android_output_dir,
		pdf_member,
		artefact_category=DEVICE_AND_BACKUP_INFO,
	)
	acquisition_stored_path = cast(Path, acquisition_file.stored_path)
	acquisition_metadata = _extract_android_acquisition_metadata(acquisition_stored_path)
	acquisition_file.values = acquisition_metadata
	_append_evidence(derived_evidence, acquisition_file)


def _append_evidence(derived_evidence: list[dict[str, Any]], evidence: Evidence) -> None:
	derived_evidence.append(evidence.to_dict())


def _finalize_android_device_files(device_files: list[Evidence], derived_evidence: list[dict[str, Any]]) -> None:
	"""Extract and populate metadata into each device file, then append."""
	_extract_android_device_metadata(device_files)
	for evidence in device_files:
		_append_evidence(derived_evidence, evidence)


def _p1_image_metadata(state: State, image_name: str) -> dict[str, Any] | None:
	"""Retrieve persisted Phase 1 image metadata (offset and fls entries)."""
	return state.phase_outputs.get("p1_provenance", {}).get("image_metadata", {}).get(image_name)


def _process_ios_source(state: State, ios_source: Evidence, ios_output_dir: Path, derived_evidence: list[dict[str, Any]]) -> None:
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
	_append_evidence(derived_evidence, converted_root_evidence)

	if backup_info_path.exists():
		backup_info_metadata = _extract_ios_backup_metadata(json.loads(backup_info_path.read_text(encoding="utf-8")))
		backup_info_evidence = Evidence(
			source_path=ios_source.source_path,
			stored_path=backup_info_path,
			parent=ios_source,
			acquisition_method=ACQUISITION_IOS_PARSER,
			type=EVIDENCE_TYPE_PARSED,
			artefact_category=DEVICE_AND_BACKUP_INFO,
			values=backup_info_metadata,
		)
		_append_evidence(derived_evidence, backup_info_evidence)
	else:
		state.anomaly_flags.append(f"P2: Missing backup_info.json for {ios_stored_path.name}")

	state.log_tool_invocation(
		tool_name="ios_parser",
		args=[str(ios_stored_path), str(ios_output_dir)],
		return_code=0,
		stdout=f"Converted iOS backup to {result.output_root}",
		stderr=None,
		output_paths=[str(result.output_root)],
	)


def _process_android_logical_source(
	android_source: Evidence,
	android_output_dir: Path,
	derived_evidence: list[dict[str, Any]],
) -> None:
	android_stored_path = cast(Path, android_source.stored_path)
	acquisition_pdf_member = find_acquisition_pdf_member(android_stored_path)
	if acquisition_pdf_member is not None:
		_populate_acquisition_evidence(
			android_source, android_output_dir, acquisition_pdf_member, derived_evidence
		)

	device_files = extract_logical_files(
		android_source,
		android_output_dir,
		["DeviceInfo.xml", "ApplicationInfo.xml", "ro.serialno", "net.hostname"],
		artefact_category=DEVICE_AND_BACKUP_INFO,
		missing_ok=True,
	)
	_finalize_android_device_files(device_files, derived_evidence)


def _process_android_physical_source(
	state: State,
	android_source: Evidence,
	android_output_dir: Path,
	derived_evidence: list[dict[str, Any]],
) -> None:
	android_stored_path = cast(Path, android_source.stored_path)
	
	# Inline logging for TSK tool callbacks: convert dict format to log_tool_invocation
	def _log_tsk_tool(log_dict: dict[str, Any]) -> None:
		tool_name = log_dict.get("tool_name") or "unknown"
		output_path = log_dict.get("output_path")
		output_paths = [str(output_path)] if output_path else None
		
		# Build args list from dict; for icat, expand cmd into typical invocation
		args_val: list[str] | None = None
		cmd = log_dict.get("cmd")
		if cmd is not None:
			cmd_list = cmd if isinstance(cmd, list) else [cmd]
			if tool_name == "icat" and cmd_list:
				offset = log_dict.get("offset_sectors") or ""
				source = log_dict.get("source_path") or ""
				inode = log_dict.get("inode") or ""
				args_val = [cmd_list[0], "-o", str(offset), str(source), str(inode)]
			else:
				args_val = [str(v) for v in cmd_list]
		
		# Probe version for known TSK tools
		version_val = None
		if cmd:
			cmd_path = cmd if isinstance(cmd, str) else (cmd[0] if isinstance(cmd, list) else None)
			if cmd_path:
				version_val = _get_tsk_tool_version(str(cmd_path))
		
		state.log_tool_invocation(
			tool_name=tool_name,
			version=version_val,
			args=args_val,
			return_code=log_dict.get("return_code"),
			stdout=log_dict.get("stdout"),
			stderr=log_dict.get("stderr"),
			output_paths=output_paths,
		)
	
	# Attempt to reuse Phase 1 metadata (offset and fls entries) to avoid re-running mmls/fls
	precomputed_entries = None
	offset_sectors = None
	p1_meta = _p1_image_metadata(state, str(android_stored_path.name))
	if p1_meta:
		offset_sectors = p1_meta.get("offset_sectors")
		precomputed_entries = [ (entry["kind"], int(entry["inode"]), entry["path"]) for entry in p1_meta.get("entries", []) ]

	extract_kwargs: dict[str, Any] = {
		"include_paths": ["DeviceInfo.xml", "ApplicationInfo.xml", "ro.serialno", "net.hostname"],
		"parent": android_source,
		"acquisition_method": ACQUISITION_TSK_MOUNTER,
		"artefact_category": DEVICE_AND_BACKUP_INFO,
		"tool_log": _log_tsk_tool,
	}
	if precomputed_entries is not None:
		extract_kwargs["precomputed_entries"] = precomputed_entries
	if offset_sectors is not None:
		extract_kwargs["offset_sectors"] = offset_sectors

	device_files = extract_tsk_image(android_stored_path, android_output_dir, **extract_kwargs)
	_finalize_android_device_files(device_files, derived_evidence)


def run_phase_2(state: State) -> State:
	"""Create the case output directory and convert controller evidence."""
	# Validate that Phase 1 outputs are present and usable
	p1 = state.phase_outputs.get("p1_provenance")
	if not p1 or "identified_evidence" not in p1:
		raise ValueError("Phase 2 requires Phase 1 outputs (p1_provenance.identified_evidence). Run Phase 1 first.")

	phase_dir = output_dir() / state.case_id / "p2_image_parsing"
	_clear_and_make(phase_dir)

	android_output_dir = phase_dir / "controller_android_parsed"
	_clear_and_make(android_output_dir)

	ios_output_dir = phase_dir / "controller_ios_parsed"
	_clear_and_make(ios_output_dir)

	derived_evidence: list[dict[str, Any]] = []

	ios_source = find_input_evidence_by_identification(state, IDENTIFICATION_CONTROLLER_IOS)
	if ios_source is None:
		state.anomaly_flags.append("P2: No controller_ios evidence found")
	else:
		try:
			_process_ios_source(state, ios_source, ios_output_dir, derived_evidence)
		except Exception as exc:
			state.anomaly_flags.append(f"P2: Failed to convert {cast(Path, ios_source.stored_path)}: {exc}")

	android_source = find_input_evidence_by_identification(state, IDENTIFICATION_CONTROLLER_ANDROID)
	if android_source is None:
		state.anomaly_flags.append("P2: No controller_android evidence found")
	else:
		try:
			android_stored_path = cast(Path, android_source.stored_path)
			if android_source.acquisition_method == ACQUISITION_LOGICAL or android_stored_path.suffix.lower() == EXTENSION_ZIP[0]:
				_process_android_logical_source(android_source, android_output_dir, derived_evidence)
			else:
				_process_android_physical_source(state, android_source, android_output_dir, derived_evidence)
		except Exception as exc:
			state.anomaly_flags.append(f"P2: Failed to parse {cast(Path, android_source.stored_path)}: {exc}")

	now = utc_now_iso()
	state.phase_outputs["p2_image_parsing"] = {
		"completed_at": now,
		"derived_evidence": derived_evidence,
	}
	if "p2_image_parsing" not in state.completed_phases:
		state.completed_phases.append("p2_image_parsing")

	return state
