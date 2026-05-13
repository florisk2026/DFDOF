"""Android parser for Phase 2 image parsing.

Extracts device metadata and backup info from Android acquisitions.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

from config import (
	ACQUISITION_PHYSICAL_READER,
	DEVICE_AND_BACKUP_INFO,
	DJI_APP_DOMAINS,
	EXTENSION_ZIP,
)
from evidence import Evidence
from parsing.logical_reader import extract_logical_files, extract_logical_member, find_acquisition_pdf_member
from parsing.physical_reader import extract_tsk_image
from state import State, _get_tsk_tool_version


TARGET_FILES = ["DeviceInfo.xml", "ApplicationInfo.xml", "ro.serialno", "net.hostname", "packages.list"]


@dataclass
class AndroidParserResult:
	output_root: Path


def _normalise_acquisition_method(value: str | None) -> str:
	"""Normalize acquisition method string for comparisons."""
	if value is None:
		return ""
	return str(value).strip().lower()


def _p1_image_metadata(state: State, image_name: str) -> dict[str, Any] | None:
	"""Retrieve persisted Phase 1 image metadata (offset and fls entries)."""
	return state.phase_outputs.get("p1_provenance", {}).get("image_metadata", {}).get(image_name)


def _log_tsk_tool(state: State, log_dict: dict[str, Any]) -> None:
	"""Convert TSK tool callbacks into log_tool_invocation entries."""
	tool_name = log_dict.get("tool_name") or "unknown"
	output_path = log_dict.get("output_path")
	output_paths = [str(output_path)] if output_path else None

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


def _parse_packages_list(path: Path) -> list[str]:
	"""Parse packages.list to find DJI package names."""
	allowed = {key.lower() for key in DJI_APP_DOMAINS["android"].keys()}
	found: list[str] = []
	for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
		if not line.strip():
			continue
		# packages.list format: package_name uid ...
		package = line.split()[0].strip().lower()
		if package in allowed and package not in found:
			found.append(package)
	return found


def _merge_if_empty(target: dict[str, Any], key: str, value: Any) -> None:
	"""Assign value if target key is empty or None."""
	if key not in target or target[key] in (None, ""):
		target[key] = value


def _merge_list_if_empty(target: dict[str, Any], key: str, value: list[str]) -> None:
	"""Assign list value if target list is empty."""
	if key not in target or target[key] in (None, []) or not target[key]:
		target[key] = value


def _ensure_unique_path(destination: Path) -> Path:
	"""Return a unique destination path if the target already exists."""
	if not destination.exists():
		return destination
	stem = destination.stem
	suffix = destination.suffix
	parent = destination.parent
	for idx in range(1, 1000):
		candidate = parent / f"{stem}_{idx}{suffix}"
		if not candidate.exists():
			return candidate
	return parent / f"{stem}_overflow{suffix}"


def _flatten_extracted_files(output_root: Path, extracted_files: list[Evidence]) -> None:
	"""Move extracted files into the output root to avoid nested folders."""
	for evidence_item in extracted_files:
		stored_path = Path(str(evidence_item.stored_path))
		if stored_path.parent == output_root:
			continue
		target_path = _ensure_unique_path(output_root / stored_path.name)
		target_path.parent.mkdir(parents=True, exist_ok=True)
		stored_path.replace(target_path)
		evidence_item.stored_path = target_path


def convert_android_source(
	source_evidence: Evidence,
	output_root: Path,
	state: State,
) -> AndroidParserResult:
	"""Convert an Android source into parsed files and backup_info.json."""
	stored_path = cast(Path, source_evidence.stored_path)
	acquisition_method = _normalise_acquisition_method(source_evidence.acquisition_method)
	is_logical = stored_path.suffix.lower() == EXTENSION_ZIP[0] or "logical" in acquisition_method

	output_root.mkdir(parents=True, exist_ok=True)

	# Import parsing helpers lazily to avoid circular import with p2_image_parsing.
	from phases import p2_image_parsing as p2_module
	_extract_android_device_metadata = p2_module._extract_android_device_metadata
	_extract_android_acquisition_metadata = p2_module._extract_android_acquisition_metadata

	extracted_files: list[Evidence] = []
	if is_logical:
		extracted_files = extract_logical_files(
			source_evidence,
			output_root,
			TARGET_FILES,
			artefact_category=DEVICE_AND_BACKUP_INFO,
			missing_ok=True,
		)
		_flatten_extracted_files(output_root, extracted_files)
	else:
		precomputed_entries = None
		offset_sectors = None
		p1_meta = _p1_image_metadata(state, str(stored_path.name))
		if p1_meta:
			offset_sectors = p1_meta.get("offset_sectors")
			precomputed_entries = [
				(entry["kind"], int(entry["inode"]), entry["path"])
				for entry in p1_meta.get("entries", [])
			]

		extract_kwargs: dict[str, Any] = {
			"include_paths": TARGET_FILES,
			"parent": source_evidence,
			"acquisition_method": ACQUISITION_PHYSICAL_READER,
			"artefact_category": DEVICE_AND_BACKUP_INFO,
			"tool_log": lambda log_dict: _log_tsk_tool(state, log_dict),
		}
		if precomputed_entries is not None:
			extract_kwargs["precomputed_entries"] = precomputed_entries
		if offset_sectors is not None:
			extract_kwargs["offset_sectors"] = offset_sectors

		extracted_files = extract_tsk_image(stored_path, output_root, **extract_kwargs)

	# Populate per-file metadata values
	_extract_android_device_metadata(extracted_files)

	# Track missing primary sources
	found_names = {Path(str(item.stored_path)).name.lower() for item in extracted_files}
	if "deviceinfo.xml" not in found_names:
		state.anomaly_flags.append(f"P2: Missing DeviceInfo.xml for {stored_path.name}")
	if "applicationinfo.xml" not in found_names:
		state.anomaly_flags.append(f"P2: Missing ApplicationInfo.xml for {stored_path.name}")

	# Layered backup_info.json assembly
	backup_info: dict[str, Any] = {
		"Build Version": None,
		"Device Name": None,
		"GUID": None,
		"Installed Applications": [],
		"Last Backup Date": None,
		"Product Name": None,
		"Product Type": None,
		"Product Version": None,
		"Serial Number": None,
		"Unique Identifier": None,
	}

	# Layer 1: DeviceInfo.xml + ApplicationInfo.xml
	for evidence_item in extracted_files:
		values = evidence_item.values or {}
		name = Path(str(evidence_item.stored_path)).name.lower()
		if name == "deviceinfo.xml":
			_merge_if_empty(backup_info, "Device Name", values.get("device_name"))
			_merge_if_empty(backup_info, "Product Name", values.get("model_name"))
			_merge_if_empty(backup_info, "Product Version", values.get("version"))
			_merge_if_empty(backup_info, "Build Version", values.get("firmware_version"))
		elif name == "applicationinfo.xml":
			_merge_list_if_empty(backup_info, "Installed Applications", values.get("installed_dji_apps", []))

	# Layer 2: ro.serialno, net.hostname, packages.list
	for evidence_item in extracted_files:
		values = evidence_item.values or {}
		name = Path(str(evidence_item.stored_path)).name.lower()
		if name == "ro.serialno":
			_merge_if_empty(backup_info, "Serial Number", values.get("device_serial"))
		elif name == "net.hostname":
			_merge_if_empty(backup_info, "Device Name", values.get("device_hostname"))
		elif name == "packages.list":
			installed = _parse_packages_list(Path(str(evidence_item.stored_path)))
			_merge_list_if_empty(backup_info, "Installed Applications", installed)
			if installed:
				evidence_item.values = {"installed_dji_apps": installed}

	# Layer 3: acquisition PDF
	acquisition_member = None
	acquisition_evidence: Evidence | None = None
	if is_logical:
		acquisition_member = find_acquisition_pdf_member(stored_path)
		if acquisition_member is not None:
			acquisition_evidence = extract_logical_member(
				source_evidence,
				output_root,
				acquisition_member,
				artefact_category=DEVICE_AND_BACKUP_INFO,
			)
			acquisition_values = _extract_android_acquisition_metadata(
				cast(Path, acquisition_evidence.stored_path)
			)
			acquisition_evidence.values = acquisition_values
			_merge_if_empty(backup_info, "Product Name", acquisition_values.get("phone_model"))
			_merge_if_empty(backup_info, "Last Backup Date", acquisition_values.get("acquisition_date"))

	# Store derived evidence entries for Phase 2
	parsed_evidence: list[dict[str, Any]] = []
	for item in extracted_files:
		parsed_evidence.append(item.to_dict())
	if acquisition_evidence is not None:
		parsed_evidence.append(acquisition_evidence.to_dict())
	state.phase_outputs.setdefault("p2_android_parser", {})["parsed_evidence"] = parsed_evidence

	backup_info_path = output_root / "backup_info.json"
	backup_info_path.write_text(json.dumps(backup_info, indent=2), encoding="utf-8")

	state.log_tool_invocation(
		tool_name="android_parser",
		args=[str(source_evidence.stored_path), str(output_root)],
		return_code=0,
		stdout=f"Parsed Android source to {output_root}",
		stderr=None,
	)

	return AndroidParserResult(output_root=output_root)
