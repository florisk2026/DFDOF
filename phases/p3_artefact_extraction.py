"""DFDOF Phase 3: Artefact Extraction.

Extracts categorised artefacts from identified evidence sources.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import zipfile
from pathlib import Path
from typing import Any, Iterable

from config import (
	ACCOUNT_DATA,
	ARTEFACT_DATABASES_INCLUDES,
	ARTEFACT_EXTENSIONS,
	ARTEFACT_EXTENSIONS_DRONE_SD,
	ARTEFACT_PATHS,
	ACQUISITION_LOGICAL_READER,
	ACQUISITION_PHYSICAL_READER,
	DATABASES,
	DEVICE_AND_BACKUP_INFO,
	DJI_APP_DOMAINS,
	DRONE_LOGS,
	EVIDENCE_TYPE_EXTRACTED,
	EXTRACT_DJI_EXE,
	EXTENSION_ZIP,
	FLIGHT_LOGS,
	FLIGHT_RECORDS,
	IDENTIFICATION_CONTROLLER_ANDROID,
	IDENTIFICATION_CONTROLLER_IOS,
	IDENTIFICATION_DRONE_FLIGHT_STORAGE,
	IDENTIFICATION_DRONE_SD,
	IMAGES,
	TSK_ICAT,
	VIDEOS,
	clear_and_make,
	output_dir,
	utc_now_iso,
)
from evidence import Evidence
from parsing.logical_reader import extract_logical_files
from parsing.path_utils import normalise_path, safe_segment, to_windows_path
from parsing.physical_reader import extract_tsk_image, run_command
from phases.phase_utils import find_input_evidence_list_by_identification
from state import State, _get_tsk_tool_version


_DJI_EXPORT_RE = re.compile(r"^DJI_ASSISTANT_EXPORT_FILE_.*\.DAT$", re.IGNORECASE)


def _build_path_category_index() -> dict[str, list[str]]:
	"""Build a reverse index of artefact paths to their categories."""
	index: dict[str, list[str]] = {}
	for category, paths in ARTEFACT_PATHS.items():
		for path in paths:
			normalised = normalise_path(path, to_lower=True)
			index.setdefault(normalised, []).append(category)
	return index


def _is_database_included(filename: str) -> bool:
	"""Return True if filename stem matches any database include token."""
	stem = Path(filename).stem.lower()
	return any(token.lower() in stem for token in ARTEFACT_DATABASES_INCLUDES)


def _get_cached_offset(state: State, image_path: Path) -> int | None:
	"""Retrieve cached mmls offset for an image from Phase 1 metadata."""
	meta = _lookup_cached_image_metadata(state, image_path)
	if not meta:
		return None
	return meta.get("offset_sectors")


def _get_cached_entries(state: State, image_path: Path) -> list[tuple[str, int, str]] | None:
	"""Retrieve cached fls entries for an image from Phase 1 metadata."""
	meta = _lookup_cached_image_metadata(state, image_path)
	if not meta:
		return None
	entries = []
	for entry in meta.get("entries", []):
		try:
			entries.append((str(entry["kind"]), int(entry["inode"]), str(entry["path"])))
		except Exception:
			continue
	return entries or None


def _lookup_cached_image_metadata(state: State, image_path: Path) -> dict[str, Any] | None:
	"""Locate cached image metadata by filename or suffix match."""
	metadata = state.phase_outputs.get("p1_provenance", {}).get("image_metadata", {})
	if not isinstance(metadata, dict):
		return None
	name = image_path.name
	if name in metadata:
		return metadata.get(name)
	name_lower = name.lower()
	for key, value in metadata.items():
		try:
			if str(key).lower() == name_lower:
				return value
		except Exception:
			continue
	return None


def _normalise_acquisition_method(value: str | None) -> str:
	"""Normalise acquisition method strings for comparisons."""
	return (value or "").strip().lower()


def _log_tsk_tool(state: State, log_dict: dict[str, Any]) -> None:
	"""Log TSK tool invocations from physical_reader callbacks."""
	tool_name = str(log_dict.get("tool_name") or "unknown")
	if tool_name not in {"mmls", "fls", "icat"}:
		return

	args_val: list[str] | None = None
	cmd = log_dict.get("cmd")
	if cmd is not None:
		cmd_list = cmd if isinstance(cmd, list) else [cmd]
		if tool_name == "icat" and cmd_list:
			offset = log_dict.get("offset_sectors") or ""
			source = log_dict.get("source_path") or ""
			inode = log_dict.get("inode") or ""
			args_val = [str(cmd_list[0]), "-o", str(offset), str(source), str(inode)]
		else:
			args_val = [str(value) for value in cmd_list]

	version_val = None
	if cmd:
		cmd_path = cmd if isinstance(cmd, str) else (cmd[0] if isinstance(cmd, list) else None)
		if cmd_path:
			version_val = _get_tsk_tool_version(str(cmd_path))

	output_path = log_dict.get("output_path")
	output_paths = [str(output_path)] if output_path else None
	state.log_tool_invocation(
		tool_name=tool_name,
		version=version_val,
		args=args_val,
		return_code=log_dict.get("return_code"),
		stdout=log_dict.get("stdout"),
		stderr=log_dict.get("stderr"),
		output_paths=output_paths,
	)


def _ensure_unique_path(target: Path) -> Path:
	"""Return a non-colliding target path by appending a numeric suffix if needed."""
	if not target.exists():
		return target
	stem = target.stem
	suffix = target.suffix
	for idx in range(1, 1000):
		candidate = target.with_name(f"{stem}_{idx}{suffix}")
		if not candidate.exists():
			return candidate
	return target


def _flatten_evidence_outputs(evidence_items: list[Evidence], output_dir: Path) -> list[Evidence]:
	"""Move extracted files into the category root to avoid nested paths."""
	flattened: list[Evidence] = []
	for item in evidence_items:
		stored_path = Path(str(item.stored_path))
		target_path = _ensure_unique_path(output_dir / stored_path.name)
		target_path.parent.mkdir(parents=True, exist_ok=True)
		if stored_path != target_path:
			stored_path.replace(target_path)
		item.stored_path = target_path
		flattened.append(item)
	return flattened


def _prune_empty_dirs(root: Path) -> None:
	"""Remove empty subdirectories under a root directory."""
	if not root.exists():
		return
	for path in sorted(root.rglob("*"), reverse=True):
		if path.is_dir():
			try:
				path.rmdir()
			except OSError:
				pass


def _account_targets(os_key: str) -> set[str]:
	"""Return expected account data filenames for a platform."""
	if os_key == "android":
		ext = ".xml"
	else:
		ext = ".plist"
	return {f"{domain}{ext}".lower() for domain in DJI_APP_DOMAINS[os_key].keys()}


def _drone_sd_category_for_suffix(suffix: str) -> str | None:
	"""Return the drone SD category for a filename suffix."""
	suffix = suffix.lower()
	if suffix == ".thm":
		return IMAGES
	if suffix == ".mp4":
		return VIDEOS
	return None


def _extract_drone_sd_physical(
	state: State,
	sd_source: Evidence,
	output_root: Path,
) -> list[Evidence]:
	"""Extract drone SD artefacts from a physical image without duplicated icat runs."""
	sd_archive = Path(str(sd_source.stored_path))
	entries = _get_cached_entries(state, sd_archive)
	if not entries:
		raise RuntimeError(f"No cached fls entries for {sd_archive.name}")
	offset_sectors = _get_cached_offset(state, sd_archive)
	output_root.mkdir(parents=True, exist_ok=True)

	extensions = {ext.lower() for ext in ARTEFACT_EXTENSIONS_DRONE_SD}
	extracted: list[Evidence] = []

	for kind, inode, rel_path in entries:
		if not str(kind).startswith("r"):
			continue
		suffix = Path(rel_path).suffix.lower()
		if suffix not in extensions:
			continue
		category = _drone_sd_category_for_suffix(suffix)
		if category is None:
			continue
		output_dir = output_root / safe_segment(category)
		output_dir.mkdir(parents=True, exist_ok=True)
		output_path = _ensure_unique_path(output_dir / Path(rel_path).name)
		with output_path.open("wb") as output_handle:
			result = run_command(
				[str(TSK_ICAT), "-o", str(offset_sectors or 0), str(sd_archive), str(inode)],
				capture_output=False,
				stdout=output_handle,
			)
		if result.returncode != 0:
			raise RuntimeError(f"icat failed for inode {inode} in {sd_archive}")
		state.log_tool_invocation(
			tool_name="icat",
			version=_get_tsk_tool_version(str(TSK_ICAT)),
			args=[str(TSK_ICAT), "-o", str(offset_sectors or 0), str(sd_archive), str(inode)],
			return_code=result.returncode,
			stdout=result.stdout or None,
			stderr=result.stderr or None,
			output_paths=[str(output_path)],
		)
		extracted.append(
			Evidence(
				source_path=to_windows_path(rel_path),
				stored_path=output_path,
				parent=sd_source,
				acquisition_method=ACQUISITION_PHYSICAL_READER,
				type=EVIDENCE_TYPE_EXTRACTED,
				artefact_category=category,
			)
		)

	return extracted


def _collect_account_members(member_names: Iterable[str], os_key: str) -> list[str]:
	"""Collect account data members from a ZIP archive by filename."""
	targets = _account_targets(os_key)
	return [name for name in member_names if Path(name).name.lower() in targets]


def _collect_account_files(parsed_root: Path, os_key: str) -> list[Path]:
	"""Collect account data files from a parsed folder by filename."""
	targets = _account_targets(os_key)
	return [path for path in parsed_root.rglob("*") if path.is_file() and path.name.lower() in targets]


def _collect_parsed_files(parsed_root: Path, category: str) -> list[Path]:
	"""Collect parsed iOS files that match the artefact category filters."""
	if category == ACCOUNT_DATA:
		return []
	paths = {normalise_path(path, to_lower=True) for path in ARTEFACT_PATHS.get(category, set())}
	extensions = {ext.lower() for ext in ARTEFACT_EXTENSIONS.get(category, set())}

	matched: list[Path] = []
	for file_path in parsed_root.rglob("*"):
		if not file_path.is_file():
			continue
		suffix = file_path.suffix.lower()
		if suffix not in extensions:
			continue
		rel_path = normalise_path(str(file_path.relative_to(parsed_root)), to_lower=True)
		if paths and not any(token in rel_path for token in paths):
			continue
		if category == DATABASES and not _is_database_included(file_path.name):
			continue
		matched.append(file_path)
	return matched


def _copy_parsed_files(
	parsed_root: Path,
	files: list[Path],
	output_dir: Path,
	parent: Evidence,
	category: str,
	acquisition_method: str,
) -> list[Evidence]:
	"""Copy parsed files into the phase output directory and wrap as Evidence."""
	extracted: list[Evidence] = []
	for file_path in files:
		output_path = _ensure_unique_path(output_dir / file_path.name)
		output_path.parent.mkdir(parents=True, exist_ok=True)
		shutil.copy2(file_path, output_path)
		rel_source = to_windows_path(str(file_path.relative_to(parsed_root)))
		extracted.append(
			Evidence(
				source_path=rel_source,
				stored_path=output_path,
				parent=parent,
				acquisition_method=acquisition_method,
				type=EVIDENCE_TYPE_EXTRACTED,
				artefact_category=category,
			)
		)
	return extracted


def _member_names(zip_path: Path) -> list[str]:
	"""Return archive member names excluding directories."""
	with zipfile.ZipFile(zip_path) as archive:
		return [name for name in archive.namelist() if not name.endswith("/")]


def _collect_members_by_category(
	member_names: Iterable[str],
	categories: Iterable[str],
) -> dict[str, list[str]]:
	"""Collect archive members per category using a single pass."""
	requested = set(categories)
	path_index = _build_path_category_index()
	category_members: dict[str, list[str]] = {category: [] for category in requested}

	for name in member_names:
		normalised = normalise_path(name, to_lower=True)
		filename = Path(name).name
		suffix = Path(filename).suffix.lower()

		matching_categories: set[str] = set()
		for token, cats in path_index.items():
			if token in normalised:
				matching_categories.update(cats)

		for category in matching_categories:
			if category not in requested:
				continue
			ext_set = {ext.lower() for ext in ARTEFACT_EXTENSIONS[category]}
			if suffix not in ext_set:
				continue
			if category == DATABASES and not _is_database_included(filename):
				continue
			category_members[category].append(name)

	return category_members


def _probe_extract_dji_version() -> str | None:
	"""Attempt to extract an ExtractDJI.exe version string."""
	try:
		result = subprocess.run(
			[str(EXTRACT_DJI_EXE), "--version"],
			capture_output=True,
			text=True,
			timeout=5,
			check=False,
		)
		combined = "\n".join([result.stdout or "", result.stderr or ""]).strip()
		if combined:
			return combined.splitlines()[0].strip()
	except Exception:
		pass
	return None


def run_phase_3(state: State) -> State:
	"""Extract and categorise artefacts for all identified evidence sources."""
	if "p1_provenance" not in state.phase_outputs:
		raise ValueError("Phase 3 requires Phase 1 outputs. Run Phase 1 first.")

	phase_dir = output_dir() / state.case_id / "p3_artefact_extraction"
	clear_and_make(phase_dir)
	staging_root = phase_dir / "_staging"

	extracted: list[Evidence] = []

	# Controller iOS
	ios_sources = find_input_evidence_list_by_identification(state, IDENTIFICATION_CONTROLLER_IOS)
	ios_source = ios_sources[0] if ios_sources else None
	ios_parsed_root: Path | None = None
	if ios_source is not None:
		p2_records = state.phase_outputs.get("p2_image_parsing", {}).get("parsed_evidence", [])
		for record in p2_records:
			if not isinstance(record, dict):
				continue
			if record.get("artefact_category") != DEVICE_AND_BACKUP_INFO:
				continue
			if str(record.get("source_path")) != str(ios_source.source_path):
				continue
			stored_path = Path(str(record.get("stored_path")))
			if stored_path.exists() and stored_path.is_dir():
				ios_parsed_root = stored_path
				break

	if ios_source is None:
		state.anomaly_flags.append("p3_no_source:controller_ios")
	elif ios_parsed_root is None:
		state.anomaly_flags.append("p3_missing_ios_parsed_root")
	else:
		ios_acquisition = _normalise_acquisition_method(ios_source.acquisition_method)
		if ios_acquisition == "physical":
			ios_acquisition_method = ACQUISITION_PHYSICAL_READER
		else:
			ios_acquisition_method = ACQUISITION_LOGICAL_READER
		controller_ios_dir = phase_dir / "controller_ios"
		clear_and_make(controller_ios_dir)
		print("Extracting from controller_ios")
		categories = [DRONE_LOGS, FLIGHT_RECORDS, FLIGHT_LOGS, IMAGES, VIDEOS, DATABASES, ACCOUNT_DATA]
		for category in categories:
			try:
				if category == ACCOUNT_DATA:
					matched_files = _collect_account_files(ios_parsed_root, "ios")
				else:
					matched_files = _collect_parsed_files(ios_parsed_root, category)
				if matched_files:
					output_dir_cat = controller_ios_dir / safe_segment(category)
					evidence_list = _copy_parsed_files(
						ios_parsed_root,
						matched_files,
						output_dir_cat,
						ios_source,
						category,
						ios_acquisition_method,
					)
					extracted.extend(evidence_list)
				else:
					state.anomaly_flags.append(f"p3_no_artefacts:{category}:controller_ios")
			except Exception as exc:
				state.anomaly_flags.append(f"p3_extraction_failed:{category}:controller_ios:{exc}")

	# Controller Android
	android_sources = find_input_evidence_list_by_identification(state, IDENTIFICATION_CONTROLLER_ANDROID)
	android_source = android_sources[0] if android_sources else None
	if android_source is None:
		state.anomaly_flags.append("p3_no_source:controller_android")
	else:
		controller_android_dir = phase_dir / "controller_android"
		clear_and_make(controller_android_dir)
		print("Extracting from controller_android")
		android_archive = Path(str(android_source.stored_path))
		acquisition_method = _normalise_acquisition_method(android_source.acquisition_method)
		is_logical = acquisition_method == "logical" or android_archive.suffix.lower() == EXTENSION_ZIP[0]
		categories = [DRONE_LOGS, FLIGHT_RECORDS, FLIGHT_LOGS, IMAGES, VIDEOS, DATABASES, ACCOUNT_DATA]
		if is_logical:
			member_names = _member_names(android_archive)
			members_by_category = _collect_members_by_category(
				member_names,
				[cat for cat in categories if cat != ACCOUNT_DATA],
			)
			account_members = _collect_account_members(member_names, "android")
			for category in categories:
				try:
					members = []
					if category == ACCOUNT_DATA:
						members = account_members
					else:
						members = members_by_category.get(category, [])
					evidence_list: list[Evidence] = []
					if members:
						output_dir_cat = controller_android_dir / safe_segment(category)
						evidence_list = extract_logical_files(
							android_source,
							output_dir_cat,
							members,
							artefact_category=category,
							missing_ok=True,
						)
						evidence_list = _flatten_evidence_outputs(evidence_list, output_dir_cat)
						_prune_empty_dirs(output_dir_cat)
						extracted.extend(evidence_list)
						if not evidence_list:
							shutil.rmtree(output_dir_cat, ignore_errors=True)
					else:
						state.anomaly_flags.append(f"p3_no_artefacts:{category}:controller_android")
				except Exception as exc:
					state.anomaly_flags.append(f"p3_extraction_failed:{category}:controller_android:{exc}")
		else:
			precomputed_entries = _get_cached_entries(state, android_archive)
			offset_sectors = _get_cached_offset(state, android_archive)
			for category in categories:
				try:
					staging_dir = staging_root / "controller_android" / safe_segment(category)
					staging_dir.mkdir(parents=True, exist_ok=True)
					if category == ACCOUNT_DATA:
						include_paths = list(_account_targets("android"))
					else:
						include_paths = sorted(ARTEFACT_PATHS.get(category, set()))

					evidence_list = extract_tsk_image(
						android_archive,
						staging_dir,
						include_paths=include_paths,
						parent=android_source,
						artefact_category=category,
						precomputed_entries=precomputed_entries,
						offset_sectors=offset_sectors,
						tool_log=lambda log_dict: _log_tsk_tool(state, log_dict),
					)

					filtered: list[Evidence] = []
					ext_set = {ext.lower() for ext in ARTEFACT_EXTENSIONS.get(category, set())}
					account_targets = _account_targets("android")
					for item in evidence_list:
						stored_path = Path(str(item.stored_path))
						suffix = stored_path.suffix.lower()
						if category == ACCOUNT_DATA:
							if stored_path.name.lower() not in account_targets:
								stored_path.unlink(missing_ok=True)
								continue
							filtered.append(item)
							continue
						if suffix not in ext_set:
							stored_path.unlink(missing_ok=True)
							continue
						if category == DATABASES and not _is_database_included(stored_path.name):
							stored_path.unlink(missing_ok=True)
							continue
						filtered.append(item)

					if filtered:
						output_dir_cat = controller_android_dir / safe_segment(category)
						filtered = _flatten_evidence_outputs(filtered, output_dir_cat)
						_prune_empty_dirs(output_dir_cat)
						extracted.extend(filtered)
					else:
						state.anomaly_flags.append(f"p3_no_artefacts:{category}:controller_android")
					shutil.rmtree(staging_dir, ignore_errors=True)
				except Exception as exc:
					state.anomaly_flags.append(f"p3_extraction_failed:{category}:controller_android:{exc}")

	# Drone SD
	sd_sources = find_input_evidence_list_by_identification(state, IDENTIFICATION_DRONE_SD)
	if not sd_sources:
		state.anomaly_flags.append("p3_no_source:drone_sd")
	else:
		for idx, sd_source in enumerate(sd_sources):
			drone_sd_dir = phase_dir / f"drone_sd_{idx + 1}"
			clear_and_make(drone_sd_dir)
			print(f"Extracting from drone_sd {idx + 1}")
			sd_archive = Path(str(sd_source.stored_path))
			acquisition_method = _normalise_acquisition_method(sd_source.acquisition_method)
			if acquisition_method != "physical" and sd_archive.suffix.lower() == EXTENSION_ZIP[0]:
				state.anomaly_flags.append(f"p3_drone_sd_requires_physical_{idx + 1}")
			else:
				try:
					evidence_list = _extract_drone_sd_physical(state, sd_source, drone_sd_dir)
					extracted.extend(evidence_list)
					if not evidence_list:
						state.anomaly_flags.append(f"p3_no_artefacts:drone_sd_{idx + 1}")
				except Exception as exc:
					state.anomaly_flags.append(f"p3_extraction_failed:drone_sd_{idx + 1}:{exc}")

	# Drone flight storage
	flight_sources = find_input_evidence_list_by_identification(state, IDENTIFICATION_DRONE_FLIGHT_STORAGE)
	flight_source = flight_sources[0] if flight_sources else None
	if flight_source is None:
		state.anomaly_flags.append("p3_no_source:drone_flight_storage")
	else:
		drone_flight_dir = phase_dir / "drone_flight_storage"
		clear_and_make(drone_flight_dir)
		print("Extracting from drone_flight_storage")
		flight_archive = Path(str(flight_source.stored_path))
		if flight_archive.suffix.lower() == EXTENSION_ZIP[0]:
			member_names = _member_names(flight_archive)
			export_members = [name for name in member_names if _DJI_EXPORT_RE.match(Path(name).name)]
			if export_members:
				print("DJI Export found. DJI Export Assistant is being launched.")
				print("Please click GO in the application window.")
				print("Once finished, close the application and type 'yes' to continue: ")
				export_input_dir = drone_flight_dir / "_dji_export_input"
				export_input_dir.mkdir(parents=True, exist_ok=True)
				extracted_exports = extract_logical_files(
					flight_source,
					export_input_dir,
					export_members,
					artefact_category=DRONE_LOGS,
					missing_ok=True,
				)

				for evidence_item in extracted_exports:
					source_dat = Path(str(evidence_item.stored_path))
					result = subprocess.run(
						[str(EXTRACT_DJI_EXE), str(source_dat), str(drone_flight_dir)],
						capture_output=True,
						text=True,
						check=False,
					)
					state.log_tool_invocation(
						tool_name=Path(EXTRACT_DJI_EXE).name,
						version=_probe_extract_dji_version() or "unknown",
						args=[str(EXTRACT_DJI_EXE), str(source_dat), str(drone_flight_dir)],
						return_code=result.returncode,
						stdout=result.stdout or None,
						stderr=result.stderr or None,
						output_paths=[str(drone_flight_dir)],
					)

				confirm = input().strip().lower()
				if confirm != "yes":
					state.anomaly_flags.append(f"p3_dji_export_aborted:{flight_archive.name}")
				else:
					generated = list(drone_flight_dir.rglob("*.DAT"))
					if not generated:
						state.anomaly_flags.append(f"p3_dji_export_incompatible:{flight_archive.name}")
					else:
						for dat_path in generated:
							target_path = _ensure_unique_path(drone_flight_dir / dat_path.name)
							if dat_path != target_path:
								dat_path.replace(target_path)
							evidence_item = Evidence(
								source_path=to_windows_path(target_path.name),
								stored_path=target_path,
								parent=flight_source,
								acquisition_method="extract_dji",
								type=EVIDENCE_TYPE_EXTRACTED,
								artefact_category=DRONE_LOGS,
							)
							extracted.append(evidence_item)
			else:
				dat_members = [name for name in member_names if Path(name).suffix.lower() == ".dat"]
				if not dat_members:
					state.anomaly_flags.append(f"p3_dji_export_not_recognised:{flight_archive.name}")
				else:
						evidence_list = extract_logical_files(
							flight_source,
							drone_flight_dir,
							dat_members,
							artefact_category=DRONE_LOGS,
							missing_ok=True,
						)
						evidence_list = _flatten_evidence_outputs(evidence_list, drone_flight_dir)
						_prune_empty_dirs(drone_flight_dir)
						extracted.extend(evidence_list)
						if not evidence_list:
							state.anomaly_flags.append(f"p3_no_artefacts:{DRONE_LOGS}:drone_flight_storage")
		else:
			state.anomaly_flags.append(f"p3_dji_export_not_recognised:{flight_archive.name}")

	state.phase_outputs["p3_artefact_extraction"] = {
		"completed_at": utc_now_iso(),
		"extracted_artefacts": [item.to_dict() for item in extracted],
	}
	shutil.rmtree(staging_root, ignore_errors=True)
	if "p3_artefact_extraction" not in state.completed_phases:
		state.completed_phases.append("p3_artefact_extraction")

	return state
