"""DFDOF Phase 4: Decision and Orchestration.

This phase:
 - create a phase 4 output directory,
 - loop through all extracted artefacts,
 - decide and orchestrate tool/script per artefact
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from config import (
	ACCOUNT_DATA,
	ACQUISITION_DATCON,
	ACQUISITION_EXIFTOOL,
	ACQUISITION_EXTRACT_DJI,
	ACQUISITION_SELECT_ACCOUNT_DATA,
	ACQUISITION_TXTLOGTOCSV,
	DATABASES,
	DRONE_LOGS,
	EVIDENCE_TYPE_PARSED,
	FLIGHT_LOGS,
	FLIGHT_RECORDS,
	IDENTIFICATION_CONTROLLER_ANDROID,
	IDENTIFICATION_CONTROLLER_IOS,
	IDENTIFICATION_DRONE_FLIGHT_STORAGE,
	IDENTIFICATION_DRONE_SD,
	IMAGES,
	SOURCE_IDENTIFICATION_TYPES,
	VIDEOS,
	output_dir,
	clear_and_make,
	utc_now_iso,
)
from evidence import Evidence, make_evidence
from observation import Observation, make_observation
from parsing.utils_parse import (
	decode_base64,
	decode_cllocation_bplist,
	extract_fields,
	ieee754_long_to_degrees,
	normalise_acquisition_method,
	parse_android_xml_map,
	parse_java_properties,
	parse_json_file,
	parse_plist_strict,
	to_windows_path,
)
from phases.utils_phase import drone_sd_label, find_input_evidence_list_by_identification, json_safe, write_json
from state import State

from tools.datcon import run_datcon
from tools.extractdji import run_extractdji
from tools.exiftool import run_exiftool
from tools.txtlogtocsv import run_txtlogtocsv

_PHASE_NAME = Path(__file__).stem

_IOS_DJI_FIELDS: dict[str, tuple] = {
	"account_email":       (["DJIACCOUNTMANAGER_LASTUSEREMAIL"], None),
	"aircraft_sn":         (["AIRCRAFT_FLIGHT_LOG_DEVICE_SN", "cached_sn_key"], None),
	"cached_product_name": (["cached_product_name_key"], None),
	"app_version":         (["appVersion_pack", "DJIAppLaunchTimeReportVersionKey"], None),
	"last_launch":         (["LastLaunchDate"], None),
	"last_flight_date":    (["Last_Flight_Record_Date_Key"], None),
	"last_country_code":   (["DJILastCountryCodeName", "supervisor_country_code_cache_key"], None),
	"device_platform":     (["machinePlatForm"], None),
}

_ANDROID_DJI_GO4_FIELDS: dict[str, tuple] = {
	"account_email":    (["key_account_email"], decode_base64),
	"account_uid":      (["key_account_uid"], decode_base64),
	"account_nickname": (["key_account_nickname"], decode_base64),
	"account_token":    (["key_account_token"], decode_base64),
	"aircraft_sn":      (["device_sn", "key_last_flyforbid_flyc_sn"], None),
	"firmware_version": (["cur_firmware_ver"], None),
	"last_country_code":(["key_country_code_local"], None),
	"last_latitude":    (["fmd_latitude"], None),
	"last_longitude":   (["fmd_longitude"], None),
}

_ANDROID_DJI_PILOT_FIELDS: dict[str, tuple] = {
	"account_uid":      (["key_account_uid"], decode_base64),
	"account_token":    (["key_account_token"], decode_base64),
	"aircraft_sn":      (["key_last_flyforbid_flyc_sn", "djiPopupKeyLastSn"], None),
	"firmware_version": (["cur_firmware_ver", "djiPopupKeyFirmware"], None),
	"device_uuid":      (["key_uuid_for_account_center"], None),
	"last_latitude":    (["KEY_CC_LAST_FLYC_LAT"], ieee754_long_to_degrees),
	"last_longitude":   (["KEY_CC_LAST_FLYC_LNG"], ieee754_long_to_degrees),
}


_INFO_KEYS_LOWER = {
	"capturedate", "positionrelativealt", "positiongpslat",
	"positiongpsalt", "positiongpslng",
}


def _decode_find_aircraft_location(raw: dict, raw_safe: dict) -> dict:
	"""Decode FIND_AIRCRAFT_LAST_LOCATION into coordinate fields.

	Reads from raw (original plist bytes), mutates raw_safe["FIND_AIRCRAFT_LAST_LOCATION"]
	in-place (removes LAST_LOCATION blob, inlines decoded fields), and returns the decoded
	fields so the Observation matches the JSON file exactly.
	"""
	block = raw.get("FIND_AIRCRAFT_LAST_LOCATION")
	if not isinstance(block, dict):
		return {}
	out = {}
	heading = block.get("LAST_HEADING")
	if heading is not None:
		try:
			out["find_aircraft_last_heading"] = str(round(float(heading), 8))
		except Exception:
			pass
	loc = block.get("LAST_LOCATION")
	if isinstance(loc, bytes):
		coords = decode_cllocation_bplist(loc)
		if coords:
			out.update(coords)
	safe_block = raw_safe.get("FIND_AIRCRAFT_LAST_LOCATION")
	if isinstance(safe_block, dict) and out:
		safe_block.pop("LAST_LOCATION", None)
		safe_block.update(out)
	return out


def _parse_account_file(file_path: Path) -> tuple[dict, dict]:
	"""Parse a DJI account data file. Return (raw_safe_dict, filtered_forensic_fields)."""
	suffix = file_path.suffix.lower()
	try:
		if suffix == ".plist":
			raw = parse_plist_strict(file_path)
			field_map = _IOS_DJI_FIELDS
		elif suffix == ".xml":
			raw = parse_android_xml_map(file_path)
			field_map = (
				_ANDROID_DJI_PILOT_FIELDS
				if "pilot" in file_path.stem.lower()
				else _ANDROID_DJI_GO4_FIELDS
			)
		elif suffix == ".json":
			raw = parse_json_file(file_path)
			field_map = _IOS_DJI_FIELDS
		else:
			return {}, {}
	except Exception:
		return {}, {}

	raw_safe = json_safe(raw)
	filtered = extract_fields(raw_safe, field_map)
	if suffix in {".plist", ".json"}:
		filtered.update(_decode_find_aircraft_location(raw, raw_safe))
	return raw_safe, filtered


def _group_artefacts_by_parent(
	artefacts: list[dict[str, Any]],
) -> dict[str, list[dict[str, Any]]]:
	grouped: dict[str, list[dict[str, Any]]] = {}
	for artefact in artefacts:
		parent_sha256 = str(artefact.get("parent_sha256") or "")
		grouped.setdefault(parent_sha256, []).append(artefact)
	return grouped


def run_phase_4(state: State) -> State:
	phase_dir = output_dir() / state.case_id / _PHASE_NAME
	clear_and_make(phase_dir)

	orchestrated: list[Evidence] = []
	observations: list[Observation] = []

	p3_output = state.phase_outputs.get("p3_artefact_extraction", {})
	extracted_artefacts = list(p3_output.get("extracted_artefacts", []))
	artefacts_by_parent = _group_artefacts_by_parent(extracted_artefacts)

	_announced_tools: set[str] = set()

	for identification in SOURCE_IDENTIFICATION_TYPES:
		sources = find_input_evidence_list_by_identification(state, identification)
		if not sources:
			state.raise_anomaly(4, identification, "source evidence not found")
			continue

		for idx, source in enumerate(sources, start=1):
			evidence_index = idx if identification == IDENTIFICATION_DRONE_SD else None
			parent_hash = source.sha256
			if not parent_hash:
				state.raise_anomaly(4, identification, "parent hash is missing", index=evidence_index)
				continue

			if identification == IDENTIFICATION_DRONE_SD:
				source_dir = phase_dir / drone_sd_label(idx)
			else:
				source_dir = phase_dir / identification
			artefacts = artefacts_by_parent.get(parent_hash, [])

			for artefact in sorted(artefacts, key=lambda a: str(a.get("artefact_category") or "")):
				stored_path = Path(str(artefact.get("stored_path") or ""))
				if not stored_path.exists():
					state.raise_anomaly(4, identification, f"input artefact missing: {stored_path.name}", index=evidence_index)
					continue

				category = str(artefact.get("artefact_category") or "").strip()
				category_key = category.lower()
				_ = normalise_acquisition_method(artefact.get("acquisition_method"))

				parent_evidence = Evidence.from_dict(artefact)

				if category_key == DRONE_LOGS:
					if identification not in {
						IDENTIFICATION_CONTROLLER_IOS,
						IDENTIFICATION_CONTROLLER_ANDROID,
						IDENTIFICATION_DRONE_FLIGHT_STORAGE,
					}:
						continue
					tool_output_dir = source_dir / DRONE_LOGS
					source_name = Path(str(artefact.get("source_path") or stored_path.name)).name
					if ACQUISITION_DATCON not in _announced_tools:
						print("  Orchestrating DatCon")
						_announced_tools.add(ACQUISITION_DATCON)
					if "ASSISTANT_EXPORT" in source_name.upper():
						if ACQUISITION_EXTRACT_DJI not in _announced_tools:
							print("  Orchestrating ExtractDJI")
							_announced_tools.add(ACQUISITION_EXTRACT_DJI)
						converted = run_extractdji(
							stored_path,
							tool_output_dir,
							state,
							parent_evidence,
							identification,
							evidence_index,
						)
						for converted_evidence in converted:
							orchestrated.append(converted_evidence)
							orchestrated.extend(
								run_datcon(
									Path(str(converted_evidence.stored_path)),
									tool_output_dir,
									state,
									converted_evidence,
									identification,
									evidence_index,
								)
							)
					else:
						orchestrated.extend(
							run_datcon(
								stored_path,
								tool_output_dir,
								state,
								parent_evidence,
								identification,
								evidence_index,
							)
						)
					continue

				if category_key == FLIGHT_RECORDS:
					if identification not in {
						IDENTIFICATION_CONTROLLER_IOS,
						IDENTIFICATION_CONTROLLER_ANDROID,
					}:
						continue
					tool_output_dir = source_dir / FLIGHT_RECORDS
					if ACQUISITION_TXTLOGTOCSV not in _announced_tools:
						print("  Orchestrating TxtLogToCsv")
						_announced_tools.add(ACQUISITION_TXTLOGTOCSV)
					csv_evidence = run_txtlogtocsv(
						stored_path,
						tool_output_dir,
						state,
						parent_evidence,
						identification,
						evidence_index,
					)
					if csv_evidence is not None:
						orchestrated.append(csv_evidence)
					continue

				if category_key == ACCOUNT_DATA:
					tool_output_dir = source_dir / ACCOUNT_DATA
					raw, filtered = _parse_account_file(stored_path)
					if not raw:
						state.raise_anomaly(4, identification, f"account data parse failed for {stored_path.name}", category=ACCOUNT_DATA, index=evidence_index)
						continue

					tool_output_dir.mkdir(parents=True, exist_ok=True)
					json_path = tool_output_dir / f"{stored_path.stem}.json"
					write_json(json_path, raw)
					orchestrated.append(
						make_evidence(
							source_path=to_windows_path(str(stored_path)),
							stored_path=json_path,
							parent=parent_evidence,
							acquisition_method=ACQUISITION_SELECT_ACCOUNT_DATA,
							type=EVIDENCE_TYPE_PARSED,
							artefact_category=ACCOUNT_DATA,
						)
					)
					observations.append(
						make_observation(
							stored_path=str(parent_evidence.stored_path),
							evidence_sha256=parent_evidence.sha256,
							evidence_category=ACCOUNT_DATA,
							acquisition_method=ACQUISITION_SELECT_ACCOUNT_DATA,
							observations=[filtered],
						)
					)
					continue

				if category_key in {IMAGES, VIDEOS}:
					if identification not in {
						IDENTIFICATION_CONTROLLER_IOS,
						IDENTIFICATION_CONTROLLER_ANDROID,
						IDENTIFICATION_DRONE_SD,
					}:
						continue
					tool_output_dir = source_dir / category_key

					if stored_path.suffix.lower() == ".info":
						raw = parse_java_properties(stored_path)
						if not raw:
							state.raise_anomaly(4, identification, f"video info parse failed for {stored_path.name}", category=VIDEOS, index=evidence_index)
							continue
						tool_output_dir.mkdir(parents=True, exist_ok=True)
						json_path = tool_output_dir / f"{stored_path.stem}.json"
						write_json(json_path, raw)
						orchestrated.append(
							make_evidence(
								source_path=to_windows_path(str(stored_path)),
								stored_path=json_path,
								parent=parent_evidence,
								acquisition_method=ACQUISITION_SELECT_ACCOUNT_DATA,
								type=EVIDENCE_TYPE_PARSED,
								artefact_category=VIDEOS,
							)
						)
						observations.append(
							make_observation(
								stored_path=str(parent_evidence.stored_path),
								evidence_sha256=parent_evidence.sha256,
								evidence_category=VIDEOS,
								acquisition_method=ACQUISITION_SELECT_ACCOUNT_DATA,
								observations=[{k: v for k, v in raw.items() if k.lower() in _INFO_KEYS_LOWER}],
							)
						)
						continue

					if ACQUISITION_EXIFTOOL not in _announced_tools:
						print("  Orchestrating ExifTool")
						_announced_tools.add(ACQUISITION_EXIFTOOL)
					evidence, observation = run_exiftool(
						stored_path,
						tool_output_dir,
						state,
						parent_evidence,
						category_key,
						identification,
						evidence_index,
					)
					if evidence is not None:
						orchestrated.append(evidence)
					if observation is not None:
						observations.append(observation)
					continue

				if category_key in {DATABASES, FLIGHT_LOGS}:
					continue

	state.phase_outputs[_PHASE_NAME] = {
		"completed_at": utc_now_iso(),
		"decision_and_orchestration_artefacts": [item.to_dict() for item in orchestrated],
		"derived_observations": [item.to_dict() for item in observations],
	}
	state.completed_phases.append(_PHASE_NAME)
	return state
