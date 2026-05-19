"""DFDOF Phase 4: Decision and Orchestration.

This phase:
 - create a phase 4 output directory,
 - loop through all extracted artefacts,
 - decide and orchestrate tool/script per artefact
"""

from __future__ import annotations

import json
import plistlib
import base64
import datetime
from pathlib import Path
import xml.etree.ElementTree as ET
from typing import Any

import config
from config import (
	ACCOUNT_DATA,
	DATABASES,
	DRONE_LOGS,
	FLIGHT_LOGS,
	FLIGHT_RECORDS,
	IDENTIFICATION_CONTROLLER_ANDROID,
	IDENTIFICATION_CONTROLLER_IOS,
	IDENTIFICATION_DRONE_FLIGHT_STORAGE,
	IDENTIFICATION_DRONE_SD,
)
from evidence import Evidence, make_evidence
from observation import Observation, make_observation
from parsing.utils_parse import normalise_acquisition_method, to_windows_path
from phases.utils_phase import find_input_evidence_list_by_identification
from state import State
from tools.datcon import run_datcon
from tools.exiftool import run_exiftool
from tools.txtlogtocsv import run_txtlogtocsv


def _group_artefacts_by_parent(
	artefacts: list[dict[str, Any]],
) -> dict[str, list[dict[str, Any]]]:
	grouped: dict[str, list[dict[str, Any]]] = {}
	for artefact in artefacts:
		parent_sha256 = str(artefact.get("parent_sha256") or "")
		grouped.setdefault(parent_sha256, []).append(artefact)
	return grouped


def _record_anomaly(state: State, anomalies: list[str], message: str) -> None:
	state.anomaly_flags.append(message)
	anomalies.append(message)


def _write_json(path: Path, payload: Any) -> None:
	def _sanitize(obj: Any) -> Any:
		# Convert bytes to base64-preserved dict
		if isinstance(obj, (bytes, bytearray)):
			return {"__bytes_base64": base64.b64encode(bytes(obj)).decode("ascii")}
		if isinstance(obj, dict):
			return {str(k): _sanitize(v) for k, v in obj.items()}
		if isinstance(obj, list):
			return [_sanitize(v) for v in obj]
		if isinstance(obj, tuple):
			return [_sanitize(v) for v in obj]
		if isinstance(obj, datetime.datetime):
			return obj.isoformat()
		if isinstance(obj, (str, int, float, bool)) or obj is None:
			return obj
		# Fallback to string representation for other types
		try:
			return str(obj)
		except Exception:
			return None

	safe = _sanitize(payload)
	path.write_text(json.dumps(safe, indent=2), encoding="utf-8")


def _parse_plist(path: Path) -> dict[str, Any]:
	with path.open("rb") as file_handle:
		data = plistlib.load(file_handle)
	return data if isinstance(data, dict) else {"value": data}


def _parse_xml(path: Path) -> dict[str, Any]:
	tree = ET.parse(path)
	root = tree.getroot()
	parsed: dict[str, Any] = {}
	for element in root.iter():
		text = (element.text or "").strip()
		if not text:
			continue
		if element.tag in parsed:
			existing = parsed[element.tag]
			if isinstance(existing, list):
				existing.append(text)
			else:
				parsed[element.tag] = [existing, text]
		else:
			parsed[element.tag] = text
	return parsed


def _evidence_type_label(identification: str, index: int | None) -> str:
	if identification == IDENTIFICATION_CONTROLLER_IOS:
		return "controller ios"
	if identification == IDENTIFICATION_CONTROLLER_ANDROID:
		return "controller android"
	if identification == IDENTIFICATION_DRONE_FLIGHT_STORAGE:
		return "drone flight storage"
	if identification == IDENTIFICATION_DRONE_SD:
		if index is not None:
			return f"drone sd {index}"
		return "drone sd"
	return "drone sd"


def run_phase_4(state: State) -> State:
	phase_dir = config.output_dir() / state.case_id / "p4_decision_and_orchestration"
	config.clear_and_make(phase_dir)

	anomalies: list[str] = []
	orchestrated: list[Evidence] = []
	observations: list[Observation] = []

	p3_output = state.phase_outputs.get("p3_artefact_extraction", {})
	extracted_artefacts = list(p3_output.get("extracted_artefacts", []))
	artefacts_by_parent = _group_artefacts_by_parent(extracted_artefacts)

	source_configs = [
		(IDENTIFICATION_CONTROLLER_IOS, "controller_ios"),
		(IDENTIFICATION_CONTROLLER_ANDROID, "controller_android"),
		(IDENTIFICATION_DRONE_SD, "drone_sd"),
		(IDENTIFICATION_DRONE_FLIGHT_STORAGE, "drone_flight_storage"),
	]

	for identification, folder_name in source_configs:
		sources = find_input_evidence_list_by_identification(state, identification)
		if not sources:
			evidence_type = _evidence_type_label(identification, None)
			_record_anomaly(
				state,
				anomalies,
				f"p4 - {evidence_type}: source evidence not found",
			)
			continue

		for idx, source in enumerate(sources, start=1):
			evidence_index = idx if identification == IDENTIFICATION_DRONE_SD and len(sources) > 1 else None
			evidence_type = _evidence_type_label(identification, evidence_index)
			parent_hash = source.sha256
			if not parent_hash:
				_record_anomaly(
					state,
					anomalies,
					f"p4 - {evidence_type}: parent hash is missing",
				)
				continue

			source_dir = phase_dir / folder_name
			artefacts = artefacts_by_parent.get(parent_hash, [])

			for artefact in artefacts:
				stored_path = Path(str(artefact.get("stored_path") or ""))
				if not stored_path.exists():
					_record_anomaly(
						state,
						anomalies,
						f"p4 - {evidence_type}: input artefact missing: {stored_path.name}",
					)
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
					output_dir = source_dir / DRONE_LOGS
					orchestrated.extend(
						run_datcon(
							stored_path,
							output_dir,
							state,
							parent_evidence,
							evidence_type,
						)
					)
					continue

				if category_key == FLIGHT_RECORDS:
					if identification not in {
						IDENTIFICATION_CONTROLLER_IOS,
						IDENTIFICATION_CONTROLLER_ANDROID,
					}:
						continue
					output_dir = source_dir / FLIGHT_RECORDS
					csv_evidence = run_txtlogtocsv(
						stored_path,
						output_dir,
						state,
						parent_evidence,
						evidence_type,
					)
					if csv_evidence is not None:
						orchestrated.append(csv_evidence)
					continue

				if category_key == ACCOUNT_DATA:
					output_dir = source_dir / ACCOUNT_DATA
					artefact_size = int(artefact.get("size") or 0)
					if artefact_size == 0:
						_record_anomaly(
							state,
							anomalies,
							f"p4 - {evidence_type}: account data file is empty: {stored_path.name} (account data)",
						)
						continue

					try:
						if identification == IDENTIFICATION_CONTROLLER_IOS:
							parsed = _parse_plist(stored_path)
						elif identification == IDENTIFICATION_CONTROLLER_ANDROID:
							parsed = _parse_xml(stored_path)
						else:
							continue
					except Exception:
						_record_anomaly(
							state,
							anomalies,
							f"p4 - {evidence_type}: account data parse failed for {stored_path.name} (account data)",
						)
						continue

					output_dir.mkdir(parents=True, exist_ok=True)
					json_path = output_dir / f"{stored_path.stem}.json"
					_write_json(json_path, parsed)
					orchestrated.append(
						make_evidence(
							source_path=to_windows_path(str(stored_path)),
							stored_path=json_path,
							parent=parent_evidence,
							acquisition_method="account_data_parse",
							type="decoded",
							artefact_category=ACCOUNT_DATA,
						)
					)
					observations.append(
						make_observation(
							evidence_sha256=parent_evidence.sha256,
							evidence_category=ACCOUNT_DATA,
							acquisition_method="account_data_parse",
							observations=[parsed],
						)
					)
					continue

				if category_key in {config.IMAGES, config.VIDEOS}:
					if identification not in {
						IDENTIFICATION_CONTROLLER_IOS,
						IDENTIFICATION_CONTROLLER_ANDROID,
						IDENTIFICATION_DRONE_SD,
					}:
						continue
					output_dir = source_dir / category_key
					evidence, observation = run_exiftool(
						stored_path,
						output_dir,
						state,
						parent_evidence,
						category_key,
						evidence_type,
					)
					if evidence is not None:
						orchestrated.append(evidence)
					if observation is not None:
						observations.append(observation)
					continue

				if category_key in {DATABASES, FLIGHT_LOGS}:
					continue

	state.phase_outputs["p4_decision_and_orchestration"] = {
		"completed_at": config.utc_now_iso(),
		"decision_and_orchestration_artefacts": [item.to_dict() for item in orchestrated],
		"derived_observations": [item.to_dict() for item in observations],
	}
	state.completed_phases.append("p4_decision_and_orchestration")
	return state
