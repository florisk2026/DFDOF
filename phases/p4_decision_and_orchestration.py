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
	ACQUISITION_ACCOUNT_DATA_PARSE,
	DATABASES,
	DRONE_LOGS,
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
from parsing.utils_parse import normalise_acquisition_method, parse_plist_strict, parse_xml_flat, to_windows_path
from phases.utils_phase import find_input_evidence_list_by_identification, write_json
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


def run_phase_4(state: State) -> State:
	phase_dir = output_dir() / state.case_id / "p4_decision_and_orchestration"
	clear_and_make(phase_dir)

	orchestrated: list[Evidence] = []
	observations: list[Observation] = []

	p3_output = state.phase_outputs.get("p3_artefact_extraction", {})
	extracted_artefacts = list(p3_output.get("extracted_artefacts", []))
	artefacts_by_parent = _group_artefacts_by_parent(extracted_artefacts)

	for identification in sorted(SOURCE_IDENTIFICATION_TYPES):
		sources = find_input_evidence_list_by_identification(state, identification)
		if not sources:
			state.raise_anomaly(4, identification, "source evidence not found")
			continue

		for idx, source in enumerate(sources, start=1):
			evidence_index = idx if identification == IDENTIFICATION_DRONE_SD and len(sources) > 1 else None
			parent_hash = source.sha256
			if not parent_hash:
				state.raise_anomaly(4, identification, "parent hash is missing", index=evidence_index)
				continue

			source_dir = phase_dir / identification
			artefacts = artefacts_by_parent.get(parent_hash, [])

			for artefact in artefacts:
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
					artefact_size = int(artefact.get("size") or 0)
					if artefact_size == 0:
						state.raise_anomaly(4, identification, f"account data file is empty: {stored_path.name}", category=ACCOUNT_DATA, index=evidence_index)
						continue

					try:
						if identification == IDENTIFICATION_CONTROLLER_IOS:
							parsed = parse_plist_strict(stored_path)
						elif identification == IDENTIFICATION_CONTROLLER_ANDROID:
							parsed = parse_xml_flat(stored_path)
						else:
							continue
					except Exception:
						state.raise_anomaly(4, identification, f"account data parse failed for {stored_path.name}", category=ACCOUNT_DATA, index=evidence_index)
						continue

					tool_output_dir.mkdir(parents=True, exist_ok=True)
					json_path = tool_output_dir / f"{stored_path.stem}.json"
					write_json(json_path, parsed)
					orchestrated.append(
						make_evidence(
							source_path=to_windows_path(str(stored_path)),
							stored_path=json_path,
							parent=parent_evidence,
							acquisition_method=ACQUISITION_ACCOUNT_DATA_PARSE,
							type="decoded",
							artefact_category=ACCOUNT_DATA,
						)
					)
					observations.append(
						make_observation(
							evidence_sha256=parent_evidence.sha256,
							evidence_category=ACCOUNT_DATA,
							acquisition_method=ACQUISITION_ACCOUNT_DATA_PARSE,
							observations=[parsed],
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

	state.phase_outputs["p4_decision_and_orchestration"] = {
		"completed_at": utc_now_iso(),
		"decision_and_orchestration_artefacts": [item.to_dict() for item in orchestrated],
		"derived_observations": [item.to_dict() for item in observations],
	}
	state.completed_phases.append("p4_decision_and_orchestration")
	return state
