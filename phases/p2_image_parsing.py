"""DFDOF Phase 2: Image Parsing.

This phase:
 - create a phase 2 output directory,
 - parse and store controller iOS (iTunes backup) source,
 - parse and store controller Android source.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, cast

from config import (
    ACQUISITION_PARSER_ANDROID,
    ACQUISITION_PARSER_IOS,
    DEVICE_AND_BACKUP_INFO,
    DJI_APP_DOMAINS,
    EVIDENCE_TYPE_PARSED,
    IDENTIFICATION_CONTROLLER_ANDROID,
    IDENTIFICATION_CONTROLLER_IOS,
    clear_and_make,
    output_dir,
    utc_now_iso,
)
from evidence import Evidence
from observation import Content, Observation
from parsing.parser_android import parse_android_source
from parsing.parser_ios import parse_ios_backup
from parsing.utils_parse import normalise_scalar, to_windows_path
from phases.utils_phase import find_input_evidence_list_by_identification
from state import State


def _extract_installed_dji_apps(
    value: Any, allowed_domains: dict[str, str]
) -> list[str]:
    """Return installed DJI app domains from a backup_info Installed Applications list."""
    if isinstance(value, (list, tuple, set)):
        items = [str(item).strip().lower() for item in value if str(item).strip()]
    elif isinstance(value, str):
        items = [value.strip().lower()] if value.strip() else []
    else:
        items = []

    allowed = {domain.lower(): domain for domain in allowed_domains.keys()}
    selected: list[str] = []
    for app in items:
        if app in allowed:
            selected.append(allowed[app])
    return selected


def _normalise_backup_info_values(backup_info_path: Path) -> dict[str, Any]:
    """Normalise backup_info.json values for observation content."""

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
            values[key] = _extract_installed_dji_apps(raw_value, allowed_domains)
        else:
            values[key] = normalise_scalar(raw_value)

    return values


def _append_evidence(parsed_evidence: list[dict[str, Any]], evidence: Evidence) -> None:
    """Append an Evidence object to the parsed evidence list as a dictionary."""
    parsed_evidence.append(evidence.to_dict())


def _make_observation(
    evidence: Evidence, derived_observations: list[Any]
) -> Observation:
    return Observation(
        content=Content(
            evidence_sha256=str(evidence.sha256),
            evidence_category=evidence.artefact_category,
            acquisition_method=evidence.acquisition_method,
            observations=derived_observations,
        )
    )


def _process_ios_source(
    state: State,
    ios_source: Evidence,
    ios_output_dir: Path,
    parsed_evidence: list[dict[str, Any]],
    observations: list[dict[str, Any]],
) -> None:
    """Process the iOS source evidence by converting the backup and extracting metadata."""
    ios_stored_path = cast(Path, ios_source.stored_path)
    result = parse_ios_backup(ios_stored_path, output_root=ios_output_dir)
    info_plist_path = result.output_root / "_metadata" / "Info.plist"
    backup_info_path = result.output_root / "backup_info.json"
    info_plist_member = getattr(result, "metadata_members", {}).get(
        "info.plist", "Info.plist"
    )

    converted_root_evidence = Evidence(
        source_path=ios_source.source_path,
        stored_path=result.output_root,
        parent=ios_source,
        acquisition_method=ACQUISITION_PARSER_IOS,
        type=EVIDENCE_TYPE_PARSED,
        artefact_category=DEVICE_AND_BACKUP_INFO,
        skip_hash=True,
    )
    _append_evidence(parsed_evidence, converted_root_evidence)

    if info_plist_path.exists():
        info_plist_evidence = Evidence(
            source_path=to_windows_path(info_plist_member),
            stored_path=info_plist_path,
            parent=ios_source,
            acquisition_method=ACQUISITION_PARSER_IOS,
            type=EVIDENCE_TYPE_PARSED,
            artefact_category=DEVICE_AND_BACKUP_INFO,
        )
        _append_evidence(parsed_evidence, info_plist_evidence)

        if backup_info_path.exists():
            info_plist_metadata = _normalise_backup_info_values(backup_info_path)
            info_plist_observation = _make_observation(
                info_plist_evidence, [info_plist_metadata]
            )
            observations.append(info_plist_observation.to_dict())
    elif not backup_info_path.exists():
        state.anomaly_flags.append(
            f"P2: Missing backup_info.json for {ios_stored_path.name}"
        )

    state.log_tool_invocation(
        tool_name=ACQUISITION_PARSER_IOS,
        args=[str(ios_stored_path), str(ios_output_dir)],
        return_code=0,
        stdout="Parsed iOS source",
        stderr=None,
        output_paths=[str(result.output_root)],
    )


def run_phase_2(state: State) -> State:
    """Create the case output directory and convert controller evidence."""
    p1 = state.phase_outputs.get("p1_provenance")
    if not p1 or "identified_evidence" not in p1:
        raise ValueError(
            "Phase 2 requires Phase 1 outputs (p1_provenance.identified_evidence). Run Phase 1 first."
        )

    phase_dir = output_dir() / state.case_id / "p2_image_parsing"
    clear_and_make(phase_dir)

    parsed_evidence: list[dict[str, Any]] = []
    observations: list[dict[str, Any]] = []

    ios_sources = find_input_evidence_list_by_identification(
        state, IDENTIFICATION_CONTROLLER_IOS
    )
    ios_source = ios_sources[0] if ios_sources else None
    if ios_source is None:
        state.anomaly_flags.append("P2: No controller_ios evidence found")
    else:
        try:
            print("Parsing controller iOS")
            ios_output_dir = phase_dir / "controller_ios_parsed"
            clear_and_make(ios_output_dir)

            _process_ios_source(
                state,
                ios_source,
                ios_output_dir,
                parsed_evidence,
                observations,
            )
        except Exception as exc:
            state.anomaly_flags.append(
                f"P2: Failed to convert {cast(Path, ios_source.stored_path)}: {exc}"
            )

    android_sources = find_input_evidence_list_by_identification(
        state, IDENTIFICATION_CONTROLLER_ANDROID
    )
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
            if not backup_info_path.exists():
                state.anomaly_flags.append(
                    f"P2: Missing backup_info.json for {cast(Path, android_source.stored_path).name}"
                )

            android_parser_phase = state.phase_outputs.pop("p2_android_parser", {})
            parsed_evidence.extend(android_parser_phase.get("parsed_evidence", []))

            android_observation_dicts = android_parser_phase.get("observations", [])
            observations.extend(android_observation_dicts)
        except Exception as exc:
            state.anomaly_flags.append(
                f"P2: Failed to parse {cast(Path, android_source.stored_path)}: {exc}"
            )

    now = utc_now_iso()
    state.phase_outputs["p2_image_parsing"] = {
        "completed_at": now,
        "parsed_evidence": parsed_evidence,
        "observations": observations,
    }
    if "p2_image_parsing" not in state.completed_phases:
        state.completed_phases.append("p2_image_parsing")

    return state