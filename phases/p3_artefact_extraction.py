"""DFDOF Phase 3: Artefact Extraction.

This phase:
 - create a phase 3 output directory,
 - loop through all evidence sources,
 - extract artefacts based on category filters and acquisition method.
"""

from __future__ import annotations

import shutil
import zipfile
from pathlib import Path
from typing import Any, Iterable

from config import (
    ACCOUNT_DATA,
    ACQUISITION_LOGICAL,
    ACQUISITION_PHYSICAL,
    ARTEFACT_DATABASES_INCLUDES,
    ARTEFACT_EXTENSIONS,
    ARTEFACT_EXTENSIONS_DRONE_SD,
    ARTEFACT_PATHS,
    ACQUISITION_EXTRACT_LOGICAL,
    ACQUISITION_EXTRACT_PHYSICAL,
    CONTROLLER_ARTEFACT_CATEGORIES,
    DATABASES,
    DEVICE_AND_BACKUP_INFO,
    DJI_APP_DOMAINS,
    DRONE_LOGS,
    EVIDENCE_TYPE_EXTRACTED,
    EXTENSION_ZIP,
    IDENTIFICATION_CONTROLLER_ANDROID,
    IDENTIFICATION_CONTROLLER_IOS,
    IDENTIFICATION_DRONE_FLIGHT_STORAGE,
    IDENTIFICATION_DRONE_SD,
    IMAGES,
    TSK_ICAT,
    VIDEOS,
	output_dir,
	clear_and_make,
	utc_now_iso,
)
from evidence import Evidence, make_evidence
from parsing.extract_logical import ensure_unique_path, extract_logical_files
from parsing.utils_parse import (
    normalise_path,
    safe_segment,
    to_windows_path,
    normalise_acquisition_method,
)
from parsing.extract_physical import extract_tsk_image, run_command
from phases.utils_phase import drone_sd_label, find_input_evidence_list_by_identification
from state import State

_PHASE_NAME = Path(__file__).stem


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


def _get_cached_entries(
    state: State, image_path: Path
) -> list[tuple[str, int, str]] | None:
    """Retrieve cached fls entries for an image from Phase 1 metadata."""
    meta = _lookup_cached_image_metadata(state, image_path)
    if not meta:
        return None
    entries = []
    for entry in meta.get("entries", []):
        try:
            entries.append(
                (str(entry["kind"]), int(entry["inode"]), str(entry["path"]))
            )
        except Exception:
            continue
    return entries or None


def _lookup_cached_image_metadata(
    state: State, image_path: Path
) -> dict[str, Any] | None:
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
        output_path = ensure_unique_path(output_dir / Path(rel_path).name)
        with output_path.open("wb") as output_handle:
            result = run_command(
                [
                    str(TSK_ICAT),
                    "-o",
                    str(offset_sectors or 0),
                    str(sd_archive),
                    str(inode),
                ],
                capture_output=False,
                stdout=output_handle,
            )
        if result.returncode != 0:
            raise RuntimeError(f"icat failed for inode {inode} in {sd_archive}")
        state.log_command_result(
            tool_name="icat",
            result=result,
            output_paths=[str(output_path)],
        )
        extracted.append(
            make_evidence(
                source_path=to_windows_path(rel_path),
                stored_path=output_path,
                parent=sd_source,
                acquisition_method=ACQUISITION_EXTRACT_PHYSICAL,
                type=EVIDENCE_TYPE_EXTRACTED,
                artefact_category=category,
            )
        )

    extracted.sort(key=lambda e: e.artefact_category or "")
    return extracted


def _collect_account_members(member_names: Iterable[str], os_key: str) -> list[str]:
    """Collect account data members from a ZIP archive by filename."""
    targets = _account_targets(os_key)
    return [name for name in member_names if Path(name).name.lower() in targets]


def _collect_account_files(parsed_root: Path, os_key: str) -> list[Path]:
    """Collect account data files from a parsed folder by filename."""
    targets = _account_targets(os_key)
    return [
        path
        for path in parsed_root.rglob("*")
        if path.is_file() and path.name.lower() in targets
    ]


def _collect_parsed_files(parsed_root: Path, category: str) -> list[Path]:
    """Collect parsed iOS files that match the artefact category filters."""
    if category == ACCOUNT_DATA:
        return []
    paths = {
        normalise_path(path, to_lower=True)
        for path in ARTEFACT_PATHS.get(category, set())
    }
    extensions = {ext.lower() for ext in ARTEFACT_EXTENSIONS.get(category, set())}

    matched: list[Path] = []
    for file_path in parsed_root.rglob("*"):
        if not file_path.is_file():
            continue
        suffix = file_path.suffix.lower()
        if suffix not in extensions:
            continue
        rel_path = normalise_path(
            str(file_path.relative_to(parsed_root)), to_lower=True
        )
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
        output_path = ensure_unique_path(output_dir / file_path.name)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(file_path, output_path)
        rel_source = to_windows_path(str(file_path.relative_to(parsed_root)))
        extracted.append(
            make_evidence(
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


def run_phase_3(state: State) -> State:
    """Extract and categorise artefacts for all identified evidence sources."""
    if "p1_provenance" not in state.phase_outputs:
        raise ValueError("Phase 3 requires Phase 1 outputs. Run Phase 1 first.")

    phase_dir = output_dir() / state.case_id / _PHASE_NAME
    clear_and_make(phase_dir)

    extracted: list[Evidence] = []

    # Controller Android.
    android_sources = find_input_evidence_list_by_identification(
        state, IDENTIFICATION_CONTROLLER_ANDROID
    )
    android_source = android_sources[0] if android_sources else None
    if android_source is None:
        state.raise_anomaly(3, IDENTIFICATION_CONTROLLER_ANDROID, "source evidence not found")
    else:
        controller_android_dir = phase_dir / "controller_android"
        clear_and_make(controller_android_dir)
        print("Extracting from controller_android")
        android_archive = Path(str(android_source.stored_path))
        acquisition_method = normalise_acquisition_method(
            android_source.acquisition_method
        )
        is_logical = (
            acquisition_method == ACQUISITION_LOGICAL
            or android_archive.suffix.lower() == EXTENSION_ZIP[0]
        )
        categories = CONTROLLER_ARTEFACT_CATEGORIES
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
                        extracted.extend(evidence_list)
                    else:
                        state.raise_anomaly(3, IDENTIFICATION_CONTROLLER_ANDROID, "no artefacts found", category=category)
                except Exception as exc:
                    state.raise_anomaly(3, IDENTIFICATION_CONTROLLER_ANDROID, f"extraction failed: {exc}", category=category)
        else:
            precomputed_entries = _get_cached_entries(state, android_archive)
            offset_sectors = _get_cached_offset(state, android_archive)
            for category in categories:
                try:
                    output_dir_cat = controller_android_dir / safe_segment(category)
                    output_dir_cat.mkdir(parents=True, exist_ok=True)
                    if category == ACCOUNT_DATA:
                        include_paths = list(_account_targets("android"))
                    else:
                        include_paths = sorted(ARTEFACT_PATHS.get(category, set()))

                    evidence_list = extract_tsk_image(
                        android_archive,
                        output_dir_cat,
                        include_paths=include_paths,
                        parent=android_source,
                        artefact_category=category,
                        precomputed_entries=precomputed_entries,
                        offset_sectors=offset_sectors,
                        state=state,
                    )

                    filtered: list[Evidence] = []
                    ext_set = {
                        ext.lower() for ext in ARTEFACT_EXTENSIONS.get(category, set())
                    }
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
                        if category == DATABASES and not _is_database_included(
                            stored_path.name
                        ):
                            stored_path.unlink(missing_ok=True)
                            continue
                        filtered.append(item)

                    if filtered:
                        extracted.extend(filtered)
                    else:
                        state.raise_anomaly(3, IDENTIFICATION_CONTROLLER_ANDROID, "no artefacts found", category=category)
                except Exception as exc:
                    state.raise_anomaly(3, IDENTIFICATION_CONTROLLER_ANDROID, f"extraction failed: {exc}", category=category)

    # Controller iOS.
    ios_sources = find_input_evidence_list_by_identification(
        state, IDENTIFICATION_CONTROLLER_IOS
    )
    ios_source = ios_sources[0] if ios_sources else None
    ios_parsed_root: Path | None = None
    if ios_source is not None:
        p2_records = state.phase_outputs.get("p2_image_parsing", {}).get(
            "parsed_evidence", []
        )
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
        state.raise_anomaly(3, IDENTIFICATION_CONTROLLER_IOS, "source evidence not found")
    elif ios_parsed_root is None:
        state.raise_anomaly(3, IDENTIFICATION_CONTROLLER_IOS, "parsed iOS root was not found")
    else:
        ios_acquisition = normalise_acquisition_method(ios_source.acquisition_method)
        if ios_acquisition == ACQUISITION_PHYSICAL:
            ios_acquisition_method = ACQUISITION_EXTRACT_PHYSICAL
        else:
            ios_acquisition_method = ACQUISITION_EXTRACT_LOGICAL
        controller_ios_dir = phase_dir / "controller_ios"
        clear_and_make(controller_ios_dir)
        print("Extracting from controller_ios")
        categories = CONTROLLER_ARTEFACT_CATEGORIES
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
                    state.raise_anomaly(3, IDENTIFICATION_CONTROLLER_IOS, "no artefacts found", category=category)
            except Exception as exc:
                state.raise_anomaly(3, IDENTIFICATION_CONTROLLER_IOS, f"extraction failed: {exc}", category=category)

    # Drone SD.
    sd_sources = find_input_evidence_list_by_identification(
        state, IDENTIFICATION_DRONE_SD
    )
    if not sd_sources:
        state.raise_anomaly(3, IDENTIFICATION_DRONE_SD, "source evidence not found")
    else:
        for idx, sd_source in enumerate(sd_sources):
            drone_sd_dir = phase_dir / drone_sd_label(idx + 1)
            clear_and_make(drone_sd_dir)
            print(f"Extracting from drone_sd {idx + 1}")
            sd_archive = Path(str(sd_source.stored_path))
            acquisition_method = normalise_acquisition_method(
                sd_source.acquisition_method
            )
            if (
                acquisition_method != ACQUISITION_PHYSICAL
                and sd_archive.suffix.lower() == EXTENSION_ZIP[0]
            ):
                state.raise_anomaly(3, IDENTIFICATION_DRONE_SD, "physical acquisition required", index=idx + 1)
            else:
                try:
                    evidence_list = _extract_drone_sd_physical(
                        state, sd_source, drone_sd_dir
                    )
                    extracted.extend(evidence_list)
                    if not evidence_list:
                        state.raise_anomaly(3, IDENTIFICATION_DRONE_SD, "no artefacts found", index=idx + 1)
                except Exception as exc:
                    state.raise_anomaly(3, IDENTIFICATION_DRONE_SD, f"extraction failed: {exc}", index=idx + 1)

    # Drone flight storage.
    flight_sources = find_input_evidence_list_by_identification(
        state, IDENTIFICATION_DRONE_FLIGHT_STORAGE
    )
    flight_source = flight_sources[0] if flight_sources else None
    if flight_source is None:
        state.raise_anomaly(3, IDENTIFICATION_DRONE_FLIGHT_STORAGE, "source evidence not found")
    else:
        drone_flight_dir = phase_dir / "drone_flight_storage"
        clear_and_make(drone_flight_dir)
        print("Extracting from drone_flight_storage")
        flight_archive = Path(str(flight_source.stored_path))
        if flight_archive.suffix.lower() == EXTENSION_ZIP[0]:
            member_names = _member_names(flight_archive)
            dat_members = [
                name for name in member_names if Path(name).suffix.lower() == ".dat"
            ]
            if not dat_members:
                state.raise_anomaly(
                    3, IDENTIFICATION_DRONE_FLIGHT_STORAGE,
                    f"no DAT files found in {flight_archive.name}",
                    category=DRONE_LOGS,
                )
            else:
                evidence_list = extract_logical_files(
                    flight_source,
                    drone_flight_dir,
                    dat_members,
                    artefact_category=DRONE_LOGS,
                    missing_ok=True,
                )
                extracted.extend(evidence_list)
                if not evidence_list:
                    state.raise_anomaly(
                        3, IDENTIFICATION_DRONE_FLIGHT_STORAGE,
                        "no artefacts extracted",
                        category=DRONE_LOGS,
                    )
        else:
            state.raise_anomaly(
                3, IDENTIFICATION_DRONE_FLIGHT_STORAGE,
                f"unsupported archive format for {flight_archive.name}",
                category=DRONE_LOGS,
            )

    state.phase_outputs[_PHASE_NAME] = {
        "completed_at": utc_now_iso(),
        "extracted_artefacts": [item.to_dict() for item in extracted],
    }

    if _PHASE_NAME not in state.completed_phases:
        state.completed_phases.append(_PHASE_NAME)

    return state
