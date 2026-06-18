"""DFDOF Phase 3: Artefact Extraction.

This phase:
 - creates a phase 3 output directory,
 - loops through all evidence sources,
 - extracts artefacts based on DJI app root discovery and explicit category paths.

Extraction is deterministic and auditable:
  1. Discover trusted DJI app roots (by bundle ID for iOS, by scope segment for Android).
  2. Construct explicit category directory paths (root / configured token).
  3. Recurse only within those directories.
  4. Filter by extension.
  5. Reject empty files.
  6. Wrap as Evidence.

No heuristic substring matching. No fallback extraction. If roots cannot be found,
an anomaly is raised and extraction stops for that source.
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
    ANDROID_ARTEFACT_PATHS,
    ARTEFACT_EXTENSIONS,
    ARTEFACT_EXTENSIONS_DRONE_SD,
    ACQUISITION_EXTRACT_LOGICAL,
    ACQUISITION_EXTRACT_PHYSICAL,
    CONTROLLER_ARTEFACT_CATEGORIES,
    DEVICE_AND_BACKUP_INFO,
    DJI_APP_DOMAINS,
    DRONE_LOGS,
    EVIDENCE_TYPE_EXTRACTED,
    EXTENSION_ZIP,
    IDENTIFICATION_CONTROLLER_ANDROID,
    IDENTIFICATION_CONTROLLER_IOS,
    IDENTIFICATION_DRONE_FLIGHT_STORAGE,
    IDENTIFICATION_DRONE_SD,
    IOS_ARTEFACT_PATHS,
    IMAGES,
    TSK_ICAT,
    VIDEOS,
    output_dir,
    clear_and_make,
    utc_now_iso,
    _write_no_output,
    _has_real_output,
)
from evidence import Evidence, make_evidence
from parsing.extract_logical import ensure_unique_path, extract_logical_files
from parsing.utils_parse import (
    parse_json_file,
    safe_segment,
    to_windows_path,
    normalise_acquisition_method,
)
from parsing.extract_physical import extract_tsk_image, run_command
from phases.utils_phase import drone_sd_label, find_input_evidence_list_by_identification
from state import State

_PHASE_NAME = Path(__file__).stem

_ARTEFACT_EXTENSIONS_LOWER: dict[str, frozenset[str]] = {
    category: frozenset(ext.lower() for ext in exts)
    for category, exts in ARTEFACT_EXTENSIONS.items()
}
_ARTEFACT_EXTENSIONS_DRONE_SD_LOWER: frozenset[str] = frozenset(
    ext.lower() for exts in ARTEFACT_EXTENSIONS_DRONE_SD.values() for ext in exts
)
_DRONE_SD_EXT_TO_CATEGORY: dict[str, str] = {
    ext.lower(): category
    for category, exts in ARTEFACT_EXTENSIONS_DRONE_SD.items()
    for ext in exts
}

_IOS_DOMAIN_PREFIXES: tuple[str, ...] = ("AppDomain-", "AppDomainGroup-")


def _android_installed_apps(state: State) -> list[str]:
    """Read installed DJI bundle IDs from P2 backup_info.json."""
    backup_info_path = (
        output_dir() / state.case_id / "p2_image_parsing"
        / "controller_android_parsed" / "backup_info.json"
    )
    if not backup_info_path.is_file():
        return []
    data = parse_json_file(backup_info_path)
    apps = data.get("Installed Applications", [])
    return [str(a) for a in apps if str(a).strip()] if isinstance(apps, list) else []


def _android_discover_scope_roots(
    member_names: Iterable[str],
    bundle_ids: list[str],
) -> list[str]:
    """Find archive path prefixes ending with an installed DJI bundle ID segment."""
    bundle_ids_lower = {b.lower() for b in bundle_ids}
    roots: set[str] = set()
    for name in member_names:
        normalised = name.replace("\\", "/").lower()
        parts = normalised.split("/")
        for i, part in enumerate(parts):
            if part in bundle_ids_lower:
                roots.add("/".join(parts[: i + 1]) + "/")
    return sorted(roots)


def _scope_filter_entries(
    entries: list[tuple[str, int, str]],
    scope_roots: list[str],
    path_tokens: set[str],
    ext_set: frozenset[str],
) -> list[tuple[str, int, str]]:
    """Filter image fls entries to those inside a DJI app scope root for a category.

    Constructs category roots as scope_root+token (same as logical branch) and
    keeps only entries whose path (compared case-insensitively) starts with one
    of those roots and whose extension matches ext_set.
    """
    category_roots = [scope + token for scope in scope_roots for token in path_tokens]
    result: list[tuple[str, int, str]] = []
    seen: set[str] = set()
    for entry in entries:
        path = entry[2]
        path_lower = path.lower()
        if not any(path_lower.startswith(cat_root) for cat_root in category_roots):
            continue
        if Path(path).suffix.lower() not in ext_set:
            continue
        if path not in seen:
            seen.add(path)
            result.append(entry)
    return result


def _ios_discover_app_roots(parsed_root: Path) -> list[Path]:
    """Find DJI app directories in the parsed iOS backup domain tree.

    Scans parsed_root/domains/ for subdirectories whose name, after stripping
    a known domain prefix (AppDomain-, AppDomainGroup-), matches a bundle ID
    from DJI_APP_DOMAINS["ios"].
    """
    bundle_ids_lower = {b.lower() for b in DJI_APP_DOMAINS["ios"].keys()}
    domains_dir = parsed_root / "domains"
    if not domains_dir.is_dir():
        return []
    roots: list[Path] = []
    for subdir in domains_dir.iterdir():
        if not subdir.is_dir():
            continue
        name = subdir.name
        stripped = name
        for prefix in _IOS_DOMAIN_PREFIXES:
            if name.lower().startswith(prefix.lower()):
                stripped = name[len(prefix):]
                break
        if stripped.lower() in bundle_ids_lower:
            roots.append(subdir)
    return sorted(roots)


def _ios_collect_category_files(app_roots: list[Path], category: str) -> list[Path]:
    """Collect files from explicit category directories under DJI iOS app roots.

    For each app root and each token in IOS_ARTEFACT_PATHS[category], constructs
    the exact path app_root / token and recurses inside it. No directory-name
    scanning; paths are constructed directly from configuration.
    """
    tokens = IOS_ARTEFACT_PATHS.get(category, set())
    ext_set = _ARTEFACT_EXTENSIONS_LOWER.get(category, frozenset())
    seen: set[Path] = set()
    matched: list[Path] = []
    for app_root in app_roots:
        for token in tokens:
            category_dir = app_root / token.rstrip("/\\")
            if not category_dir.is_dir():
                continue
            for file_path in category_dir.rglob("*"):
                if file_path.is_file() and file_path.suffix.lower() in ext_set:
                    if file_path not in seen:
                        seen.add(file_path)
                        matched.append(file_path)
    return matched


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


def _collect_account_members(
    member_names: Iterable[str],
    os_key: str,
    scope_prefixes: list[str] | None = None,
) -> list[str]:
    """Collect account data members from a ZIP archive by filename.

    When scope_prefixes are provided, only considers members whose normalised
    path starts with one of the DJI app scope roots.
    """
    targets = _account_targets(os_key)
    result = []
    for name in member_names:
        if scope_prefixes and not any(
            name.replace("\\", "/").lower().startswith(p) for p in scope_prefixes
        ):
            continue
        if Path(name).name.lower() in targets:
            result.append(name)
    return result


def _collect_account_files(app_roots: list[Path], os_key: str) -> list[Path]:
    """Collect account data files from DJI app roots by filename."""
    targets = _account_targets(os_key)
    seen: set[Path] = set()
    result: list[Path] = []
    for app_root in app_roots:
        for file_path in app_root.rglob("*"):
            if file_path.is_file() and file_path.name.lower() in targets:
                if file_path not in seen:
                    seen.add(file_path)
                    result.append(file_path)
    return result


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

    extensions = _ARTEFACT_EXTENSIONS_DRONE_SD_LOWER
    extracted: list[Evidence] = []

    for kind, inode, rel_path in entries:
        if not str(kind).startswith("r"):
            continue
        suffix = Path(rel_path).suffix.lower()
        if suffix not in extensions:
            continue
        category = _DRONE_SD_EXT_TO_CATEGORY.get(suffix)
        if category is None:
            continue
        out_dir = output_root / safe_segment(category)
        out_dir.mkdir(parents=True, exist_ok=True)
        output_path = ensure_unique_path(out_dir / Path(rel_path).name)
        icat_tmp = output_path.parent / (output_path.name + ".tmp")
        with icat_tmp.open("wb") as output_handle:
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
            icat_tmp.unlink(missing_ok=True)
            raise RuntimeError(
                f"icat failed for inode {inode} in {sd_archive}: "
                f"{result.stderr or result.stdout}"
            )
        icat_tmp.replace(output_path)
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


def _copy_parsed_files(
    parsed_root: Path,
    files: list[Path],
    out_dir: Path,
    parent: Evidence,
    category: str,
    acquisition_method: str,
) -> list[Evidence]:
    """Copy parsed files into the phase output directory and wrap as Evidence."""
    extracted: list[Evidence] = []
    for file_path in files:
        output_path = ensure_unique_path(out_dir / file_path.name)
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


def _member_names(zip_path: Path) -> tuple[str, ...]:
    """Return archive member names excluding directories."""
    with zipfile.ZipFile(zip_path) as archive:
        return tuple(name for name in archive.namelist() if not name.endswith("/"))


def _filter_empty(
    evidence_list: list[Evidence],
    state: State,
    identification: str,
    category: str | None = None,
    index: int | None = None,
) -> list[Evidence]:
    """Move 0-byte evidence items to _rejected/ and flag an anomaly for each."""
    kept: list[Evidence] = []
    rejected_dir = output_dir() / state.case_id / "_rejected"
    for item in evidence_list:
        if item.size == 0:
            file_path = Path(str(item.stored_path))
            rejected_dir.mkdir(parents=True, exist_ok=True)
            rejected_path = ensure_unique_path(rejected_dir / file_path.name)
            try:
                file_path.replace(rejected_path)
            except OSError:
                file_path.unlink(missing_ok=True)
            state.raise_anomaly(
                3,
                identification,
                f"empty file moved to _rejected: {file_path.name}",
                category=category or item.artefact_category,
                index=index,
            )
        else:
            kept.append(item)
    return kept


def _find_ios_parsed_root(state: State, ios_source: Evidence | None) -> Path | None:
    """Locate the P2-parsed iOS directory from state.phase_outputs."""
    if ios_source is None:
        return None
    for record in state.phase_outputs.get("p2_image_parsing", {}).get("parsed_evidence", []):
        if not isinstance(record, dict):
            continue
        if record.get("artefact_category") != DEVICE_AND_BACKUP_INFO:
            continue
        if str(record.get("source_path")) != str(ios_source.source_path):
            continue
        stored_path = Path(str(record.get("stored_path")))
        if stored_path.exists() and stored_path.is_dir():
            return stored_path
    return None


def _extract_android_sources(
    state: State, android_source: Evidence, phase_dir: Path
) -> list[Evidence]:
    """Extract all artefact categories for the Android controller source."""
    extracted: list[Evidence] = []
    controller_android_dir = phase_dir / "controller_android"
    clear_and_make(controller_android_dir)
    print("  Extracting from controller_android")
    android_archive = Path(str(android_source.stored_path))
    acquisition_method = normalise_acquisition_method(android_source.acquisition_method)
    is_logical = (
        acquisition_method == ACQUISITION_LOGICAL
        or android_archive.suffix.lower() == EXTENSION_ZIP[0]
    )
    categories = CONTROLLER_ARTEFACT_CATEGORIES

    if is_logical:
        member_names = _member_names(android_archive)
        installed_apps = _android_installed_apps(state)
        if not installed_apps:
            scope_roots = _android_discover_scope_roots(
                member_names, list(DJI_APP_DOMAINS["android"].keys())
            )
            if not scope_roots:
                state.raise_anomaly(
                    3, IDENTIFICATION_CONTROLLER_ANDROID,
                    "installed DJI apps not found in P2 output and no known DJI app "
                    "directories found in archive, extraction aborted",
                )
                _write_no_output(controller_android_dir)
                return extracted
            state.raise_anomaly(
                3, IDENTIFICATION_CONTROLLER_ANDROID,
                "installed DJI apps not found in P2 output; falling back to config-defined "
                "bundle IDs for extraction",
            )
        else:
            scope_roots = _android_discover_scope_roots(member_names, installed_apps)
            if not scope_roots:
                state.raise_anomaly(
                    3, IDENTIFICATION_CONTROLLER_ANDROID,
                    "no DJI app directories found in archive for installed apps, extraction aborted",
                )
                _write_no_output(controller_android_dir)
                return extracted

        for category in categories:
            try:
                if category == ACCOUNT_DATA:
                    members = _collect_account_members(
                        member_names, "android", scope_prefixes=scope_roots
                    )
                else:
                    path_tokens = {
                        p.replace("\\", "/").lower()
                        for p in ANDROID_ARTEFACT_PATHS.get(category, set())
                    }
                    ext_set = _ARTEFACT_EXTENSIONS_LOWER.get(category, frozenset())
                    category_roots = [
                        scope + token
                        for scope in scope_roots
                        for token in path_tokens
                    ]
                    seen: set[str] = set()
                    members = []
                    for name in member_names:
                        normalised = name.replace("\\", "/").lower()
                        if not any(normalised.startswith(cat_root) for cat_root in category_roots):
                            continue
                        if Path(name).suffix.lower() not in ext_set:
                            continue
                        if normalised not in seen:
                            seen.add(normalised)
                            members.append(name)

                output_dir_cat = controller_android_dir / safe_segment(category)
                if members:
                    evidence_list = _filter_empty(
                        extract_logical_files(
                            android_source,
                            output_dir_cat,
                            members,
                            artefact_category=category,
                            missing_ok=True,
                        ),
                        state,
                        IDENTIFICATION_CONTROLLER_ANDROID,
                        category,
                    )
                    if not _has_real_output(output_dir_cat):
                        _write_no_output(output_dir_cat)
                    extracted.extend(evidence_list)
                else:
                    state.raise_anomaly(
                        3, IDENTIFICATION_CONTROLLER_ANDROID, "no artefacts found", category=category
                    )
                    _write_no_output(output_dir_cat)
            except Exception as exc:
                state.raise_anomaly(
                    3, IDENTIFICATION_CONTROLLER_ANDROID, f"extraction failed: {exc}", category=category
                )

    else:
        precomputed_entries = _get_cached_entries(state, android_archive)
        offset_sectors = _get_cached_offset(state, android_archive)
        installed_apps = _android_installed_apps(state)
        if not precomputed_entries:
            state.raise_anomaly(
                3, IDENTIFICATION_CONTROLLER_ANDROID,
                "no cached image entries from P1, extraction aborted",
            )
            _write_no_output(controller_android_dir)
            return extracted

        entry_paths = [e[2] for e in precomputed_entries]
        if not installed_apps:
            scope_roots = _android_discover_scope_roots(
                entry_paths, list(DJI_APP_DOMAINS["android"].keys())
            )
            if not scope_roots:
                state.raise_anomaly(
                    3, IDENTIFICATION_CONTROLLER_ANDROID,
                    "installed DJI apps not found in P2 output and no known DJI app "
                    "directories found in image, extraction aborted",
                )
                _write_no_output(controller_android_dir)
                return extracted
            state.raise_anomaly(
                3, IDENTIFICATION_CONTROLLER_ANDROID,
                "installed DJI apps not found in P2 output; falling back to config-defined "
                "bundle IDs for extraction",
            )
        else:
            scope_roots = _android_discover_scope_roots(entry_paths, installed_apps)
            if not scope_roots:
                state.raise_anomaly(
                    3, IDENTIFICATION_CONTROLLER_ANDROID,
                    "no DJI app directories found in image for installed apps, extraction aborted",
                )
                _write_no_output(controller_android_dir)
                return extracted

        for category in categories:
            try:
                if category == ACCOUNT_DATA:
                    account_paths = set(_collect_account_members(
                        entry_paths, "android", scope_prefixes=scope_roots
                    ))
                    scoped_entries = [e for e in precomputed_entries if e[2] in account_paths]
                else:
                    path_tokens = {
                        p.replace("\\", "/").lower()
                        for p in ANDROID_ARTEFACT_PATHS.get(category, set())
                    }
                    ext_set = _ARTEFACT_EXTENSIONS_LOWER.get(category, frozenset())
                    scoped_entries = _scope_filter_entries(
                        precomputed_entries, scope_roots, path_tokens, ext_set
                    )

                output_dir_cat = controller_android_dir / safe_segment(category)
                if not scoped_entries:
                    state.raise_anomaly(
                        3, IDENTIFICATION_CONTROLLER_ANDROID, "no artefacts found", category=category
                    )
                    _write_no_output(output_dir_cat)
                    continue

                output_dir_cat.mkdir(parents=True, exist_ok=True)
                evidence_list = _filter_empty(
                    extract_tsk_image(
                        android_archive,
                        output_dir_cat,
                        include_paths=None,
                        parent=android_source,
                        artefact_category=category,
                        precomputed_entries=scoped_entries,
                        offset_sectors=offset_sectors,
                        state=state,
                    ),
                    state,
                    IDENTIFICATION_CONTROLLER_ANDROID,
                    category,
                )
                if evidence_list:
                    extracted.extend(evidence_list)
                else:
                    state.raise_anomaly(
                        3, IDENTIFICATION_CONTROLLER_ANDROID, "no artefacts found", category=category
                    )
                    _write_no_output(output_dir_cat)
            except Exception as exc:
                state.raise_anomaly(
                    3, IDENTIFICATION_CONTROLLER_ANDROID, f"extraction failed: {exc}", category=category
                )

    return extracted


def _extract_ios_sources(
    state: State, ios_source: Evidence, ios_parsed_root: Path, phase_dir: Path
) -> list[Evidence]:
    """Extract all artefact categories for the iOS controller source."""
    extracted: list[Evidence] = []
    ios_acquisition = normalise_acquisition_method(ios_source.acquisition_method)
    ios_acquisition_method = (
        ACQUISITION_EXTRACT_PHYSICAL if ios_acquisition == ACQUISITION_PHYSICAL
        else ACQUISITION_EXTRACT_LOGICAL
    )
    controller_ios_dir = phase_dir / "controller_ios"
    clear_and_make(controller_ios_dir)
    print("  Extracting from controller_ios")

    app_roots = _ios_discover_app_roots(ios_parsed_root)
    if not app_roots:
        state.raise_anomaly(
            3, IDENTIFICATION_CONTROLLER_IOS,
            "no DJI app directories found in parsed backup, extraction aborted",
        )
        _write_no_output(controller_ios_dir)
        return extracted

    for category in CONTROLLER_ARTEFACT_CATEGORIES:
        try:
            if category == ACCOUNT_DATA:
                matched_files = _collect_account_files(app_roots, "ios")
            else:
                matched_files = _ios_collect_category_files(app_roots, category)

            output_dir_cat = controller_ios_dir / safe_segment(category)
            if matched_files:
                evidence_list = _filter_empty(
                    _copy_parsed_files(
                        ios_parsed_root,
                        matched_files,
                        output_dir_cat,
                        ios_source,
                        category,
                        ios_acquisition_method,
                    ),
                    state,
                    IDENTIFICATION_CONTROLLER_IOS,
                    category,
                )
                if not _has_real_output(output_dir_cat):
                    _write_no_output(output_dir_cat)
                extracted.extend(evidence_list)
            else:
                state.raise_anomaly(
                    3, IDENTIFICATION_CONTROLLER_IOS, "no artefacts found", category=category
                )
                _write_no_output(output_dir_cat)
        except Exception as exc:
            state.raise_anomaly(
                3, IDENTIFICATION_CONTROLLER_IOS, f"extraction failed: {exc}", category=category
            )
    return extracted


def _extract_drone_sd_sources(
    state: State, sd_sources: list[Evidence], phase_dir: Path
) -> list[Evidence]:
    """Extract drone SD artefacts from all SD sources."""
    extracted: list[Evidence] = []
    for idx, sd_source in enumerate(sd_sources):
        drone_sd_dir = phase_dir / drone_sd_label(idx + 1)
        clear_and_make(drone_sd_dir)
        print(f"  Extracting from drone_sd {idx + 1}")
        sd_archive = Path(str(sd_source.stored_path))
        acquisition_method = normalise_acquisition_method(sd_source.acquisition_method)
        if (
            acquisition_method != ACQUISITION_PHYSICAL
            and sd_archive.suffix.lower() == EXTENSION_ZIP[0]
        ):
            state.raise_anomaly(3, IDENTIFICATION_DRONE_SD, "physical acquisition required", index=idx + 1)
        else:
            try:
                evidence_list = _filter_empty(
                    _extract_drone_sd_physical(state, sd_source, drone_sd_dir),
                    state,
                    IDENTIFICATION_DRONE_SD,
                    index=idx + 1,
                )
                extracted.extend(evidence_list)
                if not evidence_list:
                    state.raise_anomaly(3, IDENTIFICATION_DRONE_SD, "no artefacts found", index=idx + 1)
                if not _has_real_output(drone_sd_dir):
                    _write_no_output(drone_sd_dir)
            except Exception as exc:
                state.raise_anomaly(3, IDENTIFICATION_DRONE_SD, f"extraction failed: {exc}", index=idx + 1)
                if not _has_real_output(drone_sd_dir):
                    _write_no_output(drone_sd_dir)
    return extracted


def _extract_flight_storage_sources(
    state: State, flight_source: Evidence, phase_dir: Path
) -> list[Evidence]:
    """Extract DAT files from drone flight storage."""
    extracted: list[Evidence] = []
    drone_flight_dir = phase_dir / "drone_flight_storage"
    clear_and_make(drone_flight_dir)
    print("  Extracting from drone_flight_storage")
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
            drone_logs_dir = drone_flight_dir / safe_segment(DRONE_LOGS)
            evidence_list = _filter_empty(
                extract_logical_files(
                    flight_source,
                    drone_logs_dir,
                    dat_members,
                    artefact_category=DRONE_LOGS,
                    missing_ok=True,
                ),
                state,
                IDENTIFICATION_DRONE_FLIGHT_STORAGE,
                DRONE_LOGS,
            )
            extracted.extend(evidence_list)
            if not evidence_list:
                state.raise_anomaly(
                    3, IDENTIFICATION_DRONE_FLIGHT_STORAGE,
                    "no artefacts extracted",
                    category=DRONE_LOGS,
                )
    else:  # Physical image (.001, .E01)
        entries = _get_cached_entries(state, flight_archive)
        if not entries:
            state.raise_anomaly(
                3, IDENTIFICATION_DRONE_FLIGHT_STORAGE,
                "no cached image entries from P1, extraction aborted",
                category=DRONE_LOGS,
            )
        else:
            offset_sectors = _get_cached_offset(state, flight_archive)
            dat_entries = [
                e for e in entries
                if e[0].startswith("r") and Path(e[2]).suffix.lower() == ".dat"
            ]
            if not dat_entries:
                state.raise_anomaly(
                    3, IDENTIFICATION_DRONE_FLIGHT_STORAGE,
                    f"no DAT files found in {flight_archive.name}",
                    category=DRONE_LOGS,
                )
            else:
                drone_logs_dir = drone_flight_dir / safe_segment(DRONE_LOGS)
                evidence_list = _filter_empty(
                    extract_tsk_image(
                        flight_archive,
                        drone_logs_dir,
                        include_paths=None,
                        parent=flight_source,
                        artefact_category=DRONE_LOGS,
                        precomputed_entries=dat_entries,
                        offset_sectors=offset_sectors,
                        state=state,
                    ),
                    state,
                    IDENTIFICATION_DRONE_FLIGHT_STORAGE,
                    DRONE_LOGS,
                )
                extracted.extend(evidence_list)
                if not evidence_list:
                    state.raise_anomaly(
                        3, IDENTIFICATION_DRONE_FLIGHT_STORAGE,
                        "no artefacts extracted",
                        category=DRONE_LOGS,
                    )
    if not _has_real_output(drone_flight_dir):
        _write_no_output(drone_flight_dir)
    return extracted


def run_phase_3(state: State) -> State:
    """Extract and categorise artefacts for all identified evidence sources."""
    if "p1_provenance" not in state.phase_outputs:
        raise ValueError("Phase 3 requires Phase 1 outputs. Run Phase 1 first.")

    phase_dir = output_dir() / state.case_id / _PHASE_NAME
    clear_and_make(phase_dir)
    extracted: list[Evidence] = []

    android_sources = find_input_evidence_list_by_identification(state, IDENTIFICATION_CONTROLLER_ANDROID)
    android_source = android_sources[0] if android_sources else None
    if android_source is None:
        state.raise_anomaly(3, IDENTIFICATION_CONTROLLER_ANDROID, "source evidence not found")
    else:
        extracted.extend(_extract_android_sources(state, android_source, phase_dir))

    ios_sources = find_input_evidence_list_by_identification(state, IDENTIFICATION_CONTROLLER_IOS)
    ios_source = ios_sources[0] if ios_sources else None
    ios_parsed_root = _find_ios_parsed_root(state, ios_source)
    if ios_source is None:
        state.raise_anomaly(3, IDENTIFICATION_CONTROLLER_IOS, "source evidence not found")
    elif ios_parsed_root is None:
        state.raise_anomaly(3, IDENTIFICATION_CONTROLLER_IOS, "parsed iOS root was not found")
    else:
        extracted.extend(_extract_ios_sources(state, ios_source, ios_parsed_root, phase_dir))

    sd_sources = find_input_evidence_list_by_identification(state, IDENTIFICATION_DRONE_SD)
    if not sd_sources:
        state.raise_anomaly(3, IDENTIFICATION_DRONE_SD, "source evidence not found")
    else:
        extracted.extend(_extract_drone_sd_sources(state, sd_sources, phase_dir))

    flight_sources = find_input_evidence_list_by_identification(state, IDENTIFICATION_DRONE_FLIGHT_STORAGE)
    flight_source = flight_sources[0] if flight_sources else None
    if flight_source is None:
        state.raise_anomaly(3, IDENTIFICATION_DRONE_FLIGHT_STORAGE, "source evidence not found")
    else:
        extracted.extend(_extract_flight_storage_sources(state, flight_source, phase_dir))

    extracted.sort(key=lambda e: (e.artefact_category or "", str(e.stored_path or "")))
    state.phase_outputs[_PHASE_NAME] = {
        "completed_at": utc_now_iso(),
        "extracted_artefacts": [item.to_dict() for item in extracted],
    }

    if _PHASE_NAME not in state.completed_phases:
        state.completed_phases.append(_PHASE_NAME)

    return state
