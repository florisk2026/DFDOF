"""DFDOF Android Controller Parser.

Extracts device metadata and backup info from Android controller acquisitions via:
- DeviceInfo.xml and ApplicationInfo.xml for device identity and installed apps,
- ro.serialno, net.hostname, packages.list for serial, hostname, and package-level app list,
- acquisition PDF (if present) for phone model and acquisition date.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

from config import (
    ACQUISITION_EXTRACT_PHYSICAL,
    ACQUISITION_LOGICAL,
    ACQUISITION_PARSER_ANDROID,
    BACKUP_INFO_SCHEMA,
    DEVICE_AND_BACKUP_INFO,
    DJI_APP_DOMAINS,
    EXTENSION_ZIP,
    IDENTIFICATION_CONTROLLER_ANDROID,
)
from evidence import Evidence
from observation import Observation, make_observation
from parsing.extract_logical import (
    ensure_unique_path,
    extract_logical_files,
    find_acquisition_pdf_member,
)
from parsing import extract_physical
from state import State
from parsing.utils_parse import (
    match_labeled_value,
    normalise_scalar,
    normalise_acquisition_method,
)

try:
    from pypdf import PdfReader
except Exception:  # pragma: no cover - optional dependency fallback.
    PdfReader = None

_DATE_RE = re.compile(
    r"\b\d{4}-\d{2}-\d{2}(?:[ T]\d{2}:\d{2}:\d{2}(?:Z|[+-]\d{2}:?\d{2})?)?\b"
)

TARGET_FILES = { 
    "DeviceInfo.xml",
    "ApplicationInfo.xml",
    "ro.serialno",
    "net.hostname",
    "packages.list",
}


@dataclass
class AndroidParserResult:
    output_root: Path
    parsed_evidence: list[Evidence]
    observations: list[Observation]


def _normalise_key(value: Any) -> str:
    """Normalise a key to a lowercase string with non-alphanumeric chars removed."""
    return re.sub(r"[^a-z0-9]+", "", str(value).lower())


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


def _lookup_nested_value(data: Any, candidate_keys: tuple[str, ...]) -> Any:
    """Recursively search for a value in nested dict/list structures matching any of the candidate keys."""
    wanted = {_normalise_key(key) for key in candidate_keys}
    for k, v in _walk_nested(data):
        if k is not None and _normalise_key(k) in wanted:
            return v
    return None


def _collect_text_fragments(value: Any) -> list[str]:
    """Collect text fragments from a nested structure, returning a list of non-empty stripped strings."""
    fragments: list[str] = []

    if isinstance(value, str):
        fragment = value.strip()
        if fragment:
            fragments.append(fragment)
        return fragments

    for v in _walk_nested(value):
        if isinstance(v, str):
            fragment = v.strip()
            if fragment:
                fragments.append(fragment)
    return fragments


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
        if any(
            re.search(pattern, fragment, flags=re.IGNORECASE) for fragment in fragments
        ):
            selected.append(domain)
    return selected


def _read_text(path: Path) -> str:
    """Read text content from a file, returning it as a string with UTF-8 encoding and replacement for errors."""
    return path.read_text(encoding="utf-8", errors="replace")


def _extract_pdf_text(path: Path) -> str:
    """Extract text from a PDF file, returning it as a single string. Falls back to raw text if PDF parsing fails."""
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


def _extract_metadata_dict(
    data: Any,
    mapping: dict[str, tuple[str, ...]],
    *,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Extract metadata values from data using a mapping of output keys to candidate labels."""
    out: dict[str, Any] = {}
    for out_key, candidates in mapping.items():
        if isinstance(data, str):
            out[out_key] = normalise_scalar(match_labeled_value(data, candidates))
        else:
            out[out_key] = normalise_scalar(_lookup_nested_value(data, candidates))
    if extra:
        out.update(extra)
    return out


def _extract_android_acquisition_metadata(pdf_path: Path) -> dict[str, Any]:
    """Extract relevant metadata from an Android acquisition PDF, returning a dictionary of normalized values."""
    text = _extract_pdf_text(pdf_path)
    mapping = {
        "phone_model": ("Phone model", "Device model", "Model"),
        "acquisition_date": ("Acquisition date", "Acquired on", "Date"),
    }
    result = _extract_metadata_dict(text, mapping)
    if result.get("acquisition_date") is None:
        match = _DATE_RE.search(text)
        result["acquisition_date"] = normalise_scalar(match.group(0)) if match else None
    return result


def _extract_android_device_metadata(
    extracted_files: list[Evidence],
) -> dict[str, dict[str, Any]]:
    """Extract metadata from Android device files, keyed by stored path."""
    metadata_by_path: dict[str, dict[str, Any]] = {}
    for evidence in extracted_files:
        stored_path = cast(Path, evidence.stored_path)
        file_name = stored_path.name.lower()
        text = _read_text(stored_path)
        values: dict[str, Any] = {}

        if file_name == "deviceinfo.xml":
            values["device_name"] = match_labeled_value(
                text, ("Device Name", "DeviceName", "Name")
            )
            values["model_name"] = match_labeled_value(
                text, ("Model Name", "ModelName", "Model")
            )
            values["version"] = match_labeled_value(
                text, ("Version", "Device Version", "Android Version")
            )
            values["firmware_version"] = match_labeled_value(
                text,
                (
                    "Firmware Version",
                    "FirmwareVersion",
                    "Build Version",
                    "BuildVersion",
                ),
            )
        elif file_name == "applicationinfo.xml":
            installed = _collect_allowed_dji_apps(text, DJI_APP_DOMAINS["android"])
            if installed:
                values["installed_dji_apps"] = installed
        elif file_name == "ro.serialno":
            values["device_serial"] = normalise_scalar(text)
        elif file_name == "net.hostname":
            values["device_hostname"] = normalise_scalar(text)

        if values:
            metadata_by_path[str(stored_path)] = values

    return metadata_by_path


def _p1_image_metadata(state: State, image_name: str) -> dict[str, Any] | None:
    """Retrieve persisted Phase 1 image metadata (offset and fls entries)."""
    return (
        state.phase_outputs.get("p1_provenance", {})
        .get("image_metadata", {})
        .get(image_name)
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


def _flatten_extracted_files(
    output_root: Path, extracted_files: list[Evidence]
) -> None:
    """Move extracted files into the output root to avoid nested folders."""
    for evidence_item in extracted_files:
        stored_path = Path(str(evidence_item.stored_path))
        if stored_path.parent == output_root:
            continue
        target_path = ensure_unique_path(output_root / stored_path.name)
        target_path.parent.mkdir(parents=True, exist_ok=True)
        stored_path.replace(target_path)
        evidence_item.stored_path = target_path

    # Clean up empty directories left behind after flattening.
    for directory in sorted(
        (item for item in output_root.rglob("*") if item.is_dir()),
        key=lambda path: len(path.parts),
        reverse=True,
    ):
        try:
            directory.rmdir()
        except OSError:
            pass


def parse_android_source(
    source_evidence: Evidence,
    output_root: Path,
    state: State,
) -> AndroidParserResult:
    """Convert an Android source into parsed files and backup_info.json."""
    stored_path = cast(Path, source_evidence.stored_path)
    acquisition_method = normalise_acquisition_method(
        source_evidence.acquisition_method
    )
    is_logical = (
        stored_path.suffix.lower() == EXTENSION_ZIP[0]
        or ACQUISITION_LOGICAL in acquisition_method
    )

    output_root.mkdir(parents=True, exist_ok=True)

    state.log_tool_invocation(
        tool_name=ACQUISITION_PARSER_ANDROID,
        args=[str(source_evidence.stored_path), str(output_root)],
        return_code=None,
        stdout=None,
        stderr=None,
        output_paths=[str(output_root)],
    )

    extracted_files: list[Evidence] = []
    if is_logical:
        extracted_files = extract_logical_files(
            source_evidence,
            output_root,
            TARGET_FILES,
            artefact_category=DEVICE_AND_BACKUP_INFO,
            missing_ok=True,
        )
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
            "acquisition_method": ACQUISITION_EXTRACT_PHYSICAL,
            "artefact_category": DEVICE_AND_BACKUP_INFO,
            "state": state,
        }
        if precomputed_entries is not None:
            extract_kwargs["precomputed_entries"] = precomputed_entries
        if offset_sectors is not None:
            extract_kwargs["offset_sectors"] = offset_sectors

        extracted_files = extract_physical.extract_tsk_image(
            stored_path, output_root, **extract_kwargs
        )

    # Only flatten when physical extraction returned nested paths; logical extraction writes flat basenames.
    if not is_logical:
        _flatten_extracted_files(output_root, extracted_files)

    observations: list[Observation] = []

    # Collect per-file metadata for later observations and backup-info synthesis.
    device_metadata = _extract_android_device_metadata(extracted_files)

    # Track missing primary sources.
    found_names = {Path(str(item.stored_path)).name.lower() for item in extracted_files}
    if "deviceinfo.xml" not in found_names:
        state.raise_anomaly(2, IDENTIFICATION_CONTROLLER_ANDROID, f"DeviceInfo.xml not found for {stored_path.name}", category=DEVICE_AND_BACKUP_INFO)
    if "applicationinfo.xml" not in found_names:
        state.raise_anomaly(2, IDENTIFICATION_CONTROLLER_ANDROID, f"ApplicationInfo.xml not found for {stored_path.name}", category=DEVICE_AND_BACKUP_INFO)

    # Layered backup_info.json assembly.
    backup_info: dict[str, Any] = BACKUP_INFO_SCHEMA.copy()

    # Layer 1: DeviceInfo.xml + ApplicationInfo.xml.
    for evidence_item in extracted_files:
        values = device_metadata.get(str(cast(Path, evidence_item.stored_path)), {})
        name = Path(str(evidence_item.stored_path)).name.lower()
        if name == "deviceinfo.xml":
            _merge_if_empty(backup_info, "Device Name", values.get("device_name"))
            _merge_if_empty(backup_info, "Product Name", values.get("model_name"))
            _merge_if_empty(backup_info, "Product Version", values.get("version"))
            _merge_if_empty(
                backup_info, "Build Version", values.get("firmware_version")
            )
            if values:
                observations.append(
                    make_observation(
                        evidence_sha256=evidence_item.sha256,
                        evidence_category=evidence_item.artefact_category,
                        acquisition_method=evidence_item.acquisition_method,
                        observations=[values],
                    )
                )
        elif name == "applicationinfo.xml":
            _merge_list_if_empty(
                backup_info,
                "Installed Applications",
                values.get("installed_dji_apps", []),
            )
            if values:
                observations.append(
                    make_observation(
                        evidence_sha256=evidence_item.sha256,
                        evidence_category=evidence_item.artefact_category,
                        acquisition_method=evidence_item.acquisition_method,
                        observations=[values],
                    )
                )

    # Layer 2: ro.serialno, net.hostname, packages.list
    for evidence_item in extracted_files:
        values = device_metadata.get(str(cast(Path, evidence_item.stored_path)), {})
        name = Path(str(evidence_item.stored_path)).name.lower()
        if name == "ro.serialno":
            _merge_if_empty(backup_info, "Serial Number", values.get("device_serial"))
            if values:
                observations.append(
                    make_observation(
                        evidence_sha256=evidence_item.sha256,
                        evidence_category=evidence_item.artefact_category,
                        acquisition_method=evidence_item.acquisition_method,
                        observations=[values],
                    )
                )
        elif name == "net.hostname":
            _merge_if_empty(backup_info, "Device Name", values.get("device_hostname"))
            if values:
                observations.append(
                    make_observation(
                        evidence_sha256=evidence_item.sha256,
                        evidence_category=evidence_item.artefact_category,
                        acquisition_method=evidence_item.acquisition_method,
                        observations=[values],
                    )
                )
        elif name == "packages.list":
            installed = _parse_packages_list(Path(str(evidence_item.stored_path)))
            _merge_list_if_empty(backup_info, "Installed Applications", installed)
            if installed:
                observations.append(
                    make_observation(
                        evidence_sha256=evidence_item.sha256,
                        evidence_category=evidence_item.artefact_category,
                        acquisition_method=evidence_item.acquisition_method,
                        observations=[{"installed_dji_apps": installed}],
                    )
                )

    # Layer 3: acquisition PDF.
    acquisition_member = None
    acquisition_evidence: Evidence | None = None
    if is_logical:
        acquisition_member = find_acquisition_pdf_member(stored_path)
        if acquisition_member is not None:
            extracted = extract_logical_files(
                source_evidence,
                output_root,
                [acquisition_member],
                artefact_category=DEVICE_AND_BACKUP_INFO,
                missing_ok=False,
            )
            acquisition_evidence = extracted[0]
            acquisition_values = _extract_android_acquisition_metadata(
                cast(Path, acquisition_evidence.stored_path)
            )
            _merge_if_empty(
                backup_info, "Product Name", acquisition_values.get("phone_model")
            )
            _merge_if_empty(
                backup_info,
                "Last Backup Date",
                acquisition_values.get("acquisition_date"),
            )
            if acquisition_values:
                observations.append(
                    make_observation(
                        evidence_sha256=acquisition_evidence.sha256,
                        evidence_category=acquisition_evidence.artefact_category,
                        acquisition_method=acquisition_evidence.acquisition_method,
                        observations=[acquisition_values],
                    )
                )

    backup_info_path = output_root / "backup_info.json"
    backup_info_path.write_text(json.dumps(backup_info, indent=2), encoding="utf-8")

    all_evidence: list[Evidence] = list(extracted_files)
    if acquisition_evidence is not None:
        all_evidence.append(acquisition_evidence)

    return AndroidParserResult(
        output_root=output_root,
        parsed_evidence=all_evidence,
        observations=observations,
    )
