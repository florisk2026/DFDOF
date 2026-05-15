"""Android parser for Phase 2 image parsing.

Extracts device metadata and backup info from Android acquisitions.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

from config import (
    ACQUISITION_PHYSICAL_READER,
    BACKUP_INFO_SCHEMA,
    DEVICE_AND_BACKUP_INFO,
    DJI_APP_DOMAINS,
    EXTENSION_ZIP,
)
from evidence import Evidence
from parsing.logical_reader import extract_logical_files, find_acquisition_pdf_member
from parsing import physical_reader
from state import State, get_tsk_tool_version
from parsing.path_utils import normalise_scalar, normalise_acquisition_method

try:
    from pypdf import PdfReader
except Exception:  # pragma: no cover - optional dependency fallback
    PdfReader = None

_DATE_RE = re.compile(
    r"\b\d{4}-\d{2}-\d{2}(?:[ T]\d{2}:\d{2}:\d{2}(?:Z|[+-]\d{2}:?\d{2})?)?\b"
)

TARGET_FILES = [
    "DeviceInfo.xml",
    "ApplicationInfo.xml",
    "ro.serialno",
    "net.hostname",
    "packages.list",
]


@dataclass
class AndroidParserResult:
    output_root: Path


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

    for _k, v in _walk_nested(value):
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


def _match_labeled_value(text: str, labels: tuple[str, ...]) -> str | None:
    """Search for labeled values in text using multiple patterns, returning the first match found."""
    patterns = []
    for label in labels:
        escaped = re.escape(label)
        patterns.extend(
            [
                rf"{escaped}\s*[:=]\s*([^\r\n<]+)",
                rf"<key>\s*{escaped}\s*</key>\s*<(?:string|date|integer|real)>\s*(.*?)\s*</(?:string|date|integer|real)>",
            ]
        )
    for pattern in patterns:
        match = re.search(pattern, text, flags=re.IGNORECASE | re.DOTALL)
        if match:
            return normalise_scalar(match.group(1))
    return None


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
            out[out_key] = normalise_scalar(_match_labeled_value(data, candidates))
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


def _extract_android_device_metadata(extracted_files: list[Evidence]) -> None:
    """Extract and populate metadata from Android device files into their Evidence objects."""
    for evidence in extracted_files:
        stored_path = cast(Path, evidence.stored_path)
        file_name = stored_path.name.lower()
        text = _read_text(stored_path)
        values: dict[str, Any] = {}

        if file_name == "deviceinfo.xml":
            values["device_name"] = _match_labeled_value(
                text, ("Device Name", "DeviceName", "Name")
            )
            values["model_name"] = _match_labeled_value(
                text, ("Model Name", "ModelName", "Model")
            )
            values["version"] = _match_labeled_value(
                text, ("Version", "Device Version", "Android Version")
            )
            values["firmware_version"] = _match_labeled_value(
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

        evidence.values = values


def _p1_image_metadata(state: State, image_name: str) -> dict[str, Any] | None:
    """Retrieve persisted Phase 1 image metadata (offset and fls entries)."""
    return (
        state.phase_outputs.get("p1_provenance", {})
        .get("image_metadata", {})
        .get(image_name)
    )


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
        cmd_path = (
            cmd if isinstance(cmd, str) else (cmd[0] if isinstance(cmd, list) else None)
        )
        if cmd_path:
            version_val = get_tsk_tool_version(str(cmd_path))

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


def _flatten_extracted_files(
    output_root: Path, extracted_files: list[Evidence]
) -> None:
    """Move extracted files into the output root to avoid nested folders."""
    for evidence_item in extracted_files:
        stored_path = Path(str(evidence_item.stored_path))
        if stored_path.parent == output_root:
            continue
        target_path = _ensure_unique_path(output_root / stored_path.name)
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
        or "logical" in acquisition_method
    )

    output_root.mkdir(parents=True, exist_ok=True)

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
            "acquisition_method": ACQUISITION_PHYSICAL_READER,
            "artefact_category": DEVICE_AND_BACKUP_INFO,
            "tool_log": lambda log_dict: _log_tsk_tool(state, log_dict),
        }
        if precomputed_entries is not None:
            extract_kwargs["precomputed_entries"] = precomputed_entries
        if offset_sectors is not None:
            extract_kwargs["offset_sectors"] = offset_sectors

        extracted_files = physical_reader.extract_tsk_image(
            stored_path, output_root, **extract_kwargs
        )

    # Only flatten when physical extraction returned nested paths; logical
    # extraction now writes flat basenames so no flattening is required.
    if not is_logical:
        _flatten_extracted_files(output_root, extracted_files)

    # Populate per-file metadata values
    _extract_android_device_metadata(extracted_files)

    # Track missing primary sources
    found_names = {Path(str(item.stored_path)).name.lower() for item in extracted_files}
    if "deviceinfo.xml" not in found_names:
        state.anomaly_flags.append(f"P2: Missing DeviceInfo.xml for {stored_path.name}")
    if "applicationinfo.xml" not in found_names:
        state.anomaly_flags.append(
            f"P2: Missing ApplicationInfo.xml for {stored_path.name}"
        )

    # Layered backup_info.json assembly
    backup_info: dict[str, Any] = BACKUP_INFO_SCHEMA.copy()

    # Layer 1: DeviceInfo.xml + ApplicationInfo.xml
    for evidence_item in extracted_files:
        values = evidence_item.values or {}
        name = Path(str(evidence_item.stored_path)).name.lower()
        if name == "deviceinfo.xml":
            _merge_if_empty(backup_info, "Device Name", values.get("device_name"))
            _merge_if_empty(backup_info, "Product Name", values.get("model_name"))
            _merge_if_empty(backup_info, "Product Version", values.get("version"))
            _merge_if_empty(
                backup_info, "Build Version", values.get("firmware_version")
            )
        elif name == "applicationinfo.xml":
            _merge_list_if_empty(
                backup_info,
                "Installed Applications",
                values.get("installed_dji_apps", []),
            )

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
            acquisition_evidence.values = acquisition_values
            _merge_if_empty(
                backup_info, "Product Name", acquisition_values.get("phone_model")
            )
            _merge_if_empty(
                backup_info,
                "Last Backup Date",
                acquisition_values.get("acquisition_date"),
            )

    # Store derived evidence entries for Phase 2
    parsed_evidence: list[dict[str, Any]] = []
    for item in extracted_files:
        parsed_evidence.append(item.to_dict())
    if acquisition_evidence is not None:
        parsed_evidence.append(acquisition_evidence.to_dict())
    state.phase_outputs.setdefault("p2_android_parser", {})[
        "parsed_evidence"
    ] = parsed_evidence

    backup_info_path = output_root / "backup_info.json"
    backup_info_path.write_text(json.dumps(backup_info, indent=2), encoding="utf-8")

    state.log_tool_invocation(
        tool_name="android_parser",
        args=[str(source_evidence.stored_path), str(output_root)],
        return_code=0,
        stdout=f"Parsed Android source to {output_root}",
        stderr=None,
        output_paths=[str(output_root)],
    )

    return AndroidParserResult(output_root=output_root)
