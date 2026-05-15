"""DFDOF Phase 1: Provenance and Integrity.

This phase:
- builds evidence objects for supported inputs (see SUPPORTED_IMAGE_EXTENSIONS in config),
- classifies each source using rules,
- records operator confirmation in state.
"""

from __future__ import annotations

import re
import zipfile
from pathlib import Path
from typing import TypedDict, cast

from config import (
    SOURCE_IDENTIFICATION_TYPES,
    SUPPORTED_IMAGE_EXTENSIONS,
    TSK_FLS,
    TSK_MMLS,
    IDENTIFICATION_CONTROLLER_IOS,
    IDENTIFICATION_CONTROLLER_ANDROID,
    IDENTIFICATION_DRONE_SD,
    IDENTIFICATION_DRONE_FLIGHT_STORAGE,
    IDENTIFICATION_UNCLASSIFIED,
    ACQUISITION_LOGICAL,
    ACQUISITION_PHYSICAL,
    EVIDENCE_TYPE_INPUT,
    EXTENSION_ZIP,
    ARTEFACT_EXTENSIONS_DRONE_SD,
    CONTROLLER_IOS_INCLUDES,
    CONTROLLER_ANDROID_INCLUDES,
    DRONE_FLIGHT_STORAGE_INCLUDES,
    DRONE_SD_INCLUDES,
    DRONE_LOGS,
    ARTEFACT_EXTENSIONS,
    utc_now_iso,
)
from evidence import Evidence
from parsing.utils_parse import normalise_path
from parsing.extract_physical import list_fls_entries, parse_mmls_offset, run_command
from state import State

_SUPPORTED_INPUT_EXTS = {ext.lower() for ext in SUPPORTED_IMAGE_EXTENSIONS}


class SourceRecord(TypedDict):
    source_path: str
    identified: bool
    identified_as: str
    operator_confirmed: bool
    identified_by_operator_as: str | None


def _record_source_path(record: dict[str, object]) -> str:
    """Return the preserved source path."""
    return str(record.get("source_path") or "")


def _supported_input(path: Path) -> bool:
    return path.suffix.lower() in _SUPPORTED_INPUT_EXTS


def _is_ios_logical_backup(listing: list[str]) -> bool:
    """Detect iTunes logical backup: Manifest.db + Info.plist + 50+ hex/hex folders."""
    norm = [normalise_path(p) for p in listing]
    return (
        all(any(inc in p for p in norm) for inc in CONTROLLER_IOS_INCLUDES)
        and sum(1 for p in norm if re.search(r"[0-9a-fA-F]{2}/[0-9a-fA-F]{2}/", p)) > 50
    )


def _is_controller_android(listing: list[str]) -> bool:
    """Detect Android controller: (data/data/dji OR sdcard/dji)."""
    norm = [normalise_path(p) for p in listing]
    has_dji = any(s in p.lower() for p in norm for s in CONTROLLER_ANDROID_INCLUDES)
    return has_dji


def _is_drone_sd(listing: list[str]) -> bool:
    """Detect drone SD card: DCIM or MISC with media files (.MP4 and .THM only)."""
    norm = [normalise_path(p) for p in listing]
    extensions = {ext.lower() for ext in ARTEFACT_EXTENSIONS_DRONE_SD}
    return any(folder in p for folder in DRONE_SD_INCLUDES for p in norm) and any(
        p.lower().endswith(tuple(extensions))
        and any(folder in p for folder in DRONE_SD_INCLUDES)
        for p in norm
    )


def _is_drone_flight_storage(listing: list[str]) -> bool:
    """Detect drone flight storage: FLY*.DAT or DJI_ASSISTANT_EXPORT_FILE*.DAT."""
    norm = [normalise_path(p) for p in listing]
    dat_ext = tuple(ARTEFACT_EXTENSIONS[DRONE_LOGS])
    return any(
        any(inc in p.upper() for inc in DRONE_FLIGHT_STORAGE_INCLUDES)
        and p.upper().endswith(dat_ext)
        for p in norm
    )


def identify_source(listing: list[str]) -> str:
    """Deterministic structural identification."""
    if _is_ios_logical_backup(listing):
        return IDENTIFICATION_CONTROLLER_IOS
    if _is_controller_android(listing):
        return IDENTIFICATION_CONTROLLER_ANDROID
    if _is_drone_sd(listing):
        return IDENTIFICATION_DRONE_SD
    if _is_drone_flight_storage(listing):
        return IDENTIFICATION_DRONE_FLIGHT_STORAGE

    return IDENTIFICATION_UNCLASSIFIED


def _build_tsk_cmd(
    tool: Path,
    image_path: Path,
    image_type: str | None,
    offset: int | None,
    extra_flags: list[str] | None = None,
) -> list[str]:
    """Build a TSK command line."""
    cmd = [str(tool)]
    if image_type:
        cmd.extend(["-i", image_type])
    if extra_flags:
        cmd.extend(extra_flags)
    if offset is not None:
        cmd.extend(["-o", str(offset)])
    cmd.append(str(image_path))
    return cmd


def _enumerate_image_listing(image_path: Path, state: State) -> list[str]:
    """Enumerate file listing from forensic image via a single mmls probe and fls."""

    offset: int | None = None

    # Single mmls attempt - derive partition offset for disk-level images.
    mmls_cmd = _build_tsk_cmd(TSK_MMLS, image_path, None, None)
    mmls_result = run_command(mmls_cmd)
    state.log_command_result(tool_name="mmls", result=mmls_result)

    if mmls_result.returncode == 0:
        try:
            offset = parse_mmls_offset(mmls_result.stdout or "")
        except ValueError:
            state.anomaly_flags.append(f"p1_mmls_parse_failed:{image_path.name}")
    else:
        state.anomaly_flags.append(f"p1_mmls_unavailable_fls_direct:{image_path.name}")

    # fls enumeration - with offset if available, without if not.
    fls_cmd = _build_tsk_cmd(TSK_FLS, image_path, None, offset, ["-r", "-p"])
    fls_result = run_command(fls_cmd)
    state.log_command_result(tool_name="fls", result=fls_result)

    if fls_result.returncode != 0:
        raise RuntimeError(
            f"fls failed for {image_path.name}: {fls_result.stderr or fls_result.stdout}. "
            "Verify Sleuth Kit installation and EWF support."
        )

    entries = list_fls_entries(fls_result.stdout or "")

    # Persist image metadata into state.phase_outputs for later phases to reuse
    meta = {
        "offset_sectors": offset,
        "entries": [
            {"kind": kind, "inode": inode, "path": normalise_path(path)}
            for (kind, inode, path) in entries
        ],
    }
    state.phase_outputs.setdefault("p1_provenance", {}).setdefault(
        "image_metadata", {}
    )[image_path.name] = meta

    return [normalise_path(entry[2]) for entry in entries]


def _enumerate_zip_listing(zip_path: Path) -> list[str]:
    """Enumerate file listing from ZIP archive."""
    with zipfile.ZipFile(zip_path) as archive:
        return [normalise_path(name) for name in archive.namelist()]


def run_phase_1(state: State, *, confirm_all: bool = True) -> State:
    """Run Phase 1 classification over supported inputs in the evidence directory."""
    if not state.evidence_directory:
        raise ValueError(
            "State must contain an evidence_directory before Phase 1 can run"
        )

    evidence_dir = Path(state.evidence_directory)
    if not evidence_dir.exists() or not evidence_dir.is_dir():
        raise FileNotFoundError(f"Evidence directory not found: {evidence_dir}")

    now = utc_now_iso()
    p1_outputs: list[SourceRecord] = []

    for candidate in sorted(evidence_dir.iterdir()):
        if not candidate.is_file() or not _supported_input(candidate):
            continue

        is_zip = candidate.suffix.lower() == EXTENSION_ZIP[0].lower()
        evidence = Evidence(
            source_path=str(candidate),
            stored_path=candidate.resolve(),
            acquisition_method=ACQUISITION_LOGICAL if is_zip else ACQUISITION_PHYSICAL,
            type=EVIDENCE_TYPE_INPUT,
            skip_hash=True,
        )
        state.input_evidence.append(evidence)

        listing = (
            _enumerate_zip_listing(candidate)
            if is_zip
            else _enumerate_image_listing(candidate, state)
        )
        identified_as = identify_source(listing)

        p1_outputs.append(
            cast(
                SourceRecord,
                {
                    "source_path": str(evidence.source_path),
                    "identified": identified_as != IDENTIFICATION_UNCLASSIFIED,
                    "identified_as": identified_as,
                    "operator_confirmed": False,
                    "identified_by_operator_as": None,
                },
            )
        )

    # Enforce no unidentified sources if confirm_all
    if confirm_all and p1_outputs:
        for record in p1_outputs:
            if not record["identified"]:
                raise ValueError(
                    f"Unidentified source: {_record_source_path(cast(dict[str, object], record))}. Identify all sources before proceeding."
                )
            record["operator_confirmed"] = True

    previous_p1 = state.phase_outputs.get("p1_provenance", {})
    image_metadata = (
        previous_p1.get("image_metadata", {}) if isinstance(previous_p1, dict) else {}
    )
    state.phase_outputs["p1_provenance"] = {
        "completed_at": now,
        "identified_evidence": p1_outputs,
        "operator_final_confirmation": {"accepted": None, "timestamp": None},
        "image_metadata": image_metadata,
    }
    if "p1_provenance" not in state.completed_phases:
        state.completed_phases.append("p1_provenance")

    return state


def _show_summary(sources: list[SourceRecord]) -> None:
    """Display a compact summary of all identifications."""
    if not sources:
        print("No evidence sources detected.")
        return

    # Calculate maximum lengths for alignment
    max_filename_len = max(
        len(Path(_record_source_path(cast(dict[str, object], record))).name)
        for record in sources
    )
    max_ident_len = max(len(record["identified_as"]) for record in sources)

    print("Evidence sources detected:")
    for idx, record in enumerate(sources, start=1):
        filename = Path(_record_source_path(cast(dict[str, object], record))).name
        identified_as = record["identified_as"]
        identified = record["identified"]
        print(
            f"  [{idx}] {filename:<{max_filename_len}} -> {identified_as:<{max_ident_len}} (identified: {identified})"
        )


def _prompt_override_identifications(sources: list[SourceRecord]) -> None:
    """Allow operator to override identifications interactively."""
    all_idents = sorted(SOURCE_IDENTIFICATION_TYPES)
    for idx, record in enumerate(sources, start=1):
        print(
            f"\nSource [{idx}] {Path(_record_source_path(cast(dict[str, object], record))).name}"
        )
        print(f"  Current: {record['identified_as']}")
        for c_idx, ident in enumerate(all_idents, start=1):
            marker = " *" if ident == record["identified_as"] else ""
            print(f"    [{c_idx}] {ident}{marker}")
        print(f"    [0] Keep current")

        try:
            choice = input(f"  Select (0-{len(all_idents)}): ").strip()
            if choice and choice != "0":
                c_idx = int(choice) - 1
                if 0 <= c_idx < len(all_idents):
                    selected_identification = all_idents[c_idx]
                    if selected_identification != record["identified_as"]:
                        record["identified_by_operator_as"] = selected_identification
                    else:
                        record["identified_by_operator_as"] = None
                    record["identified"] = True
                    print(f"  → Changed to: {all_idents[c_idx]}")
        except (ValueError, IndexError):
            pass


def _has_unidentified_sources(sources: list[SourceRecord]) -> bool:
    """Check if any sources remain unidentified."""
    return any(not record["identified"] for record in sources)


def prompt_phase_1_summary_and_confirm(state: State) -> bool:
    """Print summary and request operator confirmation with override option."""
    p1 = cast(dict[str, object], state.phase_outputs.get("p1_provenance", {}))
    sources = cast(list[SourceRecord], p1.get("identified_evidence", []))
    now = utc_now_iso()

    while True:
        _show_summary(sources)
        answer = input("\nProceed? [yes/no]: ").strip().lower()

        if answer in {"y", "yes"}:
            if _has_unidentified_sources(sources):
                print(
                    "One or more sources are still unidentified. Please identify them or exit."
                )
                continue
            accepted = True
            break
        elif answer in {"n", "no"}:
            sub = input("  [change]/[exit]?: ").strip().lower()
            if sub in {"c", "change"}:
                _prompt_override_identifications(sources)
                continue
            elif sub in {"e", "exit"}:
                accepted = False
                break
            continue
        continue

    # Finalize confirmations
    for record in sources:
        record["operator_confirmed"] = accepted

    state.phase_outputs.setdefault("p1_provenance", {})[
        "operator_final_confirmation"
    ] = {
        "accepted": accepted,
        "timestamp": now,
    }
    return accepted
