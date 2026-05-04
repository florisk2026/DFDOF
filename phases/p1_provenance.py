"""DFDOF Phase 1: Provenance and Integrity.

This phase: 
- builds evidence objects for supported inputs (.E01, .001, .zip),
- classifies each source using rules,
- records operator confirmation in state.
"""

from __future__ import annotations

import re
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import TypedDict, cast

from config import (
	SOURCE_CLASSIFICATION_TYPES,
	SUPPORTED_IMAGE_EXTENSIONS,
	TSK_FLS,
	TSK_MMLS,
)
from evidence import Evidence
from parsing.tsk_mounter import _run_command, list_fls_entries, parse_mmls_offset
from state import State


class OperatorConfirmation(TypedDict):
	confirmed: bool
	confirmed_classification: str | None
	timestamp: str | None


class SourceRecord(TypedDict):
	path: str
	sha256: str
	acquisition_method: str
	enumeration_method: str
	classification: str
	operator_confirmation: OperatorConfirmation
	status: str


def _utc_now_iso() -> str:
	return datetime.now(timezone.utc).isoformat()


def _supported_input(path: Path) -> bool:
	return path.suffix.lower() in {ext.lower() for ext in SUPPORTED_IMAGE_EXTENSIONS}


def _normalise_listing_path(path_value: str) -> str:
	return path_value.replace("\\", "/")


def _is_ios_logical_backup(listing: list[str]) -> bool:
	"""Detect iTunes logical backup: Manifest.db + Info.plist + 50+ hex/hex folders."""
	norm = [_normalise_listing_path(p) for p in listing]
	return (
		any("Manifest.db" in p for p in norm) and
		any("Info.plist" in p for p in norm) and
		sum(1 for p in norm if re.search(r'[0-9a-fA-F]{2}/[0-9a-fA-F]{2}/', p)) > 50
	)


def _is_android_controller(listing: list[str]) -> bool:
	"""Detect Android controller: (data/data/dji OR sdcard/dji) + FlightRecord."""
	norm = [_normalise_listing_path(p) for p in listing]
	has_dji = any(s in p.lower() for p in norm for s in ('data/data/dji', 'data/data/com.dji', 'sdcard/dji', 'sdcard/DJI'))
	return has_dji and any('FlightRecord' in p for p in norm)


def _is_drone_sd(listing: list[str]) -> bool:
	"""Detect drone SD card: DCIM with media files (MP4/JPG/MOV)."""
	norm = [_normalise_listing_path(p) for p in listing]
	return (
		any('DCIM/' in p for p in norm) and
		any(p.endswith(('.MP4', '.JPG', '.mp4', '.jpg', '.MOV', '.mov', '.THM', '.thm')) 
		    and 'DCIM' in p for p in norm)
	)


def _is_drone_flight_storage(listing: list[str]) -> bool:
	"""Detect drone flight storage: FLY*.DAT or DJI_ASSISTANT_EXPORT_FILE*.DAT."""
	norm = [_normalise_listing_path(p) for p in listing]
	return any(
		re.search(r'(FLY\d+|DJI_ASSISTANT_EXPORT_FILE.*)', p, re.IGNORECASE) and p.upper().endswith('.DAT')
		for p in norm
	)


def classify_source(listing: list[str]) -> str:
	"""Deterministic structural classification."""
	if _is_ios_logical_backup(listing):
		return "ios_controller"
	if _is_android_controller(listing):
		return "android_controller"
	if _is_drone_sd(listing):
		return "drone_sd"
	if _is_drone_flight_storage(listing):
		return "drone_flight_storage"

	return "unclassified"


def _image_type_candidates(image_path: Path) -> list[str | None]:
	"""Return image type hints to improve TSK compatibility for known formats."""
	suffix = image_path.suffix.lower()
	if suffix == ".e01":
		return [None, "ewf"]
	if suffix == ".001":
		return [None, "split"]
	return [None]


def _build_tsk_cmd(tool: Path, image_path: Path, image_type: str | None, offset: int | None, extra_flags: list[str] | None = None) -> list[str]:
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
	"""Enumerate file listing from forensic image via mmls/fls."""
	
	# Try mmls with different image type hints
	mmls_result = None
	last_mmls_output = ""
	for image_type in _image_type_candidates(image_path):
		cmd = _build_tsk_cmd(TSK_MMLS, image_path, image_type, None)
		result = _run_command(cmd)
		state.log_tool_invocation(
			tool_name="mmls",
			args=cmd,
			return_code=result.returncode,
			stdout=result.stdout or "",
			stderr=result.stderr or "",
		)
		last_mmls_output = (result.stderr or result.stdout or "").strip()
		if result.returncode == 0:
			mmls_result = result
			chosen_type = image_type
			break
	
	# Fallback: try fls without mmls (filesystem-level images)
	if mmls_result is None:
		for image_type in _image_type_candidates(image_path):
			try:
				cmd = _build_tsk_cmd(TSK_FLS, image_path, image_type, None, ["-r", "-p"])
				result = _run_command(cmd)
				state.log_tool_invocation(
				tool_name="fls",
				args=cmd,
				return_code=result.returncode,
				stdout=result.stdout or "",
				stderr=result.stderr or "",
			)
				if result.returncode == 0:
					state.anomaly_flags.append(f"p1_mmls_unavailable_used_fls_direct:{image_path.name}:{image_type or 'auto'}")
					entries = list_fls_entries(result.stdout or "")
					return [_normalise_listing_path(entry[2]) for entry in entries]
			except RuntimeError:
				continue
		raise RuntimeError(
			f"mmls failed for {image_path}, and direct fls fallback also failed. "
			f"Verify Sleuth Kit path/configuration and EWF support for .E01 images. "
			f"Last mmls output: {last_mmls_output}"
		)
	
	# Parse partition offset and enumerate with fls
	offset = parse_mmls_offset(mmls_result.stdout or "")
	cmd = _build_tsk_cmd(TSK_FLS, image_path, chosen_type, offset, ["-r", "-p"])
	fls_result = _run_command(cmd)
	state.log_tool_invocation(
		tool_name="fls",
		args=cmd,
		return_code=fls_result.returncode,
		stdout=fls_result.stdout or "",
		stderr=fls_result.stderr or "",
	)
	if fls_result.returncode != 0:
		raise RuntimeError(f"fls failed for {image_path}: {fls_result.stderr or fls_result.stdout}")
	
	entries = list_fls_entries(fls_result.stdout or "")
	return [_normalise_listing_path(entry[2]) for entry in entries]


def _enumerate_zip_listing(zip_path: Path) -> list[str]:
	with zipfile.ZipFile(zip_path) as archive:
		return [_normalise_listing_path(name) for name in archive.namelist()]


def run_phase_1(state: State, *, confirm_all: bool = True) -> State:
	"""Run Phase 1 classification over supported inputs in the evidence directory."""
	if not state.evidence_directory:
		raise ValueError("State must contain an evidence_directory before Phase 1 can run")

	evidence_dir = Path(state.evidence_directory)
	if not evidence_dir.exists() or not evidence_dir.is_dir():
		raise FileNotFoundError(f"Evidence directory not found: {evidence_dir}")

	now = _utc_now_iso()
	p1_outputs: list[SourceRecord] = []
	
	for candidate in sorted(evidence_dir.iterdir()):
		if not candidate.is_file() or not _supported_input(candidate):
			continue

		is_zip = candidate.suffix.lower() == ".zip"
		evidence = Evidence(
			candidate.resolve(),
			provenance="input_source",
			parent=None,
			acquisition_method="logical" if is_zip else "physical",
			skip_hash=True,
		)
		state.input_evidence.append(evidence)

		listing = _enumerate_zip_listing(candidate) if is_zip else _enumerate_image_listing(candidate, state)
		classification = classify_source(listing)
		
		p1_outputs.append(cast(SourceRecord, {
			"path": str(evidence.path),
			"sha256": evidence.sha256,
			"acquisition_method": evidence.acquisition_method,
			"enumeration_method": "zip_namelist" if is_zip else "fls",
			"classification": classification,
			"operator_confirmation": {
				"confirmed": False,
				"confirmed_classification": classification,
				"timestamp": None,
			},
			"status": "classified" if classification != "unclassified" else "unclassified",
		}))

	# Enforce no unclassified sources if confirm_all
	if confirm_all and p1_outputs:
		for record in p1_outputs:
			if record["status"] == "unclassified":
				raise ValueError(f"Unclassified source: {record['path']}. Classify all sources before proceeding.")
			record["operator_confirmation"]["confirmed"] = True
			record["operator_confirmation"]["timestamp"] = now

	state.phase_outputs["p1_provenance"] = {"sources": p1_outputs, "completed_at": now}
	if "p1_provenance" not in state.completed_phases:
		state.completed_phases.append("p1_provenance")

	return state


def _show_summary(sources: list[SourceRecord]) -> None:
	"""Display a compact summary of all classifications."""

	print("Evidence sources detected:")
	for idx, record in enumerate(sources, start=1):
		classification = record["classification"]
		status = record["status"]
		print(f"  [{idx}] {Path(record['path']).name} -> {classification} (status: {status})")


def _prompt_override_classifications(sources: list[SourceRecord]) -> None:
	"""Allow operator to override classifications interactively."""
	all_classes = sorted(SOURCE_CLASSIFICATION_TYPES)
	for idx, record in enumerate(sources, start=1):
		print(f"\nSource [{idx}] {Path(record['path']).name}")
		print(f"  Current: {record['classification']}")
		for c_idx, cls in enumerate(all_classes, start=1):
			marker = " *" if cls == record['classification'] else ""
			print(f"    [{c_idx}] {cls}{marker}")
		print(f"    [0] Keep current")
		
		try:
			choice = input("  Select (0-{len(all_classes)}): ").strip()
			if choice and choice != "0":
				c_idx = int(choice) - 1
				if 0 <= c_idx < len(all_classes):
					record["classification"] = all_classes[c_idx]
					record["status"] = "classified"
					record["operator_confirmation"]["confirmed_classification"] = all_classes[c_idx]
					print(f"  → Changed to: {all_classes[c_idx]}")
		except (ValueError, IndexError):
			pass


def _has_unclassified_sources(sources: list[SourceRecord]) -> bool:
	return any(record["status"] == "unclassified" for record in sources)


def prompt_phase_1_summary_and_confirm(state: State) -> bool:
	"""Print summary and request operator confirmation with override option."""
	p1 = cast(dict[str, object], state.phase_outputs.get("p1_provenance", {}))
	sources = cast(list[SourceRecord], p1.get("sources", []))
	now = _utc_now_iso()
	
	while True:
		_show_summary(sources)
		answer = input("\nProceed? [yes/no]: ").strip().lower()
		
		if answer in {"y", "yes"}:
			if _has_unclassified_sources(sources):
				print("One or more sources are still unclassified. Please classify them or exit.")
				continue
			accepted = True
			break
		elif answer in {"n", "no"}:
			sub = input("  [change]/[exit]?: ").strip().lower()
			if sub in {"c", "change"}:
				_prompt_override_classifications(sources)
				continue
			elif sub in {"e", "exit"}:
				accepted = False
				break
			continue
		continue
	
	# Finalize confirmations
	for record in sources:
		record["operator_confirmation"]["confirmed"] = accepted
		record["operator_confirmation"]["timestamp"] = now
	
	state.phase_outputs.setdefault("p1_provenance", {})["operator_final_confirmation"] = {
		"accepted": accepted,
		"timestamp": now,
	}
	return accepted
