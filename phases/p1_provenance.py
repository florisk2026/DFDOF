"""Phase 1: Provenance and Integrity.

This phase:
- builds Evidence objects for supported inputs (.E01, .001, .zip),
- enumerates structure-only file listings (fls or zip namelist),
- classifies each source with a weighted confidence model,
- records operator confirmations in state,
- saves state atomically.
"""

from __future__ import annotations

import re
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, NotRequired, TypedDict, cast

from config import (
	AMBIGUOUS_MIN_SCORE,
	AUTO_CLASSIFY_MIN_SCORE,
	AUTO_CLASSIFY_SECONDARY_MAX,
	CLASSIFICATION_SIGNALS,
	CLASSIFICATION_SCORE_CAP,
	IOS_LOGICAL_BACKUP_BONUS,
	IOS_LOGICAL_HEX_FOLDER_THRESHOLD,
	TSK_FLS,
	TSK_MMLS,
)
from evidence import Evidence
from mounting.tsk_mounter import _run_command, list_fls_entries, parse_mmls_offset
from state import State


SourceChoiceFn = Callable[[Evidence, list[tuple[str, int]]], str]


class ClassificationDecision(TypedDict):
	scores: dict[str, int]
	ranked: list[tuple[str, int]]
	auto_classification: str | None
	status: str
	candidates: NotRequired[list[tuple[str, int]]]


class OperatorConfirmation(TypedDict):
	confirmed: bool
	confirmed_classification: str | None
	timestamp: str | None


class SourceRecord(TypedDict):
	path: str
	sha256: str
	acquisition_method: str
	enumeration_method: str
	classification: ClassificationDecision
	operator_confirmation: OperatorConfirmation
	status: str


def _utc_now_iso() -> str:
	return datetime.now(timezone.utc).isoformat()


def _supported_input(path: Path) -> bool:
	return path.suffix.lower() in {".e01", ".001", ".zip"}


def _normalise_listing_path(path_value: str) -> str:
	return path_value.replace("\\", "/")


def _score_ios_logical_backup(listing: list[str]) -> int:
	"""Detect a logical iTunes backup structure using aggregate characteristics."""

	hex_folders: set[str] = set()
	marker_bonus = 0
	for raw_path in listing:
		parts = _normalise_listing_path(raw_path).split("/")
		for part in parts:
			if re.fullmatch(r"[0-9a-fA-F]{2}", part):
				hex_folders.add(part.lower())
		if "Manifest.db" in raw_path:
			marker_bonus += 2
		if raw_path.endswith("Manifest"):
			marker_bonus += 1
		if raw_path.endswith("Info"):
			marker_bonus += 1
		if raw_path.endswith("Status"):
			marker_bonus += 1

	if len(hex_folders) >= IOS_LOGICAL_HEX_FOLDER_THRESHOLD:
		return IOS_LOGICAL_BACKUP_BONUS + marker_bonus
	return 0


def _image_type_candidates(image_path: Path) -> list[str | None]:
	"""Return image type hints to improve TSK compatibility for known formats."""

	suffix = image_path.suffix.lower()
	if suffix == ".e01":
		return [None, "ewf"]
	if suffix == ".001":
		return [None, "split"]
	return [None]


def _enumerate_image_listing(image_path: Path, state: State) -> list[str]:
	def _run_fls(image_type: str | None, offset: int | None) -> list[str]:
		fls_cmd = [str(TSK_FLS)]
		if image_type is not None:
			fls_cmd.extend(["-i", image_type])
		fls_cmd.extend(["-r", "-p"])
		if offset is not None:
			fls_cmd.extend(["-o", str(offset)])
		fls_cmd.append(str(image_path))

		fls_result = _run_command(fls_cmd)
		state.log_tool_invocation(
			tool_name="fls",
			args=fls_cmd,
			return_code=fls_result.returncode,
			stdout=fls_result.stdout or "",
			stderr=fls_result.stderr or "",
		)
		if fls_result.returncode != 0:
			raise RuntimeError(f"fls failed for {image_path}: {fls_result.stderr or fls_result.stdout}")

		entries = list_fls_entries(fls_result.stdout or "")
		return [_normalise_listing_path(entry[2]) for entry in entries]

	last_mmls_output = ""
	chosen_image_type: str | None = None
	mmls_result = None
	for image_type in _image_type_candidates(image_path):
		mmls_cmd = [str(TSK_MMLS)]
		if image_type is not None:
			mmls_cmd.extend(["-i", image_type])
		mmls_cmd.append(str(image_path))
		candidate_result = _run_command(mmls_cmd)
		state.log_tool_invocation(
			tool_name="mmls",
			args=mmls_cmd,
			return_code=candidate_result.returncode,
			stdout=candidate_result.stdout or "",
			stderr=candidate_result.stderr or "",
		)
		last_mmls_output = (candidate_result.stderr or candidate_result.stdout or "").strip()
		if candidate_result.returncode == 0:
			mmls_result = candidate_result
			chosen_image_type = image_type
			break

	if mmls_result is None:
		# Some forensic images are filesystem-level (no partition table), where
		# mmls fails but fls can still enumerate paths directly.
		for image_type in _image_type_candidates(image_path):
			try:
				listing = _run_fls(image_type=image_type, offset=None)
				state.anomaly_flags.append(
					f"p1_mmls_unavailable_used_fls_direct:{image_path.name}:{image_type or 'auto'}"
				)
				return listing
			except RuntimeError:
				continue

		raise RuntimeError(
			f"mmls failed for {image_path}, and direct fls fallback also failed. "
			"Verify Sleuth Kit path/configuration and EWF support for .E01 images. "
			f"Last mmls output: {last_mmls_output}"
		)

	try:
		offset = parse_mmls_offset(mmls_result.stdout or "")
	except ValueError as exc:
		raise RuntimeError(f"Unable to parse mmls partition table for {image_path}: {exc}") from exc

	return _run_fls(image_type=chosen_image_type, offset=offset)


def _enumerate_zip_listing(zip_path: Path) -> list[str]:
	with zipfile.ZipFile(zip_path) as archive:
		return [_normalise_listing_path(name) for name in archive.namelist()]


def score_source_type(listing: list[str]) -> dict[str, int]:
	"""Score each source class using regex signal matches."""

	scores = {class_name: 0 for class_name in CLASSIFICATION_SIGNALS}
	scores["ios_controller"] += _score_ios_logical_backup(listing)
	for class_name, signals in CLASSIFICATION_SIGNALS.items():
		matched_patterns: set[str] = set()
		for raw_path in listing:
			candidate = _normalise_listing_path(raw_path)
			for pattern, weight in signals:
				if pattern in matched_patterns:
					continue
				if re.search(pattern, candidate, flags=re.IGNORECASE):
					scores[class_name] += weight
					matched_patterns.add(pattern)
		scores[class_name] = min(scores[class_name], CLASSIFICATION_SCORE_CAP)
	return scores


def decide_classification(scores: dict[str, int]) -> ClassificationDecision:
	"""Apply confidence rules and return a decision payload."""

	ranked = sorted(scores.items(), key=lambda kv: kv[1], reverse=True)
	top_class, top_score = ranked[0]
	second_class, second_score = ranked[1]

	decision: ClassificationDecision = {
		"scores": scores,
		"ranked": ranked,
		"auto_classification": None,
		"status": "unclassified",
	}

	if top_score >= AUTO_CLASSIFY_MIN_SCORE and second_score <= AUTO_CLASSIFY_SECONDARY_MAX:
		decision["auto_classification"] = top_class
		decision["status"] = "auto"
		return decision

	if top_score >= AMBIGUOUS_MIN_SCORE and second_score >= AMBIGUOUS_MIN_SCORE:
		decision["status"] = "ambiguous"
		decision["candidates"] = [(top_class, top_score), (second_class, second_score)]

	return decision


def run_phase_1(
	state: State,
	*,
	confirm_all: bool = True,
	resolve_ambiguous: SourceChoiceFn | None = None,
) -> State:
	"""Run Phase 1 classification over supported inputs in the evidence directory."""

	if not state.evidence_directory:
		raise ValueError("State must contain an evidence_directory before Phase 1 can run")

	evidence_dir = Path(state.evidence_directory)
	if not evidence_dir.exists() or not evidence_dir.is_dir():
		raise FileNotFoundError(f"Evidence directory not found: {evidence_dir}")

	p1_outputs: list[SourceRecord] = []
	for candidate in sorted(evidence_dir.iterdir()):
		if not candidate.is_file() or not _supported_input(candidate):
			continue

		acquisition_method = "logical" if candidate.suffix.lower() == ".zip" else "physical"
		evidence = Evidence(
			candidate.resolve(),
			provenance="input_source",
			parent=None,
			acquisition_method=acquisition_method,
			skip_hash=True,
		)
		state.input_evidence.append(evidence)

		if candidate.suffix.lower() == ".zip":
			listing = _enumerate_zip_listing(candidate)
			enumeration_method = "zip_namelist"
		else:
			listing = _enumerate_image_listing(candidate, state)
			enumeration_method = "fls"

		scores = score_source_type(listing)
		decision = decide_classification(scores)

		confirmed_classification = cast(str | None, decision.get("auto_classification"))
		operator_record: OperatorConfirmation = {
			"confirmed": False,
			"confirmed_classification": confirmed_classification,
			"timestamp": None,
		}

		if decision["status"] == "ambiguous" and resolve_ambiguous is not None:
			ambiguous_candidates = cast(list[tuple[str, int]], decision.get("candidates", []))
			choice = resolve_ambiguous(evidence, ambiguous_candidates)
			operator_record["confirmed"] = True
			operator_record["confirmed_classification"] = choice
			operator_record["timestamp"] = _utc_now_iso()

		p1_outputs.append(
			cast(SourceRecord, {
				"path": str(evidence.path),
				"sha256": evidence.sha256,
				"acquisition_method": evidence.acquisition_method or acquisition_method,
				"enumeration_method": enumeration_method,
				"classification": decision,
				"operator_confirmation": operator_record,
				"status": decision["status"],
			})
		)

	if confirm_all and p1_outputs:
		for record in p1_outputs:
			operator_confirmation = record["operator_confirmation"]
			operator_confirmation["confirmed"] = True
			operator_confirmation["timestamp"] = _utc_now_iso()
			if operator_confirmation["confirmed_classification"] is None:
				operator_confirmation["confirmed_classification"] = "unclassified"

	state.phase_outputs["p1_provenance"] = {
		"sources": p1_outputs,
		"completed_at": _utc_now_iso(),
	}

	if "p1_provenance" not in state.completed_phases:
		state.completed_phases.append("p1_provenance")

	return state


def _show_summary(sources: list[SourceRecord]) -> None:
	"""Display a compact summary of all classifications."""

	print("Evidence sources detected:\n")
	for idx, record in enumerate(sources, start=1):
		classification = record["classification"]
		auto = classification.get("auto_classification")
		status = classification.get("status")
		ranked = classification.get("ranked", [])
		top_score = ranked[0][1] if ranked else 0
		label = auto if auto is not None else "unclassified"
		print(f"  [{idx}] {Path(record['path']).name} -> {label} (status: {status}, score: {top_score}/10)")


def _prompt_override_classifications(sources: list[SourceRecord]) -> None:
	"""Allow operator to override classifications interactively."""

	all_classes = list(CLASSIFICATION_SIGNALS.keys())
	
	for idx, record in enumerate(sources, start=1):
		classification = record["classification"]
		scores = classification.get("scores", {})
		current_auto = classification.get("auto_classification") or "unclassified"
		
		print(f"\nSource [{idx}] {Path(record['path']).name}")
		print(f"  Current classification: {current_auto}")
		print("  Options:")
		for class_idx, class_name in enumerate(all_classes, start=1):
			score = scores.get(class_name, 0)
			marker = " *" if class_name == current_auto else ""
			print(f"    [{class_idx}] {class_name} (score: {score}/10){marker}")
		print(f"    [0] Keep current")
		
		choice = input("  Select classification (number) or press Enter to skip: ").strip()
		if not choice or choice == "0":
			continue
		
		try:
			choice_idx = int(choice) - 1
			if 0 <= choice_idx < len(all_classes):
				new_class = all_classes[choice_idx]
				classification["auto_classification"] = new_class
				record["operator_confirmation"]["confirmed_classification"] = new_class
				print(f"  → Changed to: {new_class}")
		except (ValueError, IndexError):
			print("  Invalid choice; skipping.")


def _has_unclassified_sources(sources: list[SourceRecord]) -> bool:
	return any(record["classification"].get("auto_classification") is None for record in sources)


def prompt_phase_1_summary_and_confirm(state: State) -> bool:
	"""Print a summary and request final operator confirmation with override option."""

	p1 = cast(dict[str, object], state.phase_outputs.get("p1_provenance", {}))
	sources = cast(list[SourceRecord], p1.get("sources", []))
	
	while True:
		_show_summary(sources)
		
		answer = input("\nProceed with these classifications? [yes/no]: ").strip().lower()
		if answer in {"y", "yes"}:
			if _has_unclassified_sources(sources):
				print("One or more sources are still unclassified. Please classify them or abort.")
				continue
			accepted = True
			break
		elif answer in {"n", "no"}:
			change_answer = input("Would you like to [change] classifications or [abort]?: ").strip().lower()
			if change_answer in {"c", "change"}:
				_prompt_override_classifications(sources)
				continue
			elif change_answer in {"a", "abort"}:
				accepted = False
				break
			else:
				print("Please enter 'change' or 'exit'.")
				continue
		else:
			print("Please enter 'yes' or 'no'.")
			continue
	
	p1_outputs = cast(list[SourceRecord], p1.get("sources", []))
	for record in p1_outputs:
		record["operator_confirmation"]["confirmed"] = accepted
		record["operator_confirmation"]["timestamp"] = _utc_now_iso()

	state.phase_outputs.setdefault("p1_provenance", {})["operator_final_confirmation"] = {
		"accepted": accepted,
		"timestamp": _utc_now_iso(),
	}
	return accepted
