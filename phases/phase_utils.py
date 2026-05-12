"""Phase utilities for identification and evidence matching.

Shared helpers used across phases for evidence source matching and identification.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from evidence import Evidence
from state import State


def find_input_evidence_list_by_identification(state: State, identification: str) -> list[Evidence]:
	"""Find all input evidence matching an identification from phase 1 output.
	
	Uses the auto-classification if operator_confirmed is True; otherwise
	uses the operator's override if present. Prioritizes operator intent.
	
	Returns a list of matching Evidence objects (may be empty).
	"""
	source_records = state.phase_outputs.get("p1_provenance", {}).get("identified_evidence", [])
	matching_evidence: list[Evidence] = []
	for record in source_records:
		# Determine effective identification: auto if confirmed, else operator override
		if record.get("operator_confirmed"):
			recorded_identification = str(record.get("identified_as", ""))
		else:
			recorded_identification = str(
				record.get("identified_by_operator_as") or record.get("identified_as", "")
			)
		
		if recorded_identification != identification:
			continue
		source_path = str(record.get("source_path") or "")
		if not source_path:
			continue
		for evidence in state.input_evidence:
			if str(evidence.source_path) == source_path:
				matching_evidence.append(evidence)
				break  # Assuming one evidence per source_path, but collect all
	return matching_evidence
