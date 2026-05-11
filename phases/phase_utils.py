"""Phase utilities for identification and evidence matching.

Shared helpers used across phases for evidence source matching and identification.
"""

from __future__ import annotations

from evidence import Evidence
from state import State


def find_input_evidence_by_identification(state: State, identification: str) -> Evidence | None:
	"""Find input evidence matching an identification from phase 1 output.
	
	Uses the auto-classification if operator_confirmed is True; otherwise
	uses the operator's override if present. Prioritizes operator intent.
	"""
	source_records = state.phase_outputs.get("p1_provenance", {}).get("identified_evidence", [])
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
				return evidence
	return None
