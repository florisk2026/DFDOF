"""Phase utilities for identification and evidence matching.

Shared helpers used across phases for evidence source matching and identification.
"""

from __future__ import annotations

from evidence import Evidence
from state import State


def find_input_evidence_by_identification(state: State, identification: str) -> Evidence | None:
	"""Find input evidence matching an identification from phase 1 output."""
	source_records = state.phase_outputs.get("p1_provenance", {}).get("identified_evidence", [])
	for record in source_records:
		recorded_identification = str(record.get("identified_as", record.get("identification", "")))
		if recorded_identification != identification:
			continue
		source_path = str(record.get("source_path") or "")
		if not source_path:
			continue
		for evidence in state.input_evidence:
			if str(evidence.source_path) == source_path:
				return evidence
	return None
