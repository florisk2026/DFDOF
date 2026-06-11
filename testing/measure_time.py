"""Pipeline timing instrumentation for DFDOF efficiency validation (T_EFF).

Records wall-clock duration per phase and total pipeline time.
Output is saved as timing_<case_id>.json alongside state.json in the case output directory.

Notes:
- time.perf_counter() is used for duration measurement (monotonic, high-resolution).
- datetime timestamps are for human readability only.
- P4 duration includes DatCon operator interaction time and cannot be isolated further.
- automated_seconds excludes P4 to reflect purely automated pipeline time.
"""

from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from pathlib import Path


_P4_PHASE = "p4_decision_and_orchestration"


class PipelineTimer:
    def __init__(self, case_id: str, operator: str) -> None:
        self._case_id = case_id
        self._operator = operator
        self._pipeline_start_iso = datetime.now(timezone.utc).isoformat()
        self._pipeline_end_iso: str | None = None
        self._phases: dict[str, dict[str, object]] = {}
        self._active_phase: str | None = None
        self._active_perf: float | None = None
        self._active_start_iso: str | None = None

    def start_phase(self, phase_name: str) -> None:
        self._active_phase = phase_name
        self._active_perf = time.perf_counter()
        self._active_start_iso = datetime.now(timezone.utc).isoformat()

    def end_phase(self, phase_name: str) -> None:
        end_perf = time.perf_counter()
        end_iso = datetime.now(timezone.utc).isoformat()
        if self._active_phase != phase_name or self._active_perf is None:
            raise RuntimeError(
                f"end_phase('{phase_name}') called but active phase is '{self._active_phase}'"
            )
        self._phases[phase_name] = {
            "start": self._active_start_iso,
            "end": end_iso,
            "duration_s": round(end_perf - self._active_perf, 3),
        }
        self._active_phase = None
        self._active_perf = None
        self._active_start_iso = None

    def finish(self) -> None:
        self._pipeline_end_iso = datetime.now(timezone.utc).isoformat()

    def _total_seconds(self) -> float:
        return round(sum(p["duration_s"] for p in self._phases.values()), 3)  # type: ignore[misc]

    def _automated_seconds(self) -> float:
        p4 = self._phases.get(_P4_PHASE, {}).get("duration_s", 0.0)
        return round(self._total_seconds() - p4, 3)  # type: ignore[operator]

    def save(self, output_path: Path) -> None:
        payload = {
            "case_id": self._case_id,
            "operator": self._operator,
            "pipeline_start": self._pipeline_start_iso,
            "pipeline_end": self._pipeline_end_iso,
            "total_seconds": self._total_seconds(),
            "automated_seconds": self._automated_seconds(),
            "phases": self._phases,
            "notes": {
                "p4_includes_datcon_operator_time": True,
                "automated_seconds_excludes": [_P4_PHASE],
            },
        }
        tmp = output_path.with_suffix(output_path.suffix + ".tmp")
        tmp.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        tmp.replace(output_path)
