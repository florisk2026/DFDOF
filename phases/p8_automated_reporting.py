"""DFDOF Phase 8: Automated Forensic Baseline Report.

This phase:
- drafts an automated report based on the outputs of P7,
- this includes an executive summary, detailed findings and analyses,
- visualizations (plots, charts, timelines),
- forensic safe statements and recommendations.
"""

from __future__ import annotations

from pathlib import Path

from config import output_dir, utc_now_iso
from reporting.report_builder import build_report
from state import State

_PHASE_NAME = Path(__file__).stem


def run_phase_8(state: State) -> State:
    """Phase 8: Generate the forensic baseline PDF report."""
    if "p7_analysis_and_validation" not in state.phase_outputs:
        raise ValueError("Phase 8 requires Phase 7 outputs. Run Phase 7 first.")

    case_dir  = output_dir() / state.case_id
    plots_dir = case_dir / _PHASE_NAME
    plots_dir.mkdir(parents=True, exist_ok=True)

    pdf_path = case_dir / f"{state.case_id}_forensic_baseline.pdf"

    print(f"  Generating report: {pdf_path.name}")
    build_report(state, pdf_path, plots_dir)

    state.phase_outputs[_PHASE_NAME] = {
        "completed_at": utc_now_iso(),
        "report_path": str(pdf_path),
        "plots_dir":   str(plots_dir),
    }
    if _PHASE_NAME not in state.completed_phases:
        state.completed_phases.append(_PHASE_NAME)

    print(f"  Report written: {pdf_path}")
    return state
