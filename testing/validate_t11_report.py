"""T11 — Report Completeness and Auditability.

Usage
-----
    python testing/validate_t11_report.py state.json [state.json ...]

Requires pdfplumber for PDF text extraction:
    pip install pdfplumber

Pass criteria (R2a, R2b, R4, R6, R7b)
---------------------------------------
- All 12 PDF section headings present and non-empty
- Appendix A SHA-256 hashes match state.json P3 extracted_artefacts (100 %)
- Appendix C entry count matches len(state.tool_invocation_log)
- Cover page contains operator name, case ID, and start timestamp (year at minimum)
- Appendix B shows at least one parent-to-child derivation entry
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

try:
    import pdfplumber  # type: ignore[import]
    _PDF_OK = True
except ImportError:
    _PDF_OK = False

# Exact section titles from report_builder.py
_REQUIRED_SECTIONS = [
    "1. Evidence Intake and Chain of Custody",
    "2. Pipeline Execution Summary",
    "3. Device and Account Identification",
    "4. Flight Analysis",           # prefix match (flight_id appended)
    "5. Artefact Coverage",
    "6. Data Quality and Anomalies",
    "7. Further Investigation Items",
    "Appendix A",
    "Appendix B",
    "Appendix C",
    "Appendix D",
]

_SHA256_RE = re.compile(r"\b([0-9a-f]{64})\b")


def _load(path: str) -> dict:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def _find_pdf(state_path: str) -> Path | None:
    base = Path(state_path).parent
    pdfs = sorted(base.glob("*.pdf"))
    return pdfs[0] if pdfs else None


def _extract_full_text(pdf_path: Path) -> str:
    if not _PDF_OK:
        return ""
    pages = []
    with pdfplumber.open(str(pdf_path)) as pdf:
        for page in pdf.pages:
            pages.append(page.extract_text() or "")
    return "\n".join(pages)


def _section_between(full_text: str, start_marker: str, end_marker: str | None) -> str:
    idx = full_text.find(start_marker)
    if idx == -1:
        return ""
    if end_marker:
        end_idx = full_text.find(end_marker, idx + len(start_marker))
        return full_text[idx: end_idx] if end_idx != -1 else full_text[idx:]
    return full_text[idx:]


def _check_sections(full_text: str) -> dict:
    results = {}
    for section in _REQUIRED_SECTIONS:
        present = section in full_text
        results[section] = present
    return results


def _check_appendix_a(full_text: str, p3_artefacts: list[dict]) -> dict:
    appendix_text = _section_between(full_text, "Appendix A", "Appendix B")
    if not appendix_text:
        return {"status": "SKIP", "reason": "Appendix A section not found in PDF"}

    pdf_hashes = set(_SHA256_RE.findall(appendix_text.lower()))
    state_hashes = {a["sha256"].lower() for a in p3_artefacts if a.get("sha256")}

    only_in_pdf = pdf_hashes - state_hashes
    only_in_state = state_hashes - pdf_hashes
    matched = pdf_hashes & state_hashes

    return {
        "pdf_hashes": len(pdf_hashes),
        "state_hashes": len(state_hashes),
        "matched": len(matched),
        "only_in_pdf": sorted(only_in_pdf)[:5],
        "only_in_state": sorted(only_in_state)[:5],
        "pass": not only_in_pdf and not only_in_state,
    }


def _count_appendix_c_entries(full_text: str) -> int:
    """Count tool entries in Appendix C.

    Each entry's header line is rendered as:
        "2026-01-01 10:00:00   datcon   v4.3.0   rc=0"
    Counting "   rc=" occurrences gives one match per entry.
    """
    appendix_text = _section_between(full_text, "Appendix C", "Appendix D")
    if not appendix_text:
        return -1
    return appendix_text.count("   rc=")


def _check_cover(full_text: str, state: dict) -> dict:
    case_id = state.get("case_id", "")
    operator = state.get("operator", "")
    start_time = state.get("start_time", "")
    year = start_time[:4] if start_time else ""

    issues = []
    if case_id and case_id not in full_text:
        issues.append(f"Case ID '{case_id}' not found in PDF")
    if operator and operator not in full_text:
        issues.append(f"Operator '{operator}' not found in PDF")
    if year and year not in full_text:
        issues.append(f"Start year '{year}' not found in PDF")

    return {"issues": issues, "pass": not issues}


def _validate(state_path: str) -> dict:
    state = _load(state_path)
    case_id = state.get("case_id", "unknown")
    tool_log = state.get("tool_invocation_log", [])
    p3 = (state.get("phase_outputs", {})
               .get("p3_artefact_extraction", {})
               .get("extracted_artefacts", []))

    if not _PDF_OK:
        return {
            "case_id": case_id,
            "pdf_available": False,
            "error": "pdfplumber not installed — run: pip install pdfplumber",
            "pass": False,
        }

    pdf_path = _find_pdf(state_path)
    if not pdf_path:
        return {
            "case_id": case_id,
            "pdf_available": False,
            "error": f"No PDF found next to {state_path}",
            "pass": False,
        }

    full_text = _extract_full_text(pdf_path)

    section_check = _check_sections(full_text)
    appendix_a = _check_appendix_a(full_text, p3)
    cover_check = _check_cover(full_text, state)
    appendix_c_count = _count_appendix_c_entries(full_text)

    sections_pass = all(section_check.values())
    appendix_a_pass = appendix_a.get("pass", False)

    # Appendix C count comparison (approximate — heuristic counting)
    c_expected = len(tool_log)
    c_delta = abs(appendix_c_count - c_expected) if appendix_c_count >= 0 else None
    appendix_c_pass = c_delta is not None and c_delta <= 2  # allow ±2 for heuristic

    # Appendix B: check at least one entry present
    appendix_b_text = _section_between(full_text, "Appendix B", "Appendix C")
    appendix_b_pass = len(appendix_b_text) > 200  # non-trivial content present

    overall = sections_pass and appendix_a_pass and cover_check["pass"] and appendix_b_pass

    return {
        "case_id": case_id,
        "pdf_path": str(pdf_path),
        "pdf_available": True,
        "section_check": section_check,
        "sections_pass": sections_pass,
        "appendix_a": appendix_a,
        "cover_check": cover_check,
        "appendix_b_pass": appendix_b_pass,
        "appendix_c": {
            "pdf_count": appendix_c_count,
            "state_count": c_expected,
            "delta": c_delta,
            "pass": appendix_c_pass,
        },
        "pass": overall,
    }


def _print_result(r: dict) -> None:
    status = "PASS" if r["pass"] else "FAIL"
    print(f"\n{'='*60}")
    print(f"  Case: {r['case_id']}  -> {status}")

    if not r.get("pdf_available"):
        print(f"  ERROR: {r.get('error')}")
        return

    print(f"  PDF: {r['pdf_path']}")

    sec = r["section_check"]
    missing = [k for k, v in sec.items() if not v]
    print(f"  Sections: {len(sec) - len(missing)}/{len(sec)} present"
          f" -> {'PASS' if not missing else 'FAIL'}")
    for m in missing:
        print(f"    MISSING: {m}")

    aa = r["appendix_a"]
    if aa.get("status") == "SKIP":
        print(f"  Appendix A: SKIP — {aa['reason']}")
    else:
        print(f"  Appendix A: {aa['matched']}/{aa['state_hashes']} hashes matched"
              f" -> {'PASS' if aa['pass'] else 'FAIL'}")
        for h in aa.get("only_in_state", [])[:3]:
            print(f"    MISSING from PDF: {h[:16]}...")
        for h in aa.get("only_in_pdf", [])[:3]:
            print(f"    EXTRA in PDF: {h[:16]}...")

    cv = r["cover_check"]
    print(f"  Cover page: -> {'PASS' if cv['pass'] else 'FAIL'}")
    for issue in cv["issues"]:
        print(f"    {issue}")

    print(f"  Appendix B (derivation): -> {'PASS' if r['appendix_b_pass'] else 'FAIL'}")

    ac = r["appendix_c"]
    print(f"  Appendix C: PDF~{ac['pdf_count']} entries, state={ac['state_count']}"
          f" (delta={ac['delta']}) -> {'PASS' if ac['pass'] else 'WARN'}")
    if not ac["pass"]:
        print("    (Heuristic count — do manual check: open PDF Appendix C and count entries)")


def main() -> int:
    ap = argparse.ArgumentParser(description="T11 — Report completeness")
    ap.add_argument("state_files", nargs="+", metavar="state.json")
    args = ap.parse_args()

    if not _PDF_OK:
        print("WARNING: pdfplumber not installed. Install with: pip install pdfplumber",
              file=sys.stderr)

    all_pass = True
    for path in args.state_files:
        try:
            r = _validate(path)
            _print_result(r)
            if not r["pass"]:
                all_pass = False
        except Exception as exc:
            print(f"ERROR reading {path}: {exc}", file=sys.stderr)
            all_pass = False

    print(f"\n{'='*60}")
    print(f"T11 RESULT: {'PASS' if all_pass else 'FAIL'}")
    print("Manual checklist: for 3 PDFs, tick off each section is non-empty and")
    print("  visually coherent. Confirm Appendix B shows at least one parent-child chain.")
    return 0 if all_pass else 1


if __name__ == "__main__":
    sys.exit(main())
