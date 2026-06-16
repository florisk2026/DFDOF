"""NT4 -- Complete Parent-Child Lineage (R4)

For each state.json, verify the full SHA-256 parent->child lineage chain
from input_evidence through P5. Input evidence has no parent (root nodes).

Chain rules:
  - input_evidence: parent_sha256 must be null (root)
  - p2 parsed_evidence: parent_sha256 must point to an input_evidence sha256
  - p3 extracted_artefacts: parent_sha256 must point to an input_evidence sha256
  - p4 artefacts: parent_sha256 must point to a p3 sha256
  - p5 artefacts: parent_sha256 must point to a p4 sha256 OR a p3 sha256
                  (flight_logs skip p4 and normalise directly from p3)
  No circular links (sha256 == parent_sha256)

Usage
-----
    python testing/nt4_chain.py state.json [state.json ...]
    python testing/nt4_chain.py *.json --output pre_results/results_nt4.json
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path


def _load(path: str) -> dict:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def _sha_set(artefacts: list[dict]) -> set[str]:
    return {a["sha256"] for a in artefacts if a.get("sha256")}


def _validate_case(state_path: str) -> dict:
    s = _load(state_path)
    case_id = s.get("case_id", Path(state_path).parent.name)
    issues: list[str] = []

    # Collect all artefact sets by phase
    input_ev = s.get("input_evidence", [])
    p2_artefacts = s.get("phase_outputs", {}).get("p2_image_parsing", {}).get("parsed_evidence", [])
    p3_artefacts = s.get("phase_outputs", {}).get("p3_artefact_extraction", {}).get("extracted_artefacts", [])
    p4_artefacts = s.get("phase_outputs", {}).get("p4_decision_and_orchestration", {}).get("decision_and_orchestration_artefacts", [])
    p5_artefacts = s.get("phase_outputs", {}).get("p5_normalisation_and_anomaly_checking", {}).get("normalised_artefacts", [])

    input_shas = _sha_set(input_ev)
    p2_shas = _sha_set(p2_artefacts)
    p3_shas = _sha_set(p3_artefacts)
    p4_shas = _sha_set(p4_artefacts)
    p5_shas = _sha_set(p5_artefacts)

    # input_evidence: must have no parent
    for a in input_ev:
        if a.get("parent_sha256"):
            issues.append(f"input_evidence {a.get('sha256','?')[:16]}: has parent_sha256 but should be root")

    # p2: parent must be in input_evidence
    for a in p2_artefacts:
        p = a.get("parent_sha256")
        sha = (a.get("sha256") or "dir")[:16]
        if not p:
            issues.append(f"p2 {sha}: missing parent_sha256")
        elif p not in input_shas:
            issues.append(f"p2 {sha}: parent_sha256 {p[:16]} not in input_evidence")
        # no self-link
        if a.get("sha256") and a["sha256"] == p:
            issues.append(f"p2 {sha}: circular link (sha256 == parent_sha256)")

    # p3: parent must be in input_evidence
    for a in p3_artefacts:
        p = a.get("parent_sha256")
        sha = (a.get("sha256") or "?")[:16]
        if not p:
            issues.append(f"p3 {sha}: missing parent_sha256")
        elif p not in input_shas:
            issues.append(f"p3 {sha}: parent_sha256 {p[:16]} not in input_evidence")
        if a.get("sha256") and a["sha256"] == p:
            issues.append(f"p3 {sha}: circular link")

    # p4: parent must be in p3
    for a in p4_artefacts:
        p = a.get("parent_sha256")
        sha = (a.get("sha256") or "?")[:16]
        if not p:
            issues.append(f"p4 {sha}: missing parent_sha256")
        elif p not in p3_shas:
            issues.append(f"p4 {sha}: parent_sha256 {p[:16]} not in p3")
        if a.get("sha256") and a["sha256"] == p:
            issues.append(f"p4 {sha}: circular link")

    # p5: parent must be in p4 OR p3 (flight_logs skip p4)
    p4_or_p3 = p4_shas | p3_shas
    for a in p5_artefacts:
        p = a.get("parent_sha256")
        sha = (a.get("sha256") or "?")[:16]
        if not p:
            issues.append(f"p5 {sha}: missing parent_sha256")
        elif p not in p4_or_p3:
            issues.append(f"p5 {sha}: parent_sha256 {p[:16]} not in p4 or p3")
        if a.get("sha256") and a["sha256"] == p:
            issues.append(f"p5 {sha}: circular link")

    counts = {
        "input_evidence": len(input_ev),
        "p2": len(p2_artefacts),
        "p3": len(p3_artefacts),
        "p4": len(p4_artefacts),
        "p5": len(p5_artefacts),
    }

    return {
        "case_id": case_id,
        "state_path": state_path,
        "artefact_counts": counts,
        "issues": issues,
        "passed": len(issues) == 0,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="NT4 -- Parent-child lineage")
    ap.add_argument("state_files", nargs="+", metavar="state.json")
    ap.add_argument("--output", metavar="results.json")
    args = ap.parse_args()

    results = []
    all_pass = True
    for path in args.state_files:
        try:
            r = _validate_case(path)
            results.append(r)
            if not r["passed"]:
                all_pass = False
        except Exception as exc:
            results.append({"case_id": path, "error": str(exc), "passed": False})
            all_pass = False

    for r in results:
        print(f"\n{'='*60}")
        status = "PASS" if r.get("passed") else "FAIL"
        counts = r.get("artefact_counts", {})
        print(f"  Case: {r.get('case_id', '?')}  -> {status}")
        print(f"  Artefacts: input={counts.get('input_evidence',0)}  p3={counts.get('p3',0)}  p4={counts.get('p4',0)}  p5={counts.get('p5',0)}")
        if r.get("issues"):
            print(f"  Issues ({len(r['issues'])}):")
            for issue in r["issues"][:15]:
                print(f"    {issue}")

    print(f"\n{'='*60}")
    total_issues = sum(len(r.get("issues", [])) for r in results)
    print(f"NT4 RESULT: {'PASS' if all_pass else 'FAIL'}  ({len(results)} cases, {total_issues} issues)")

    if args.output:
        output = {
            "test": "NT4",
            "requirement": "R4",
            "description": "Parent-child lineage: complete chain from input_evidence through P5 with no broken or circular links",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "cases": results,
            "summary": "PASS" if all_pass else f"FAIL: {total_issues} linkage issues",
        }
        Path(args.output).parent.mkdir(parents=True, exist_ok=True)
        Path(args.output).write_text(json.dumps(output, indent=2), encoding="utf-8")
        print(f"\nResults written to {args.output}")

    return 0 if all_pass else 1


if __name__ == "__main__":
    sys.exit(main())
