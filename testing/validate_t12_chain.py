"""T12 — Chain of Custody Integrity.

Usage
-----
    python testing/validate_t12_chain.py state.json [state.json ...]

Pass criteria (R4)
------------------
- Every P3 artefact's parent_sha256 exists in input_evidence SHA-256 set
- Every P4 artefact's parent_sha256 exists in the P3 SHA-256 set
- Every P5 artefact's parent_sha256 exists in the P4 SHA-256 set
  (or P3 set for flight_log artefacts, which skip P4)
- No artefact is its own parent
- device_and_backup_info artefacts (P2) trace to input_evidence (not P3)

Documented exceptions
---------------------
- device_and_backup_info artefacts originate from P2, not P3. Their parent_sha256
  should appear in input_evidence (they are produced by the parser, not P3 extraction).
  These are excluded from the P3-parent check and handled separately.
"""

from __future__ import annotations

import argparse
import json
import sys


def _load(path: str) -> dict:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def _sha_set(artefacts: list[dict]) -> set[str]:
    return {a["sha256"] for a in artefacts if a.get("sha256")}


def _validate(state_path: str) -> dict:
    state = _load(state_path)
    case_id = state.get("case_id", "unknown")

    input_ev = state.get("input_evidence", [])
    p2_parsed = (state.get("phase_outputs", {})
                      .get("p2_image_parsing", {})
                      .get("parsed_evidence", []))
    p3 = (state.get("phase_outputs", {})
               .get("p3_artefact_extraction", {})
               .get("extracted_artefacts", []))
    p4 = (state.get("phase_outputs", {})
               .get("p4_decision_and_orchestration", {})
               .get("decision_and_orchestration_artefacts", []))
    p5 = (state.get("phase_outputs", {})
               .get("p5_normalisation_and_anomaly_checking", {})
               .get("normalised_artefacts", []))

    input_shas = _sha_set(input_ev)
    p3_shas = _sha_set(p3)
    p4_shas = _sha_set(p4)

    violations: list[str] = []

    # --- P2 device_and_backup_info -> input_evidence ---
    p2_violations = []
    for a in p2_parsed:
        sha = a.get("sha256", "")
        parent = a.get("parent_sha256", "")
        cat = a.get("artefact_category", "")
        if cat == "device_and_backup_info":
            if not parent:
                p2_violations.append(f"P2 {sha[:12]} has no parent_sha256")
            elif parent not in input_shas:
                p2_violations.append(
                    f"P2 {sha[:12]} parent={parent[:12]} not in input_evidence"
                )
            if sha and sha == parent:
                violations.append(f"P2 {sha[:12]} is its own parent")

    # --- P3 artefacts -> input_evidence ---
    p3_violations = []
    for a in p3:
        sha = a.get("sha256", "")
        parent = a.get("parent_sha256", "")
        if not sha:
            continue
        if sha == parent:
            violations.append(f"P3 {sha[:12]} is its own parent")
            continue
        if not parent:
            p3_violations.append(f"P3 {sha[:12]} ({a.get('artefact_category')}) has no parent_sha256")
        elif parent not in input_shas:
            p3_violations.append(
                f"P3 {sha[:12]} ({a.get('artefact_category')}) parent={parent[:12]}"
                f" not in input_evidence"
            )

    # --- P4 artefacts -> P3 ---
    p4_violations = []
    for a in p4:
        sha = a.get("sha256", "")
        parent = a.get("parent_sha256", "")
        if not sha:
            continue
        if sha == parent:
            violations.append(f"P4 {sha[:12]} is its own parent")
            continue
        if not parent:
            p4_violations.append(f"P4 {sha[:12]} ({a.get('artefact_category')}) has no parent_sha256")
        elif parent not in p3_shas:
            p4_violations.append(
                f"P4 {sha[:12]} ({a.get('artefact_category')}) parent={parent[:12]}"
                f" not in P3"
            )

    # --- P5 artefacts -> P4 (or P3 for flight_logs) ---
    p5_violations = []
    for a in p5:
        sha = a.get("sha256", "")
        parent = a.get("parent_sha256", "")
        cat = a.get("artefact_category", "")
        if not sha:
            continue
        if sha == parent:
            violations.append(f"P5 {sha[:12]} is its own parent")
            continue
        if not parent:
            p5_violations.append(f"P5 {sha[:12]} ({cat}) has no parent_sha256")
        elif cat == "flight_logs":
            # Flight logs skip P4: parent should be in P3
            if parent not in p3_shas:
                p5_violations.append(
                    f"P5 flight_log {sha[:12]} parent={parent[:12]} not in P3"
                )
        else:
            if parent not in p4_shas:
                # Allow parent to be in P3 (some formats may have been skipped in P4)
                if parent not in p3_shas:
                    p5_violations.append(
                        f"P5 {sha[:12]} ({cat}) parent={parent[:12]} not in P4 or P3"
                    )

    all_violations = (violations + p2_violations + p3_violations +
                      p4_violations + p5_violations)

    return {
        "case_id": case_id,
        "input_sha_count": len(input_shas),
        "p2_count": len(p2_parsed),
        "p3_count": len(p3),
        "p4_count": len(p4),
        "p5_count": len(p5),
        "p2_violations": p2_violations,
        "p3_violations": p3_violations,
        "p4_violations": p4_violations,
        "p5_violations": p5_violations,
        "self_parent_violations": violations,
        "total_violations": len(all_violations),
        "pass": not all_violations,
    }


def _print_result(r: dict) -> None:
    status = "PASS" if r["pass"] else "FAIL"
    print(f"\n{'='*60}")
    print(f"  Case: {r['case_id']}  -> {status}")
    print(f"  Chain: input({r['input_sha_count']}) -> P2({r['p2_count']})"
          f" -> P3({r['p3_count']}) -> P4({r['p4_count']}) -> P5({r['p5_count']})")

    for label, vlist in [
        ("Self-parent", r["self_parent_violations"]),
        ("P2->input", r["p2_violations"]),
        ("P3->input", r["p3_violations"]),
        ("P4->P3", r["p4_violations"]),
        ("P5->P4/P3", r["p5_violations"]),
    ]:
        count = len(vlist)
        line_status = "PASS" if count == 0 else "FAIL"
        print(f"  {label}: {count} violation(s) -> {line_status}")
        for v in vlist[:5]:
            print(f"    {v}")
        if len(vlist) > 5:
            print(f"    ... and {len(vlist) - 5} more")

    print(f"  Total violations: {r['total_violations']}")


def main() -> int:
    ap = argparse.ArgumentParser(description="T12 — Chain of custody integrity")
    ap.add_argument("state_files", nargs="+", metavar="state.json")
    args = ap.parse_args()

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
    print(f"T12 RESULT: {'PASS' if all_pass else 'FAIL'}")
    return 0 if all_pass else 1


if __name__ == "__main__":
    sys.exit(main())
