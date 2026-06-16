"""NT6 -- All Artefacts Accounted For (R5b)

For each state.json, verify:
1. uncorrelated_artefacts in P7 contains no duplicate sha256s
2. Every P3 artefact is either:
   a. Explicitly marked uncorrelated in P7, OR
   b. Itself referenced in any accounting source, OR
   c. Has at least one P4/P5 descendant referenced in any accounting source

Accounting sources (for step 2b/2c):
  - P7 account_and_drone_analysis corroboration_sources
  - P6 flights_identified evidence_sha256 (from timeline JSON files)
  - P4 KML files (DatCon output)
  - P4 DatCon CSV files
  - P4 TXTlogToCSV CSV files

Pass criteria
-------------
- No duplicate sha256s in P7 uncorrelated_artefacts
- Every P3 artefact is accounted for (uncorrelated or referenced directly/via descendants)

Usage
-----
    python testing/nt6_correlated.py state.json [state.json ...]
    python testing/nt6_correlated.py *.json --output pre_results/results_nt6.json
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


def _strip_prefix(s: str) -> str:
    """Strip p2:/p4:/p5:/p6: prefix and :rowID suffix."""
    for prefix in ("p2:", "p4:", "p5:", "p6:"):
        if s.startswith(prefix):
            s = s[len(prefix):]
            break
    if ":" in s:
        parts = s.rsplit(":", 1)
        if parts[1].lstrip("-").isdigit():
            s = parts[0]
    return s


def _read_timeline_shas(case_dir: Path) -> set[str]:
    """Collect sha256s from all timeline JSONs:
    - flights_identified[*].evidence_sha256
    - plausibly_correlated[*] (strip 'p5:' prefix)
    - possibly_correlated[*].source_pointer (strip 'p5:'/'p4:' prefix)
    """
    shas: set[str] = set()
    p6_dir = case_dir / "p6_multisource_correlation"
    if not p6_dir.exists():
        return shas
    for tl_file in p6_dir.glob("timeline_flight*.json"):
        try:
            data = json.loads(tl_file.read_text("utf-8"))
            for fi in data.get("flights_identified", []):
                sha = fi.get("evidence_sha256")
                if sha:
                    shas.add(sha)
            for pc in data.get("plausibly_correlated", []):
                shas.add(_strip_prefix(str(pc)))
            for pc in data.get("possibly_correlated", []):
                sp = pc.get("source_pointer", "") if isinstance(pc, dict) else str(pc)
                sha = _strip_prefix(sp)
                if sha and len(sha) >= 32:
                    shas.add(sha)
        except Exception:
            pass
    return shas


def _validate_case(state_path: str) -> dict:
    s = _load(state_path)
    case_id = s.get("case_id", Path(state_path).parent.name)
    case_dir = Path(state_path).parent

    p3 = s.get("phase_outputs", {}).get("p3_artefact_extraction", {}).get("extracted_artefacts", [])
    p4 = s.get("phase_outputs", {}).get("p4_decision_and_orchestration", {}).get("decision_and_orchestration_artefacts", [])
    p5 = s.get("phase_outputs", {}).get("p5_normalisation_and_anomaly_checking", {}).get("normalised_artefacts", [])
    p7 = s.get("phase_outputs", {}).get("p7_analysis_and_validation", {})

    p3_shas = {a["sha256"] for a in p3 if a.get("sha256")}

    # --- Check 1: no duplicates in uncorrelated_artefacts ---
    uncorr_list = [u.get("evidence_sha256") for u in p7.get("uncorrelated_artefacts", [])
                   if u.get("evidence_sha256")]
    uncorr_shas = set(uncorr_list)
    uncorr_duplicates = len(uncorr_list) - len(uncorr_shas)

    # --- Build accounting set (all referenced sha256s) ---
    referenced: set[str] = set()

    # Account corroboration sources (P7)
    aad = p7.get("account_and_drone_analysis", {})
    for field_data in aad.values():
        if isinstance(field_data, dict):
            for raw in field_data.get("corroboration_sources", []):
                sha = _strip_prefix(str(raw))
                if sha and len(sha) >= 32:
                    referenced.add(sha)

    # Flights identified (all flights, matched or not)
    referenced |= _read_timeline_shas(case_dir)

    # P4 KML files
    for a in p4:
        if a.get("sha256") and str(a.get("stored_path", "")).lower().endswith(".kml"):
            referenced.add(a["sha256"])

    # P4 DatCon CSV files (drone_logs decoded via datcon)
    for a in p4:
        if (a.get("sha256") and a.get("artefact_category") == "drone_logs"
                and a.get("acquisition_method") == "datcon"):
            referenced.add(a["sha256"])

    # P4 TXTlogToCSV CSV files (flight_records decoded)
    for a in p4:
        if (a.get("sha256") and a.get("artefact_category") == "flight_records"
                and a.get("acquisition_method") == "txtlogtocsvtool"):
            referenced.add(a["sha256"])

    # --- Build forward lineage maps for P3 -> P4 -> P5 ---
    p3_to_p4: dict[str, set[str]] = {}
    for a in p4:
        p, s_ = a.get("parent_sha256"), a.get("sha256")
        if p and s_:
            p3_to_p4.setdefault(p, set()).add(s_)

    p4_to_p5: dict[str, set[str]] = {}
    p3_to_p5_direct: dict[str, set[str]] = {}
    for a in p5:
        p, s_ = a.get("parent_sha256"), a.get("sha256")
        if not p or not s_:
            continue
        if p in p3_shas:
            p3_to_p5_direct.setdefault(p, set()).add(s_)
        else:
            p4_to_p5.setdefault(p, set()).add(s_)

    # --- Check 2: every P3 sha is accounted for ---
    truly_unaccounted: list[str] = []
    sha_to_art = {a["sha256"]: a for a in p3 if a.get("sha256")}

    for sha in p3_shas:
        if sha in uncorr_shas:
            continue  # explicitly uncorrelated -- known and accounted
        if sha in referenced:
            continue  # directly referenced

        # Check P4 children
        p4_children = p3_to_p4.get(sha, set())
        if p4_children & referenced:
            continue

        # Check P5 grandchildren (via P4)
        p5_via_p4: set[str] = set()
        for p4sha in p4_children:
            p5_via_p4 |= p4_to_p5.get(p4sha, set())
        if p5_via_p4 & referenced:
            continue

        # Check P5 direct children (flight_logs bypass P4)
        p5_direct = p3_to_p5_direct.get(sha, set())
        if p5_direct & referenced:
            continue

        truly_unaccounted.append(sha)

    issues: list[str] = []
    if uncorr_duplicates > 0:
        issues.append(f"uncorrelated_artefacts has {uncorr_duplicates} duplicate sha256(s)")
    if truly_unaccounted:
        details = []
        for sha in truly_unaccounted[:5]:
            a = sha_to_art.get(sha, {})
            details.append(f"{sha[:16]}({a.get('artefact_category','?')})")
        issues.append(f"{len(truly_unaccounted)} P3 artefact(s) not accounted for: {details}")

    return {
        "case_id": case_id,
        "state_path": state_path,
        "p3_total": len(p3_shas),
        "uncorrelated_count": len(uncorr_shas),
        "referenced_count": len(referenced),
        "truly_unaccounted": len(truly_unaccounted),
        "uncorr_duplicates": uncorr_duplicates,
        "unaccounted_details": [
            {"sha": s, "category": sha_to_art.get(s, {}).get("artefact_category", "?")}
            for s in truly_unaccounted
        ],
        "issues": issues,
        "passed": len(issues) == 0,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="NT6 -- All artefacts accounted for")
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
        print(f"  Case: {r.get('case_id', '?')}  -> {status}")
        print(f"  P3 total: {r.get('p3_total','?')}  Uncorrelated: {r.get('uncorrelated_count','?')}  Truly unaccounted: {r.get('truly_unaccounted','?')}")
        if r.get("issues"):
            for issue in r["issues"]:
                print(f"  !! {issue}")

    print(f"\n{'='*60}")
    print(f"NT6 RESULT: {'PASS' if all_pass else 'FAIL'}  ({len(results)} cases)")

    if args.output:
        output = {
            "test": "NT6",
            "requirement": "R5b",
            "description": "All artefacts accounted for: every P3 artefact is uncorrelated or linked via descendants to an accounting source",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "cases": results,
            "summary": "PASS" if all_pass else "FAIL: see case issues",
        }
        Path(args.output).parent.mkdir(parents=True, exist_ok=True)
        Path(args.output).write_text(json.dumps(output, indent=2), encoding="utf-8")
        print(f"\nResults written to {args.output}")

    return 0 if all_pass else 1


if __name__ == "__main__":
    sys.exit(main())
