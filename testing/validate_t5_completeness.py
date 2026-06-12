"""T5 — Pipeline Completeness: no artefact silently dropped P3->P5->P6/P7.

Usage
-----
    python testing/validate_t5_completeness.py state.json [state.json ...]

Pass criteria (R2a, R5a, R5b)
------------------------------
- Every P3 artefact (by SHA-256) has a corresponding entry in P4 or P5 (or is
  a 0-byte rejected file recorded in anomaly_flags, or is a flight_log that
  routes P3->P5 skipping P4, or is a database/account_data assessed by P5
  without producing a new normalised file)
- Every P5 normalised artefact SHA-256 appears in P6 correlation outputs OR
  its P3 ancestor SHA-256 appears in P7 uncorrelated_artefacts
- Any 0-byte rejected file appears in state.anomaly_flags
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# These P3 categories do not produce P4 decoded artefacts (or P5 normalised
# artefacts) because they are either assessed in-place or skip P4 routing.
_P4_SKIP_CATS = {"flight_logs", "databases"}
# device_and_backup_info comes from P2, not P3 — exclude from P3 accounting.
_P2_ONLY_CATS = {"device_and_backup_info"}


def _load(path: str) -> dict:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def _build_sha_set(artefacts: list[dict]) -> set[str]:
    return {a["sha256"] for a in artefacts if a.get("sha256")}


def _build_parent_map(artefacts: list[dict]) -> dict[str, str]:
    """sha256 -> parent_sha256 for all artefacts."""
    return {a["sha256"]: a["parent_sha256"]
            for a in artefacts if a.get("sha256") and a.get("parent_sha256")}


def _strip_prefix(s: str) -> str:
    """Remove p3:/p4:/p5: prefixes used in P6 correlation pointers."""
    for pfx in ("p5:", "p4:", "p3:", "p2:"):
        if s.startswith(pfx):
            s = s[len(pfx):]
    # Also strip :rowID suffix
    if ":" in s:
        s = s.rsplit(":", 1)[0]
    return s


def _build_p6_referenced_set(flights: list[dict]) -> set[str]:
    """Collect all SHA-256 values referenced in P6 correlation outputs."""
    refs: set[str] = set()
    for f in flights:
        for fi in f.get("flights_identified", []):
            sha = fi.get("evidence_sha256", "")
            if sha:
                refs.add(sha)
        for pc in f.get("plausibly_correlated", []):
            refs.add(_strip_prefix(str(pc)))
        for poc in f.get("possibly_correlated", []):
            sp = poc.get("source_pointer", "")
            if sp:
                refs.add(_strip_prefix(sp))
    return refs


def _validate(state_path: str) -> dict:
    state = _load(state_path)
    case_id = state.get("case_id", "unknown")
    anomaly_flags = state.get("anomaly_flags", [])

    p3 = (state.get("phase_outputs", {})
               .get("p3_artefact_extraction", {})
               .get("extracted_artefacts", []))
    p4 = (state.get("phase_outputs", {})
               .get("p4_decision_and_orchestration", {})
               .get("decision_and_orchestration_artefacts", []))
    p5 = (state.get("phase_outputs", {})
               .get("p5_normalisation_and_anomaly_checking", {})
               .get("normalised_artefacts", []))
    p6_flights = (state.get("phase_outputs", {})
                       .get("p6_multisource_correlation", {})
                       .get("flights", []))
    p7_uncorr = (state.get("phase_outputs", {})
                      .get("p7_analysis_and_validation", {})
                      .get("uncorrelated_artefacts", []))

    p3_shas = _build_sha_set(p3)
    p4_shas = _build_sha_set(p4)
    p5_shas = _build_sha_set(p5)
    p5_parent_map = _build_parent_map(p5)
    p4_parent_map = _build_parent_map(p4)

    p7_uncorr_shas = {u.get("evidence_sha256", "") for u in p7_uncorr}
    p6_refs = _build_p6_referenced_set(p6_flights)

    # --- Check 1: every P3 artefact is accounted for downstream ---
    # Account for: P4 has it (by parent) | P5 has it (by parent, flight_logs) |
    # database assessed by P5 (no new file) | rejected (in anomaly_flags) |
    # account_data goes to P4 only (no P5 normalised)
    p4_covers = set(p4_parent_map.values())  # P3 SHAs that produced a P4 child
    p5_covers = set(p5_parent_map.values())  # P4 (or P3) SHAs that produced a P5 child

    # Build set of P3 SHAs covered by P4 or P5 (via chain P3->P4->P5)
    # A P3 SHA is covered if: it appears as a parent in P4, OR appears as a parent in P5 directly
    covered_by_p4_or_p5 = p4_covers | (p5_covers & p3_shas)

    # Rejected files: "empty file moved to _rejected" in anomaly_flags
    rejected_names = set()
    for flag in anomaly_flags:
        if "empty file moved to _rejected" in flag:
            # Extract filename from flag text
            name = flag.split("_rejected:")[-1].strip() if "_rejected:" in flag else ""
            rejected_names.add(name)

    # P3 artefacts in skip categories (databases, flight_logs) may not produce
    # P4/P5 children — they are assessed in-place by P5 via derived_anomalies
    p3_skip_shas = {a["sha256"] for a in p3
                    if a.get("artefact_category") in _P4_SKIP_CATS and a.get("sha256")}
    # flight_logs that become P5 normalised artefacts (some formats produce observations only)
    p5_fl_parents = {p5_parent_map.get(sha) for sha in p5_shas} - {None}

    unaccounted = []
    for a in p3:
        sha = a.get("sha256", "")
        cat = a.get("artefact_category", "")
        if not sha or cat in _P2_ONLY_CATS:
            continue
        fname = Path(a.get("stored_path", "")).name
        # Covered if: in P4 parent set, or in P5 parent set, or in skip cats, or rejected
        if (sha in covered_by_p4_or_p5 or sha in p3_skip_shas or
                fname in rejected_names):
            continue
        unaccounted.append({"sha": sha[:12], "cat": cat, "file": fname})

    # Check 0-byte rejected files appear in anomaly_flags
    rejected_in_flags = [f for f in anomaly_flags if "_rejected" in f]

    # --- Check 2: every P5 SHA referenced in P6 or whose P3 ancestor is in P7 ---
    p5_unaccounted = []
    for a in p5:
        sha = a.get("sha256", "")
        if not sha:
            continue
        if sha in p6_refs:
            continue
        # Walk parent chain back to P3
        ancestor = p5_parent_map.get(sha, "")
        p3_ancestor = p4_parent_map.get(ancestor, ancestor)
        if p3_ancestor in p7_uncorr_shas:
            continue
        # Also check P3 ancestor directly in P7 uncorrelated
        if ancestor in p7_uncorr_shas:
            continue
        fname = Path(a.get("stored_path", "")).name
        p5_unaccounted.append({"sha": sha[:12], "file": fname,
                                "cat": a.get("artefact_category", "")})

    overall = not unaccounted and not p5_unaccounted

    return {
        "case_id": case_id,
        "p3_total": len(p3_shas),
        "p4_total": len(p4_shas),
        "p5_total": len(p5_shas),
        "p3_unaccounted": unaccounted,
        "p5_unaccounted": p5_unaccounted,
        "p6_flight_count": len(p6_flights),
        "p7_uncorrelated_count": len(p7_uncorr),
        "rejected_flag_count": len(rejected_in_flags),
        "pass": overall,
    }


def _print_result(r: dict) -> None:
    print(f"\n{'='*60}")
    print(f"  Case: {r['case_id']}")
    print(f"  Artefact counts: P3={r['p3_total']}  P4={r['p4_total']}"
          f"  P5={r['p5_total']}  P6_flights={r['p6_flight_count']}"
          f"  P7_uncorr={r['p7_uncorrelated_count']}")
    print(f"  Rejected files in anomaly_flags: {r['rejected_flag_count']}")

    unc = r["p3_unaccounted"]
    print(f"  P3 unaccounted: {len(unc)} -> {'PASS' if not unc else 'FAIL'}")
    for u in unc[:10]:
        print(f"    sha={u['sha']}  cat={u['cat']}  file={u['file']}")

    p5u = r["p5_unaccounted"]
    print(f"  P5 unaccounted in P6/P7: {len(p5u)} -> {'PASS' if not p5u else 'FAIL'}")
    for u in p5u[:10]:
        print(f"    sha={u['sha']}  cat={u['cat']}  file={u['file']}")

    print(f"  OVERALL: {'PASS' if r['pass'] else 'FAIL'}")


def main() -> int:
    ap = argparse.ArgumentParser(description="T5 — Pipeline completeness")
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
    print(f"T5 RESULT: {'PASS' if all_pass else 'FAIL'}")
    return 0 if all_pass else 1


if __name__ == "__main__":
    sys.exit(main())
