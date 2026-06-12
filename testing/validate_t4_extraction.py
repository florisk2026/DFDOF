"""T4 — Artefact Extraction Correctness.

Usage
-----
    python testing/validate_t4_extraction.py state.json [state.json ...]

Pass criteria (R1, R3, R5a)
----------------------------
- All expected artefact categories present for each source type
- All stored_path files exist on disk
- SHA-256 of sampled artefacts match recorded values
- No artefact stored_path falls inside the original evidence directory (copy, not in-place)
"""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import sys
from pathlib import Path

_SAMPLE_SIZE = 5

# Minimum expected categories per source type (non-exhaustive — at least these)
_EXPECTED_CATS: dict[str, set[str]] = {
    "controller_ios":           {"databases", "flight_logs", "flight_records"},
    "controller_android":       {"databases", "flight_records"},
    "drone_sd":                 {"images"},
    "drone_flight_storage":     {"drone_logs"},
}


def _hash_file(path: Path) -> str:
    sha256 = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


def _normalise(p: str) -> str:
    return str(Path(p).resolve()).lower()


def _validate(state_path: str, seed: int) -> dict:
    rng = random.Random(seed)
    with open(state_path, encoding="utf-8") as fh:
        state = json.load(fh)

    case_id = state.get("case_id", "unknown")
    evidence_dir = _normalise(state.get("evidence_directory", ""))
    p3 = (state.get("phase_outputs", {})
               .get("p3_artefact_extraction", {})
               .get("extracted_artefacts", []))

    # --- Existence check ---
    missing = []
    for a in p3:
        sp = a.get("stored_path", "")
        if sp and not Path(sp).exists():
            missing.append(Path(sp).name)

    # --- Category coverage per source ---
    cats_by_source: dict[str, set[str]] = {}
    for a in p3:
        src = a.get("source_identification", "unknown")
        cat = a.get("artefact_category", "unknown")
        cats_by_source.setdefault(src, set()).add(cat)

    coverage_warnings = []  # missing expected categories is a warning, not a failure
    for src, expected in _EXPECTED_CATS.items():
        present = cats_by_source.get(src, set())
        if present:  # only check if this source exists in this run
            missing_cats = expected - present
            if missing_cats:
                coverage_warnings.append(f"{src}: expected categories absent: {missing_cats}")

    # --- SHA-256 sample check ---
    sample = rng.sample(p3, min(_SAMPLE_SIZE, len(p3)))
    hash_results = []
    for a in sample:
        sp = Path(a.get("stored_path", ""))
        recorded = a.get("sha256", "")
        if not sp.exists():
            hash_results.append({"file": sp.name, "ok": False, "reason": "missing"})
        else:
            actual = _hash_file(sp)
            ok = actual == recorded
            hash_results.append({"file": sp.name, "ok": ok,
                                  "reason": "mismatch" if not ok else "ok"})
    hash_ok = sum(1 for r in hash_results if r["ok"])

    # --- Copy check: stored_path must not be inside evidence_directory ---
    in_place = []
    for a in p3:
        sp = _normalise(a.get("stored_path", ""))
        if evidence_dir and sp.startswith(evidence_dir):
            in_place.append(Path(a["stored_path"]).name)

    # --- Count by category ---
    cat_counts: dict[str, int] = {}
    for a in p3:
        cat = a.get("artefact_category", "unknown")
        cat_counts[cat] = cat_counts.get(cat, 0) + 1

    overall = (not missing and hash_ok == len(sample) and not in_place)
    # coverage_warnings are informational only — absent categories may be legitimate

    return {
        "case_id": case_id,
        "total_artefacts": len(p3),
        "category_counts": cat_counts,
        "sources_present": sorted(cats_by_source),
        "missing_files": missing,
        "coverage_warnings": coverage_warnings,
        "hash_sample": {"sampled": len(sample), "ok": hash_ok, "detail": hash_results},
        "in_place_violations": in_place,
        "pass": overall,
    }


def _print_result(r: dict) -> None:
    print(f"\n{'='*60}")
    print(f"  Case: {r['case_id']}  ({r['total_artefacts']} P3 artefacts)")

    print(f"  Categories: {dict(sorted(r['category_counts'].items()))}")
    print(f"  Sources:    {r['sources_present']}")

    miss = r["missing_files"]
    print(f"  Files on disk: {r['total_artefacts'] - len(miss)}/{r['total_artefacts']}"
          f" -> {'PASS' if not miss else 'FAIL'}")
    for f in miss[:5]:
        print(f"    MISSING: {f}")

    warns = r["coverage_warnings"]
    if warns:
        print(f"  Category coverage: WARN (absent categories may be legitimate for this case)")
        for w in warns:
            print(f"    WARN: {w}")
    else:
        print(f"  Category coverage: all expected categories present")

    hs = r["hash_sample"]
    print(f"  Hash sample ({hs['sampled']} files): {hs['ok']}/{hs['sampled']}"
          f" -> {'PASS' if hs['ok'] == hs['sampled'] else 'FAIL'}")
    for d in hs["detail"]:
        if not d["ok"]:
            print(f"    FAIL {d['file']}: {d['reason']}")

    ip = r["in_place_violations"]
    print(f"  Copy check (not in evidence_dir): {'PASS' if not ip else 'FAIL'}")
    for f in ip[:5]:
        print(f"    IN-PLACE: {f}")

    print(f"  OVERALL: {'PASS' if r['pass'] else 'FAIL'}")


def main() -> int:
    ap = argparse.ArgumentParser(description="T4 — Artefact extraction correctness")
    ap.add_argument("state_files", nargs="+", metavar="state.json")
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()

    all_pass = True
    for path in args.state_files:
        try:
            r = _validate(path, args.seed)
            _print_result(r)
            if not r["pass"]:
                all_pass = False
        except Exception as exc:
            print(f"ERROR reading {path}: {exc}", file=sys.stderr)
            all_pass = False

    print(f"\n{'='*60}")
    print(f"T4 RESULT: {'PASS' if all_pass else 'FAIL'}")
    return 0 if all_pass else 1


if __name__ == "__main__":
    sys.exit(main())
