"""NT3 -- Hash Integrity (R3)

For each state.json, compute SHA-256 and SHA-1 of every input_evidence and
P3 artefact file on disk and compare with the recorded hashes.
Directories (e.g. iOS parsed folder) have null hashes and are skipped.

Usage
-----
    python testing/nt3_hash.py state.json [state.json ...]
    python testing/nt3_hash.py *.json --output pre_results/results_nt3.json

Pass criteria
-------------
- All hashes on disk match recorded hashes (no mismatches)
- All expected files exist on disk
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path


def _load(path: str) -> dict:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def _compute_hashes(file_path: Path) -> tuple[str, str]:
    """Return (sha256_hex, sha1_hex) for file, reading in 1 MB chunks."""
    h256 = hashlib.sha256()
    h1 = hashlib.sha1()
    with open(file_path, "rb") as fh:
        while True:
            chunk = fh.read(1_048_576)
            if not chunk:
                break
            h256.update(chunk)
            h1.update(chunk)
    return h256.hexdigest(), h1.hexdigest()


def _check_artefact(a: dict) -> dict | None:
    """Verify one artefact's hashes. Returns issue dict or None if OK."""
    sha256_recorded = a.get("sha256")
    sha1_recorded = a.get("sha1")

    # Directories or hash-free artefacts are skipped
    if not sha256_recorded and not sha1_recorded:
        return None

    stored_path = a.get("stored_path")
    if not stored_path:
        return {"stored_path": str(stored_path), "issue": "stored_path missing"}

    path = Path(stored_path)
    if not path.exists():
        return {"stored_path": str(stored_path), "issue": "file not found on disk"}

    if path.is_dir():
        return None  # directories skipped

    sha256_actual, sha1_actual = _compute_hashes(path)

    issues = []
    if sha256_recorded and sha256_actual != sha256_recorded:
        issues.append(f"SHA-256 mismatch: recorded={sha256_recorded} actual={sha256_actual}")
    if sha1_recorded and sha1_actual != sha1_recorded:
        issues.append(f"SHA-1 mismatch: recorded={sha1_recorded} actual={sha1_actual}")

    if issues:
        return {"stored_path": str(stored_path), "issue": "; ".join(issues)}
    return None


def _validate_case(state_path: str) -> dict:
    s = _load(state_path)
    case_id = s.get("case_id", Path(state_path).parent.name)

    all_artefacts: list[dict] = []
    all_artefacts.extend(s.get("input_evidence", []))
    p3 = s.get("phase_outputs", {}).get("p3_artefact_extraction", {}).get("extracted_artefacts", [])
    all_artefacts.extend(p3)

    checked = 0
    skipped = 0
    failures: list[dict] = []

    for a in all_artefacts:
        sha256 = a.get("sha256")
        sha1 = a.get("sha1")
        if not sha256 and not sha1:
            skipped += 1
            continue
        issue = _check_artefact(a)
        checked += 1
        if issue:
            failures.append(issue)

    passed = len(failures) == 0
    return {
        "case_id": case_id,
        "state_path": state_path,
        "artefacts_checked": checked,
        "artefacts_skipped_no_hash": skipped,
        "failures": failures,
        "passed": passed,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="NT3 -- Hash integrity")
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
        print(f"  Checked: {r.get('artefacts_checked', '?')}  Skipped(no-hash): {r.get('artefacts_skipped_no_hash', '?')}")
        if r.get("failures"):
            print(f"  FAILURES ({len(r['failures'])}):")
            for f in r["failures"][:10]:
                print(f"    {f}")

    print(f"\n{'='*60}")
    total_checked = sum(r.get("artefacts_checked", 0) for r in results)
    total_failures = sum(len(r.get("failures", [])) for r in results)
    print(f"NT3 RESULT: {'PASS' if all_pass else 'FAIL'}  "
          f"({len(results)} cases, {total_checked} files checked, {total_failures} failures)")

    if args.output:
        output = {
            "test": "NT3",
            "requirement": "R3",
            "description": "Hash integrity: SHA-256 and SHA-1 of input_evidence and P3 artefacts match disk",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "cases": results,
            "summary": "PASS" if all_pass else f"FAIL: {total_failures} hash mismatches across {len(results)} cases",
        }
        Path(args.output).parent.mkdir(parents=True, exist_ok=True)
        Path(args.output).write_text(json.dumps(output, indent=2), encoding="utf-8")
        print(f"\nResults written to {args.output}")

    return 0 if all_pass else 1


if __name__ == "__main__":
    sys.exit(main())
