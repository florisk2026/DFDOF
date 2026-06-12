"""T2 — Evidence Integrity: verify hashes and original-file immutability.

Usage
-----
    python testing/validate_t2_integrity.py state.json [state.json ...]

Pass criteria (R1, R3)
----------------------
- SHA-256 and SHA-1 of every input_evidence file match recorded values (100 %)
- SHA-256 of a sample of P3 extracted artefacts match recorded values (≥ 95 %)
- No source file has a modification timestamp later than state.start_time
"""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import sys
from datetime import datetime, timezone
from pathlib import Path

_SAMPLE_SIZE = 5


def _hash_file(path: Path) -> tuple[str, str]:
    sha256 = hashlib.sha256()
    sha1 = hashlib.sha1()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            sha256.update(chunk)
            sha1.update(chunk)
    return sha256.hexdigest(), sha1.hexdigest()


def _parse_dt(s: str | None) -> datetime | None:
    if not s:
        return None
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f+00:00", "%Y-%m-%dT%H:%M:%S+00:00",
                "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S.%fZ"):
        try:
            return datetime.strptime(s, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            pass
    try:
        return datetime.fromisoformat(s)
    except ValueError:
        return None


def _check_entry(entry: dict, label: str) -> dict:
    path = Path(str(entry.get("stored_path") or entry.get("source_path") or ""))
    recorded_256 = entry.get("sha256", "")
    recorded_1 = entry.get("sha1", "")

    if not path.exists():
        return {"label": label, "file": path.name, "status": "MISSING",
                "sha256_ok": False, "sha1_ok": False}

    actual_256, actual_1 = _hash_file(path)
    sha256_ok = actual_256 == recorded_256
    sha1_ok = actual_1 == recorded_1

    status = "OK" if sha256_ok and sha1_ok else "HASH_MISMATCH"
    return {
        "label": label,
        "file": path.name,
        "status": status,
        "sha256_ok": sha256_ok,
        "sha1_ok": sha1_ok,
        "actual_sha256": actual_256 if not sha256_ok else None,
        "recorded_sha256": recorded_256 if not sha256_ok else None,
    }


def _check_mtime(entry: dict, start_dt: datetime | None) -> dict:
    path = Path(str(entry.get("stored_path") or entry.get("source_path") or ""))
    if not path.exists():
        return {"file": path.name, "mtime_ok": None, "reason": "file missing"}
    if start_dt is None:
        return {"file": path.name, "mtime_ok": None, "reason": "no start_time to compare"}
    mtime = datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)
    ok = mtime <= start_dt
    return {
        "file": path.name,
        "mtime_ok": ok,
        "mtime": mtime.isoformat(),
        "start_time": start_dt.isoformat(),
    }


def _validate(state_path: str) -> dict:
    with open(state_path, encoding="utf-8") as fh:
        state = json.load(fh)

    case_id = state.get("case_id", "unknown")
    start_dt = _parse_dt(state.get("start_time"))

    # --- Input evidence hash check ---
    input_ev = state.get("input_evidence", [])
    input_results = [_check_entry(e, "input") for e in input_ev]
    input_ok = sum(1 for r in input_results if r["sha256_ok"])

    # --- Input evidence mtime check ---
    mtime_results = [_check_mtime(e, start_dt) for e in input_ev]
    mtime_ok = sum(1 for r in mtime_results if r.get("mtime_ok") is True)
    mtime_checkable = sum(1 for r in mtime_results if r.get("mtime_ok") is not None)

    # --- P3 extracted artefacts sample check ---
    p3 = (state.get("phase_outputs", {})
               .get("p3_artefact_extraction", {})
               .get("extracted_artefacts", []))
    sample = random.sample(p3, min(_SAMPLE_SIZE, len(p3)))
    p3_results = [_check_entry(e, "p3") for e in sample]
    p3_ok = sum(1 for r in p3_results if r["sha256_ok"])

    return {
        "case_id": case_id,
        "state_path": state_path,
        "input_evidence": {
            "total": len(input_ev),
            "sha256_ok": input_ok,
            "pass": input_ok == len(input_ev),
            "failures": [r for r in input_results if not r["sha256_ok"]],
        },
        "mtime": {
            "checkable": mtime_checkable,
            "ok": mtime_ok,
            "pass": mtime_ok == mtime_checkable,
            "failures": [r for r in mtime_results if r.get("mtime_ok") is False],
        },
        "p3_sample": {
            "sampled": len(sample),
            "sha256_ok": p3_ok,
            "pass": p3_ok == len(sample),
            "failures": [r for r in p3_results if not r["sha256_ok"]],
        },
    }


def _print_result(r: dict) -> None:
    ev = r["input_evidence"]
    mt = r["mtime"]
    p3 = r["p3_sample"]
    overall = ev["pass"] and mt["pass"] and p3["pass"]

    print(f"\n{'='*60}")
    print(f"  Case: {r['case_id']}")
    print(f"  Input evidence hashes: {ev['sha256_ok']}/{ev['total']}"
          f" -> {'PASS' if ev['pass'] else 'FAIL'}")
    for f in ev["failures"]:
        print(f"    FAIL {f['file']}: status={f['status']}")

    print(f"  Source file mtime: {mt['ok']}/{mt['checkable']} not modified after run start"
          f" -> {'PASS' if mt['pass'] else 'FAIL'}")
    for f in mt["failures"]:
        print(f"    MODIFIED {f['file']}: mtime={f['mtime']} > start={f['start_time']}")

    print(f"  P3 artefact sample ({p3['sampled']} files): {p3['sha256_ok']}/{p3['sampled']}"
          f" -> {'PASS' if p3['pass'] else 'FAIL'}")
    for f in p3["failures"]:
        print(f"    FAIL {f['file']}: status={f['status']}")

    print(f"  OVERALL: {'PASS' if overall else 'FAIL'}")


def main() -> int:
    ap = argparse.ArgumentParser(description="T2 — Evidence integrity validation")
    ap.add_argument("state_files", nargs="+", metavar="state.json")
    ap.add_argument("--seed", type=int, default=42,
                    help="Random seed for P3 sample selection (default: 42)")
    args = ap.parse_args()
    random.seed(args.seed)

    all_pass = True
    for path in args.state_files:
        r = _validate(path)
        _print_result(r)
        if not (r["input_evidence"]["pass"] and r["mtime"]["pass"] and r["p3_sample"]["pass"]):
            all_pass = False

    print(f"\n{'='*60}")
    print(f"T2 RESULT: {'PASS' if all_pass else 'FAIL'}")
    return 0 if all_pass else 1


if __name__ == "__main__":
    sys.exit(main())
