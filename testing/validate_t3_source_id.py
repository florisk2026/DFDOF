"""T3 — Source Identification Accuracy.

Usage
-----
    python testing/validate_t3_source_id.py state.json [state.json ...]

    # Write to CSV for comparison against ground-truth table:
    python testing/validate_t3_source_id.py *.json --csv t3_results.csv

Pass criteria (R5a)
-------------------
- Every source file in every run receives a classification (identified = True)
- No .001 file misclassified as controller_ios (cross-format check)
- Android physical correctly flagged in acquisition_method = "physical"
- Any not_identified result is printed with its source path for manual explanation
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path


def _load(path: str) -> dict:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def _acquisition_for(source_path: str, input_evidence: list[dict]) -> str | None:
    """Look up acquisition_method from input_evidence by source_path."""
    for e in input_evidence:
        if str(e.get("source_path", "")) == source_path:
            return e.get("acquisition_method")
    return None


def _validate(state_path: str) -> list[dict]:
    state = _load(state_path)
    case_id = state.get("case_id", Path(state_path).parent.name)
    input_ev = state.get("input_evidence", [])

    p1_ev = (state.get("phase_outputs", {})
                  .get("p1_provenance", {})
                  .get("identified_evidence", []))

    rows = []
    for entry in p1_ev:
        src = entry.get("source_path", "")
        identified_as = entry.get("identified_by_operator_as") or entry.get("identified_as") or "not_identified"
        identified = entry.get("identified", False)
        acq = _acquisition_for(src, input_ev)
        ext = Path(src).suffix.lower()

        # Cross-format sanity check
        issues = []
        if ext in {".001", ".e01"} and identified_as == "controller_ios":
            issues.append("IMAGE_AS_IOS")
        if identified_as == "not_identified":
            issues.append("NOT_IDENTIFIED")
        if identified_as == "controller_android" and acq and "physical" not in acq and ext in {".001", ".e01"}:
            issues.append("ANDROID_PHYSICAL_NO_PHYSICAL_ACQ")

        rows.append({
            "case_id": case_id,
            "source_file": Path(src).name,
            "source_path": src,
            "extension": ext,
            "identified": identified,
            "identified_as": identified_as,
            "acquisition_method": acq or "-",
            "issues": "|".join(issues) if issues else "OK",
        })
    return rows


def _print_results(all_rows: list[dict]) -> bool:
    all_pass = True
    by_case: dict[str, list[dict]] = {}
    for r in all_rows:
        by_case.setdefault(r["case_id"], []).append(r)

    for case_id, rows in by_case.items():
        issues = [r for r in rows if r["issues"] != "OK"]
        ok_count = len(rows) - len(issues)
        status = "PASS" if not issues else "FAIL"
        if status == "FAIL":
            all_pass = False

        print(f"\n{'='*60}")
        print(f"  Case: {case_id}  ({ok_count}/{len(rows)} sources OK)  -> {status}")
        print(f"  {'Source file':<35} {'Identified as':<30} {'Acquisition':<20} Issues")
        print(f"  {'-'*35} {'-'*30} {'-'*20} ------")
        for r in rows:
            flag = "!!" if r["issues"] != "OK" else "  "
            print(f"  {flag}{r['source_file']:<33} {r['identified_as']:<30}"
                  f" {r['acquisition_method']:<20} {r['issues']}")

    return all_pass


def main() -> int:
    ap = argparse.ArgumentParser(description="T3 — Source identification accuracy")
    ap.add_argument("state_files", nargs="+", metavar="state.json")
    ap.add_argument("--csv", metavar="OUTPUT.csv",
                    help="Write results to CSV for ground-truth comparison")
    args = ap.parse_args()

    all_rows: list[dict] = []
    for path in args.state_files:
        try:
            all_rows.extend(_validate(path))
        except Exception as exc:
            print(f"ERROR reading {path}: {exc}", file=sys.stderr)

    all_pass = _print_results(all_rows)

    if args.csv and all_rows:
        fieldnames = ["case_id", "source_file", "source_path", "extension",
                      "identified", "identified_as", "acquisition_method", "issues"]
        with open(args.csv, "w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(all_rows)
        print(f"\nCSV written to {args.csv}")
        print("Compare 'identified_as' column against your ground-truth VTO inventory table.")

    print(f"\n{'='*60}")
    total_issues = sum(1 for r in all_rows if r["issues"] != "OK")
    not_id = sum(1 for r in all_rows if "NOT_IDENTIFIED" in r["issues"])
    print(f"T3 RESULT: {'PASS' if all_pass else 'FAIL'}"
          f"  ({len(all_rows)} sources across {len(args.state_files)} cases,"
          f" {total_issues} issues, {not_id} not_identified)")
    if not_id:
        print("  not_identified sources (document with explanation):")
        for r in all_rows:
            if "NOT_IDENTIFIED" in r["issues"]:
                print(f"    {r['case_id']}: {r['source_path']}")
    return 0 if all_pass else 1


if __name__ == "__main__":
    sys.exit(main())
