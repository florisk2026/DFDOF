"""Manual Test 5 (MT5) -- Correct Identification (R5a)

For each state.json, extract:
- From input_evidence: source_path, source_identification, acquisition_method
- From p1_provenance.identified_evidence: source_path, identified_as (operator override if set)

Outputs a structured report and optional CSV for manual review.
The investigator manually verifies classification correctness against the
known VTO inventory.

Usage
-----
    python testing/mt5_id.py state.json [state.json ...]
    python testing/mt5_id.py *.json --csv mt5_identification.csv --output pre_results/results_mt5.json
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
from datetime import datetime, timezone
from pathlib import Path


def _load(path: str) -> dict:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def _validate_case(state_path: str) -> dict:
    s = _load(state_path)
    case_id = s.get("case_id", Path(state_path).parent.name)

    input_ev = {str(e.get("source_path")): e for e in s.get("input_evidence", [])}
    p1_ev = (s.get("phase_outputs", {})
              .get("p1_provenance", {})
              .get("identified_evidence", []))

    sources = []
    issues = []
    for entry in p1_ev:
        src = str(entry.get("source_path", ""))
        # Take operator override if populated, else identified_as
        identified_as = (entry.get("identified_by_operator_as") or
                         entry.get("identified_as") or "not_identified")
        input_record = input_ev.get(src, {})
        acq = input_record.get("acquisition_method", "-")
        ext = Path(src).suffix.lower()

        flags = []
        if identified_as == "not_identified":
            flags.append("NOT_IDENTIFIED")
        if ext in {".001", ".e01"} and identified_as == "controller_ios":
            flags.append("IMAGE_AS_IOS")
        if ext in {".001", ".e01"} and identified_as == "controller_android" and "physical" not in (acq or ""):
            flags.append("ANDROID_PHYSICAL_NO_PHYSICAL_ACQ")

        if flags:
            issues.extend([f"{Path(src).name}: {f}" for f in flags])

        sources.append({
            "case_id": case_id,
            "source_file": Path(src).name,
            "source_path": src,
            "extension": ext,
            "identified_as": identified_as,
            "acquisition_method": acq or "-",
            "flags": "|".join(flags) if flags else "OK",
        })

    return {
        "case_id": case_id,
        "state_path": state_path,
        "sources": sources,
        "issues": issues,
        "note": "Manual verification required: compare identified_as against ground truth",
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="MT5 -- Source identification (for manual review)")
    ap.add_argument("state_files", nargs="+", metavar="state.json")
    ap.add_argument("--csv", metavar="OUTPUT.csv", help="Write flat CSV for manual ground-truth comparison")
    ap.add_argument("--output", metavar="results.json")
    args = ap.parse_args()

    all_results = []
    all_rows: list[dict] = []

    for path in args.state_files:
        try:
            r = _validate_case(path)
            all_results.append(r)
            all_rows.extend(r["sources"])
        except Exception as exc:
            all_results.append({"case_id": path, "error": str(exc)})

    # Print summary
    for r in all_results:
        print(f"\n{'='*60}")
        print(f"  Case: {r.get('case_id', '?')}")
        for src in r.get("sources", []):
            flag_str = f"  [{src['flags']}]" if src["flags"] != "OK" else ""
            print(f"    {src['source_file']:<45} {src['identified_as']:<30} {src['acquisition_method']}{flag_str}")
        if r.get("issues"):
            print(f"  Auto-detected issues: {r['issues']}")

    print(f"\n{'='*60}")
    print(f"MT5 NOTE: No automated pass/fail -- manual verification required.")
    print(f"Total sources: {len(all_rows)} across {len(all_results)} cases")
    auto_issues = sum(len(r.get("issues", [])) for r in all_results)
    if auto_issues:
        print(f"Auto-detected flag issues: {auto_issues} (see above)")

    if args.csv:
        fields = ["case_id", "source_file", "source_path", "extension",
                  "identified_as", "acquisition_method", "flags"]
        with open(args.csv, "w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=fields, extrasaction="ignore")
            writer.writeheader()
            writer.writerows(all_rows)
        print(f"\nCSV written to {args.csv}")

    if args.output:
        output = {
            "test": "MT5",
            "requirement": "R5a",
            "description": "Source identification: classification and acquisition method per evidence source",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "cases": all_results,
            "summary": (f"MANUAL REVIEW REQUIRED: {len(all_rows)} sources across {len(all_results)} cases"
                        + (f"; {auto_issues} auto-detected flag issues" if auto_issues else "")),
        }
        Path(args.output).parent.mkdir(parents=True, exist_ok=True)
        Path(args.output).write_text(json.dumps(output, indent=2), encoding="utf-8")
        print(f"Results written to {args.output}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
