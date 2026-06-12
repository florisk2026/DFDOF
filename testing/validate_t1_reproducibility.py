"""T1 — Reproducibility: compare two pipeline runs of the same cases.

Usage
-----
Run the pipeline twice on the same evidence directories using different case IDs
(e.g. CASE-T1-A and CASE-T1-B) so each run's output is preserved.  Then pass
both state.json files to this script:

    python testing/validate_t1_reproducibility.py \\
        --run1 path/to/CASE-T1-A/state.json \\
        --run2 path/to/CASE-T1-B/state.json

For multiple cases pass lists in matching order:

    python testing/validate_t1_reproducibility.py \\
        --run1 caseA_r1.json caseB_r1.json \\
        --run2 caseA_r2.json caseB_r2.json

Pass criteria (R2b)
-------------------
- All non-timestamp, non-path fields in state.json identical (target 100 %)
- All timeline_flight*.json files identical (minus generated_at)
- PDF Appendix A SHA-256 hashes identical across runs (requires pdfplumber)
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

# Keys stripped before comparison because they are expected to differ.
_TS_KEYS = {"start_time", "completed_at", "hash_timestamp", "generated_at",
            "pipeline_start", "pipeline_end", "hash_note"}
# Path-like keys that will differ when case IDs differ.
_PATH_KEYS = {"stored_path", "evidence_directory", "report_path", "plots_dir",
              "source_path"}

_SHA256_RE = re.compile(r"\b[0-9a-f]{64}\b")


def _load(path: str) -> dict:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def _strip(obj, drop_keys: set[str]):
    """Recursively remove drop_keys from dicts."""
    if isinstance(obj, dict):
        return {k: _strip(v, drop_keys) for k, v in obj.items() if k not in drop_keys}
    if isinstance(obj, list):
        return [_strip(i, drop_keys) for i in obj]
    return obj


def _leaf_compare(a, b, path: str, diffs: list, total: list):
    """Recursively compare two stripped objects, recording leaf differences."""
    if isinstance(a, dict) and isinstance(b, dict):
        all_keys = set(a) | set(b)
        for k in sorted(all_keys):
            _leaf_compare(a.get(k), b.get(k), f"{path}.{k}", diffs, total)
    elif isinstance(a, list) and isinstance(b, list):
        for i, (x, y) in enumerate(zip(a, b)):
            _leaf_compare(x, y, f"{path}[{i}]", diffs, total)
        if len(a) != len(b):
            diffs.append(f"{path}: list length {len(a)} vs {len(b)}")
            total.append(path)
    else:
        total.append(path)
        if a != b:
            diffs.append(f"{path}: {repr(a)!r:.60} != {repr(b)!r:.60}")


def _compare_state(path1: str, path2: str) -> dict:
    s1 = _load(path1)
    s2 = _load(path2)
    drop = _TS_KEYS | _PATH_KEYS
    c1 = _strip(s1, drop)
    c2 = _strip(s2, drop)

    diffs: list[str] = []
    total: list[str] = []
    _leaf_compare(c1, c2, "state", diffs, total)

    total_count = len(total)
    identical = total_count - len(diffs)
    pct = f"{identical / total_count * 100:.1f}%" if total_count else "N/A"

    return {
        "run1": path1,
        "run2": path2,
        "case_id_run1": s1.get("case_id"),
        "case_id_run2": s2.get("case_id"),
        "total_fields": total_count,
        "identical_fields": identical,
        "identical_pct": pct,
        "diffs": diffs[:20],  # cap for readability
        "pass": len(diffs) == 0,
    }


def _find_timelines(state_path: str) -> list[Path]:
    """Find timeline_flight*.json next to or under the state.json directory."""
    base = Path(state_path).parent
    # Case output dir may contain p6_multisource_correlation/
    candidates = list(base.glob("p6_multisource_correlation/timeline_*.json"))
    if not candidates:
        candidates = list(base.glob("timeline_*.json"))
    return sorted(candidates)


def _compare_timelines(path1: str, path2: str) -> dict:
    tl1 = _find_timelines(path1)
    tl2 = _find_timelines(path2)

    results = []
    for t1, t2 in zip(tl1, tl2):
        d1 = _strip(_load(str(t1)), _TS_KEYS | _PATH_KEYS)
        d2 = _strip(_load(str(t2)), _TS_KEYS | _PATH_KEYS)
        match = d1 == d2
        results.append({"file": t1.name, "match": match})

    missing = abs(len(tl1) - len(tl2))
    return {
        "timelines_compared": len(results),
        "all_match": all(r["match"] for r in results),
        "missing_count": missing,
        "detail": results,
    }


def _extract_pdf_hashes(pdf_path: str) -> list[str]:
    """Extract all 64-char hex SHA-256 hashes from the Appendix A section."""
    if not _PDF_OK:
        return []
    hashes = []
    in_appendix_a = False
    with pdfplumber.open(pdf_path) as pdf:
        for page in pdf.pages:
            text = page.extract_text() or ""
            if "Appendix A" in text:
                in_appendix_a = True
            if in_appendix_a and "Appendix B" in text:
                break
            if in_appendix_a:
                hashes.extend(_SHA256_RE.findall(text.lower()))
    return list(dict.fromkeys(hashes))  # deduplicate, preserve order


def _find_pdf(state_path: str) -> str | None:
    base = Path(state_path).parent
    pdfs = list(base.glob("*.pdf"))
    return str(pdfs[0]) if pdfs else None


def _compare_pdfs(path1: str, path2: str) -> dict:
    if not _PDF_OK:
        return {"skipped": True, "reason": "pdfplumber not installed (pip install pdfplumber)"}
    pdf1 = _find_pdf(path1)
    pdf2 = _find_pdf(path2)
    if not pdf1 or not pdf2:
        return {"skipped": True, "reason": f"PDF not found (run1={pdf1}, run2={pdf2})"}
    h1 = set(_extract_pdf_hashes(pdf1))
    h2 = set(_extract_pdf_hashes(pdf2))
    only_in_1 = h1 - h2
    only_in_2 = h2 - h1
    return {
        "hashes_run1": len(h1),
        "hashes_run2": len(h2),
        "only_in_run1": sorted(only_in_1),
        "only_in_run2": sorted(only_in_2),
        "pass": len(only_in_1) == 0 and len(only_in_2) == 0,
    }


def _print_result(r: dict) -> None:
    ok = r["state"]["pass"] and r["timelines"]["all_match"]
    pdf_r = r["pdf"]
    pdf_ok = pdf_r.get("pass", False) or pdf_r.get("skipped", False)
    overall = "PASS" if ok and pdf_ok else "FAIL"

    print(f"\n{'='*60}")
    print(f"  Case:  {r['state']['case_id_run1']} vs {r['state']['case_id_run2']}")
    print(f"  State: {r['state']['identical_fields']}/{r['state']['total_fields']} fields identical"
          f" ({r['state']['identical_pct']})"
          f" -> {'PASS' if r['state']['pass'] else 'FAIL'}")
    if r["state"]["diffs"]:
        for d in r["state"]["diffs"][:10]:
            print(f"    DIFF: {d}")
        if len(r["state"]["diffs"]) > 10:
            print(f"    ... and {len(r['state']['diffs']) - 10} more differences")

    tl = r["timelines"]
    tl_status = "PASS" if tl["all_match"] and tl["missing_count"] == 0 else "FAIL"
    print(f"  Timelines: {tl['timelines_compared']} compared, all match: {tl['all_match']}"
          f", missing: {tl['missing_count']} -> {tl_status}")
    for d in tl["detail"]:
        status = "OK" if d["match"] else "DIFF"
        print(f"    {d['file']}: {status}")

    if pdf_r.get("skipped"):
        print(f"  PDF: SKIPPED — {pdf_r['reason']}")
    else:
        pdf_status = "PASS" if pdf_r.get("pass") else "FAIL"
        print(f"  PDF Appendix A: {pdf_r['hashes_run1']} hashes run1,"
              f" {pdf_r['hashes_run2']} hashes run2 -> {pdf_status}")
        if pdf_r.get("only_in_run1"):
            print(f"    Only in run1: {pdf_r['only_in_run1'][:3]}")
        if pdf_r.get("only_in_run2"):
            print(f"    Only in run2: {pdf_r['only_in_run2'][:3]}")

    print(f"  OVERALL: {overall}")


def main() -> int:
    ap = argparse.ArgumentParser(description="T1 — Reproducibility validation")
    ap.add_argument("--run1", nargs="+", required=True, metavar="STATE",
                    help="state.json path(s) from first run")
    ap.add_argument("--run2", nargs="+", required=True, metavar="STATE",
                    help="state.json path(s) from second run (same order as --run1)")
    args = ap.parse_args()

    if len(args.run1) != len(args.run2):
        print("ERROR: --run1 and --run2 must have the same number of files", file=sys.stderr)
        return 2

    all_pass = True
    for p1, p2 in zip(args.run1, args.run2):
        result = {
            "state":     _compare_state(p1, p2),
            "timelines": _compare_timelines(p1, p2),
            "pdf":       _compare_pdfs(p1, p2),
        }
        _print_result(result)
        if not result["state"]["pass"] or not result["timelines"]["all_match"]:
            all_pass = False

    print(f"\n{'='*60}")
    print(f"T1 RESULT: {'PASS' if all_pass else 'FAIL'}")
    return 0 if all_pass else 1


if __name__ == "__main__":
    sys.exit(main())
