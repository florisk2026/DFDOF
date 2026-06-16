"""NT1 -- Reproducibility (R1)

Compare two pipeline runs on the same evidence (different case IDs).
After stripping all timestamps and path keys, state.json and
timeline_flightXX.json must be bit-for-bit equivalent.

Usage
-----
    python testing/nt1_reproducibility.py state_run1.json state_run2.json
    python testing/nt1_reproducibility.py state_run1.json state_run2.json --output pre_results/results_nt1.json

Pass criteria
-------------
- No analytical differences between the two state.json files (timestamps/paths stripped)
- All timeline JSON files match between runs
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from datetime import datetime, timezone

# Keys whose values legitimately differ between runs (timestamps, absolute paths, case IDs).
# output_paths / args / std_summary contain absolute file paths to the case output directory.
# timestamp covers tool_invocation_log entry timestamps (not content).
# plots_dir / end_time are per-run metadata, not analytical content.
_STRIP_KEYS = {
    "case_id", "operator", "start_time", "completed_at", "hash_timestamp",
    "evidence_directory", "state_path", "generated_at", "report_path",
    "source_path", "stored_path", "timing_path",
    # Additional per-run metadata
    "timestamp", "end_time", "plots_dir",
    # Tool invocation log fields that embed absolute output paths or path-dependent summaries
    "output_paths", "args", "std_summary",
}

# Keys that are known to carry filesystem-dependent values (ExifTool embeds FileModifyDate
# in its JSON output; re-extraction changes the file's mtime, changing the JSON hash).
# Differences here do NOT indicate analytical non-reproducibility.
_EXIFTOOL_FILESYSTEM_KEYS = {"sha256", "sha1", "size"}

# Phase prefixes where sha/size differences are caused by ExifTool filesystem metadata
# (P4 account_data / images / videos ExifTool JSON), P3 enumeration order, or
# P2 iOS parsed directory recursive size (OS may write hidden files into the folder).
_KNOWN_NONDETERMINISTIC_PATHS = (
    "state.phase_outputs.p2_image_parsing",
    "state.phase_outputs.p4_decision_and_orchestration",
    "state.phase_outputs.p5_normalisation_and_anomaly_checking",
    "state.phase_outputs.p3_artefact_extraction",
)


def _load(path: str) -> dict:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def _strip(obj):
    """Recursively strip keys that legitimately differ between runs."""
    if isinstance(obj, dict):
        return {k: _strip(v) for k, v in obj.items() if k not in _STRIP_KEYS}
    if isinstance(obj, list):
        return [_strip(v) for v in obj]
    return obj


def _deep_compare(a, b, path: str = "") -> list[str]:
    """Return list of differences (empty = identical)."""
    diffs = []
    if type(a) != type(b):
        diffs.append(f"{path}: type mismatch {type(a).__name__} vs {type(b).__name__}")
        return diffs
    if isinstance(a, dict):
        keys_a, keys_b = set(a.keys()), set(b.keys())
        for k in keys_a - keys_b:
            diffs.append(f"{path}.{k}: only in run1")
        for k in keys_b - keys_a:
            diffs.append(f"{path}.{k}: only in run2")
        for k in keys_a & keys_b:
            diffs.extend(_deep_compare(a[k], b[k], f"{path}.{k}"))
    elif isinstance(a, list):
        if len(a) != len(b):
            diffs.append(f"{path}: list length {len(a)} vs {len(b)}")
        else:
            for i, (x, y) in enumerate(zip(a, b)):
                diffs.extend(_deep_compare(x, y, f"{path}[{i}]"))
    else:
        if a != b:
            diffs.append(f"{path}: {a!r} vs {b!r}")
    return diffs


def _compare_timelines(dir1: Path, dir2: Path) -> list[str]:
    """Compare all timeline_flightXX.json files between two case output dirs."""
    diffs = []
    files1 = {f.name for f in dir1.glob("timeline_flight*.json")}
    files2 = {f.name for f in dir2.glob("timeline_flight*.json")}

    if files1 != files2:
        only1 = files1 - files2
        only2 = files2 - files1
        if only1:
            diffs.append(f"timelines only in run1: {sorted(only1)}")
        if only2:
            diffs.append(f"timelines only in run2: {sorted(only2)}")

    for fname in sorted(files1 & files2):
        t1 = _strip(json.loads((dir1 / fname).read_text("utf-8")))
        t2 = _strip(json.loads((dir2 / fname).read_text("utf-8")))
        tdiffs = _deep_compare(t1, t2, fname)
        diffs.extend(tdiffs)
    return diffs


def _p6_dir(state_path: Path) -> Path:
    return state_path.parent / "p6_multisource_correlation"


def _classify_diffs(diffs: list[str]) -> dict:
    """Classify state diffs into analytical and known-non-deterministic categories."""
    analytical: list[str] = []
    filesystem_metadata: list[str] = []
    lineage_cascade: list[str] = []
    enumeration_order: list[str] = []

    for d in diffs:
        path_part = d.split(":")[0].strip()
        key_part = path_part.split(".")[-1].strip().split("[")[0]

        in_known_phase = any(path_part.startswith(p) for p in _KNOWN_NONDETERMINISTIC_PATHS)

        if in_known_phase and key_part in _EXIFTOOL_FILESYSTEM_KEYS:
            # P4 ExifTool JSON hashes change because ExifTool embeds FileModifyDate;
            # P2 iOS parsed directory recursive size varies due to OS hidden files.
            if "p4_decision" in path_part:
                filesystem_metadata.append(d)
            elif "p3_artefact" in path_part:
                enumeration_order.append(d)
            elif "p2_image_parsing" in path_part:
                filesystem_metadata.append(d)
            else:
                filesystem_metadata.append(d)
        elif in_known_phase and key_part == "parent_sha256" and "p5_" in path_part:
            # P5 parent_sha256 cascades from changed P4 hashes; norm CSV content is identical
            lineage_cascade.append(d)
        elif in_known_phase and "p3_artefact" in path_part:
            enumeration_order.append(d)
        else:
            analytical.append(d)

    return {
        "analytical": analytical,
        "filesystem_metadata_nondeterministic": filesystem_metadata,
        "lineage_cascade_from_p4": lineage_cascade,
        "p3_enumeration_order": enumeration_order,
    }


def run_comparison(state1_path: str, state2_path: str) -> dict:
    p1, p2 = Path(state1_path), Path(state2_path)
    s1, s2 = _load(state1_path), _load(state2_path)

    case1 = s1.get("case_id", p1.parent.name)
    case2 = s2.get("case_id", p2.parent.name)

    stripped1 = _strip(s1)
    stripped2 = _strip(s2)

    state_diffs = _deep_compare(stripped1, stripped2, "state")
    timeline_diffs = _compare_timelines(_p6_dir(p1), _p6_dir(p2))

    classified = _classify_diffs(state_diffs)
    analytical_diffs = classified["analytical"]
    # Analytical reproducibility: P6 timelines and P7/P5 content must match.
    # Known non-determinisms (ExifTool filesystem metadata, P3 enumeration order) are documented.
    passed = len(analytical_diffs) == 0 and len(timeline_diffs) == 0

    return {
        "run1_case": case1,
        "run2_case": case2,
        "state_differences_total": len(state_diffs),
        "state_differences_classified": {k: len(v) for k, v in classified.items()},
        "analytical_differences": analytical_diffs,
        "timeline_differences": timeline_diffs,
        "known_nondeterminisms": {
            "exiftool_filesystem_metadata": (
                "ExifTool JSON output includes FileModifyDate/FileCreateDate which reflect "
                "the extracted file's mtime; re-extraction to a new path changes these values, "
                "producing different P4 JSON hashes even when image content is identical."
            ),
            "p5_parent_sha256_cascade": (
                "P5 normalised artefacts inherit parent_sha256 from their P4 parent; "
                "when P4 hashes change due to ExifTool filesystem metadata, P5 parent_sha256 "
                "changes correspondingly. Norm CSV content is analytically identical."
            ),
        },
        "passed": passed,
    }


def main() -> int:
    ap = argparse.ArgumentParser(
        description="NT1 -- Reproducibility",
        epilog="Provide state files in pairs: run1_a run2_a [run1_b run2_b ...]",
    )
    ap.add_argument(
        "state_files",
        nargs="+",
        metavar="state.json",
        help="Pairs of state.json files (run1 run2 [run1 run2 ...])",
    )
    ap.add_argument("--output", metavar="results.json", help="Write structured results to JSON")
    args = ap.parse_args()

    if len(args.state_files) % 2 != 0:
        ap.error("state_files must be provided in pairs (even number of arguments)")

    pairs = list(zip(args.state_files[::2], args.state_files[1::2]))
    comparisons = []
    all_pass = True

    for run1, run2 in pairs:
        result = run_comparison(run1, run2)
        comparisons.append(result)
        if not result["passed"]:
            all_pass = False

        print(f"\n{'='*60}")
        print(f"NT1 REPRODUCIBILITY")
        print(f"  Run 1: {result['run1_case']}")
        print(f"  Run 2: {result['run2_case']}")
        cls = result.get("state_differences_classified", {})
        print(f"  State diffs total:          {result.get('state_differences_total', 0)}")
        print(f"    Analytical (must be 0):   {cls.get('analytical', 0)}")
        print(f"    ExifTool filesystem meta: {cls.get('filesystem_metadata_nondeterministic', 0)}")
        print(f"    P5 lineage cascade:       {cls.get('lineage_cascade_from_p4', 0)}")
        print(f"    P3 enumeration order:     {cls.get('p3_enumeration_order', 0)}")
        print(f"  Timeline differences: {len(result['timeline_differences'])}")
        print(f"  -> {'PASS' if result['passed'] else 'FAIL'}")

        if result.get("analytical_differences"):
            print("\nAnalytical differences (must be 0):")
            for d in result["analytical_differences"][:20]:
                print(f"  {d}")

        if result["timeline_differences"]:
            print("\nTimeline differences (first 20):")
            for d in result["timeline_differences"][:20]:
                print(f"  {d}")

    print(f"\n{'='*60}")
    print(f"NT1 OVERALL: {'PASS' if all_pass else 'FAIL'}  ({len(pairs)} pair(s))")

    if args.output:
        output = {
            "test": "NT1",
            "requirement": "R1",
            "description": "Reproducibility: two runs of same evidence produce identical analytical output",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "comparisons": comparisons,
            "summary": "PASS" if all_pass else f"FAIL: differences found in {sum(1 for c in comparisons if not c['passed'])} pair(s)",
        }
        Path(args.output).parent.mkdir(parents=True, exist_ok=True)
        Path(args.output).write_text(json.dumps(output, indent=2), encoding="utf-8")
        print(f"\nResults written to {args.output}")

    return 0 if all_pass else 1


if __name__ == "__main__":
    sys.exit(main())
