"""Cleanup extracted raw media files after validation to free disk space.

After running all validation scripts for a case, this script removes the large
raw extracted files (videos and images from P3) while preserving all analysis
outputs needed for the thesis:

KEPT (small, needed for analysis):
  - state.json
  - *.pdf (forensic report)
  - p6_multisource_correlation/timeline_*.json
  - p5_normalisation_and_anomaly_checking/**/*.csv (normalised CSVs)
  - p4_decision_and_orchestration/**/*.csv  (DatCon/TXTlogToCSV outputs)
  - p4_decision_and_orchestration/**/*.kml  (DatCon KML tracks)
  - p4_decision_and_orchestration/**/*_exif.json (ExifTool sidecars, small)
  - timing_*.json

DELETED (large, only needed during active validation):
  - p3_artefact_extraction/**/videos/**   (*.mp4, *.mov)
  - p3_artefact_extraction/**/images/**   (*.jpg, *.jpeg, *.png, *.thm, *.thumbnail)
  - p3_artefact_extraction/**/drone_logs/ (large .DAT files, decoded by DatCon already)
  - p3_artefact_extraction/**/flight_logs/**   (raw .txt/.dat logs, already in state)
  - p3_artefact_extraction/**/flight_records/**  (raw .txt, decoded by TXTlogToCSV)
  - p3_artefact_extraction/**/databases/**  (SQLite .db files)
  - p3_artefact_extraction/**/account_data/**  (raw plist/xml/json)

Usage
-----
    # Preview what will be deleted (dry run, no files removed):
    python testing/cleanup_case.py ~/Documents/dfdof_output/CASE-X

    # Actually delete:
    python testing/cleanup_case.py ~/Documents/dfdof_output/CASE-X --confirm

    # Clean all cases in the output directory:
    python testing/cleanup_case.py ~/Documents/dfdof_output --all --confirm

IMPORTANT: Run all validation scripts BEFORE running this script.
After cleanup, T4 hash verification will fail (files gone) — that is expected.
"""

from __future__ import annotations

import argparse
import shutil
import sys
from pathlib import Path

# Directories inside p3_artefact_extraction to delete entirely
_P3_DELETE_SUBDIRS = {
    "videos",
    "images",
    "drone_logs",
    "flight_logs",
    "flight_records",
    "databases",
    "account_data",
}


def _find_p3_dirs(case_dir: Path) -> list[Path]:
    """Find all p3 category subdirectories to delete."""
    p3_root = case_dir / "p3_artefact_extraction"
    if not p3_root.exists():
        return []
    targets = []
    # p3_root / source_id / category/
    for source_dir in p3_root.iterdir():
        if not source_dir.is_dir():
            continue
        for cat_dir in source_dir.iterdir():
            if cat_dir.is_dir() and cat_dir.name in _P3_DELETE_SUBDIRS:
                targets.append(cat_dir)
    return sorted(targets)


def _dir_size_mb(path: Path) -> float:
    total = sum(f.stat().st_size for f in path.rglob("*") if f.is_file())
    return total / (1024 * 1024)


def _cleanup_case(case_dir: Path, confirm: bool) -> dict:
    if not case_dir.is_dir():
        return {"case_dir": str(case_dir), "error": "not a directory", "freed_mb": 0}

    state_json = case_dir / "state.json"
    if not state_json.exists():
        return {"case_dir": str(case_dir), "error": "no state.json found", "freed_mb": 0}

    targets = _find_p3_dirs(case_dir)
    if not targets:
        return {"case_dir": str(case_dir), "targets": [], "freed_mb": 0.0,
                "status": "nothing to clean"}

    total_mb = sum(_dir_size_mb(t) for t in targets)

    print(f"\n  Case: {case_dir.name}")
    print(f"  P3 directories to delete ({len(targets)}, ~{total_mb:.0f} MB):")
    for t in targets:
        mb = _dir_size_mb(t)
        file_count = sum(1 for _ in t.rglob("*") if _.is_file())
        print(f"    {t.parent.name}/{t.name}/  ({file_count} files, {mb:.0f} MB)")

    if not confirm:
        print("  DRY RUN -- no files deleted. Add --confirm to actually delete.")
        return {"case_dir": str(case_dir), "targets": [str(t) for t in targets],
                "freed_mb": total_mb, "status": "dry_run"}

    for target in targets:
        shutil.rmtree(target)

    print(f"  Deleted. Freed ~{total_mb:.0f} MB.")
    return {"case_dir": str(case_dir), "targets": [str(t) for t in targets],
            "freed_mb": total_mb, "status": "deleted"}


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Clean up extracted raw media files after validation"
    )
    ap.add_argument("case_dirs", nargs="+", metavar="CASE_DIR",
                    help="Case output directory (e.g. ~/Documents/dfdof_output/CASE-X)")
    ap.add_argument("--confirm", action="store_true",
                    help="Actually delete files (default is dry run)")
    ap.add_argument("--all", action="store_true", dest="scan_all",
                    help="Treat each positional arg as a root dir and scan for all case subdirs")
    args = ap.parse_args()

    dirs: list[Path] = []
    for d in args.case_dirs:
        p = Path(d).expanduser()
        if args.scan_all:
            # Scan subdirectories
            dirs.extend(sorted(sub for sub in p.iterdir()
                               if sub.is_dir() and (sub / "state.json").exists()))
        else:
            dirs.append(p)

    if not dirs:
        print("No case directories found.", file=sys.stderr)
        return 2

    total_freed = 0.0
    for case_dir in dirs:
        r = _cleanup_case(case_dir, args.confirm)
        total_freed += r.get("freed_mb", 0)

    print(f"\n{'='*60}")
    action = "Would free" if not args.confirm else "Freed"
    print(f"  {action} ~{total_freed:.0f} MB across {len(dirs)} case(s)")
    if not args.confirm:
        print("  Re-run with --confirm to actually delete.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
