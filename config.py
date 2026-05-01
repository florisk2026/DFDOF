"""Central configuration for DFDOF prototype 1.

Keep the forensic decisions in one place so the rest of the pipeline stays
deterministic, portable, and easy to audit.
"""

from __future__ import annotations

import os
from pathlib import Path


def _env_path(name: str, default: str) -> Path:
	"""Resolve a tool path from the environment, falling back to a default."""

	return Path(os.environ.get(name, default))


SAMPLE_RATE_HZ = 30
HASH_ALGORITHMS = ["sha256", "sha1"]

SUPPORTED_IMAGE_EXTENSIONS = (".E01", ".001", ".zip")

# Source classification signals used in Phase 1 (Provenance and Integrity).
# Each tuple is (regex_pattern, score_weight). Scores are capped per class.
CLASSIFICATION_SIGNALS = {
	"ios_controller": [
		(r"[A-F0-9-]{36}/com\.dji\.", 10),
		(r"Library/Preferences/.*\.plist", 5),
		(r"Documents/FlightRecord/.*\.txt", 5),
		(r"Manifest\.db", 5),
		(r"(?:^|/)Manifest(?:/|$)", 1),
		(r"(?:^|/)Info(?:/|$)", 1),
		(r"(?:^|/)Status(?:/|$)", 1),
	],
	"android_controller": [
		(r"sdcard/DJI/dji\.go", 10),
		(r"data/data/dji\.go\.v4", 10),
		(r"FlightRecord/.*\.txt", 3),
	],
	"drone_sd": [
		(r"DCIM/100MEDIA/.*\.MP4", 10),
		(r"MISC/THM/", 5),
		(r"DCIM/.*\.JPG", 3),
	],
	"drone_flight_storage": [
		(r"FLY\d+\.DAT", 10),
		(r"DJI_ASSISTANT_EXPORT_FILE_.*\.DAT", 10),
	],
}

CLASSIFICATION_SCORE_CAP = 10
AUTO_CLASSIFY_MIN_SCORE = 10
AUTO_CLASSIFY_SECONDARY_MAX = 3
AMBIGUOUS_MIN_SCORE = 10
IOS_LOGICAL_HEX_FOLDER_THRESHOLD = 128
IOS_LOGICAL_BACKUP_BONUS = 5

IOS_APP_DOMAINS = {
	"DJI GO": "com.dji.pilot",
	"DJI GO 4": "com.dji.go",
	"DJI Pilot": "dji.pilot",
}

ANDROID_PACKAGES = {
	"DJI GO": "com.dji.go",
	"DJI GO 4": "dji.go.v4",
	"DJI Pilot": "dji.pilot",
}

# Treat these as searchable prefixes, not strict filesystem roots.
ANDROID_EXTERNAL_ROOTS = (
	"/sdcard/Android/data/",
	"/sdcard/DJI/",
	"/userdata/media/0/DJI/",
)

TXTLOG_VARIANTS = {
	"default": "TXTlogToCSVtool.exe",
	"exp": "TXTlogToCSVtool-exp.exe",
	"mm": "TXTlogToCSVtoolMM.exe",
}

ARTEFACT_CATEGORIES = (
	"drone_logs",
	"flight_records",
	"flight_logs",
	"media",
	"databases",
	"account_data",
	"camera_logs",
)

ARTEFACT_CATEGORY_SET = frozenset(ARTEFACT_CATEGORIES)

# Tool locations are kept as defaults here, but should be configured manually according to the environment.
SLEUTH_KIT_BIN = _env_path(
	"DFDOF_SLEUTH_KIT_BIN",
	r"C:\Users\Floris\Documents\sleuthkit\bin",
)
TSK_MMLS = _env_path(
	"DFDOF_TSK_MMLS",
	str(SLEUTH_KIT_BIN / "mmls.exe"),
)
TSK_FLS = _env_path(
	"DFDOF_TSK_FLS",
	str(SLEUTH_KIT_BIN / "fls.exe"),
)
TSK_ICAT = _env_path(
	"DFDOF_TSK_ICAT",
	str(SLEUTH_KIT_BIN / "icat.exe"),
)
TXTLOG_TO_CSV_DEFAULT = _env_path(
	"DFDOF_TXTLOG_TO_CSV_DEFAULT",
	r"C:\Users\Floris\Documents\txtlogtocsv\TXTlogToCSVtool.exe",
)
TXTLOG_TO_CSV_EXP = _env_path(
	"DFDOF_TXTLOG_TO_CSV_EXP",
	r"C:\Users\Floris\Documents\txtlogtocsv\TXTlogToCSVtool-exp.exe",
)
TXTLOG_TO_CSV_MM = _env_path(
	"DFDOF_TXTLOG_TO_CSV_MM",
	r"C:\Users\Floris\Documents\txtlogtocsv\TXTlogToCSVtoolMM.exe",
)
DJI_LOG_PARSER_EXE = _env_path(
	"DFDOF_DJI_LOG_PARSER_EXE",
	r"C:\Users\Floris\Documents\dji-log-parser\dji-log-parser.exe",
)
DROP_SCRIPT = _env_path(
	"DFDOF_DROP_SCRIPT",
	r"C:\Users\Floris\Documents\drop\DROP.py",
)
EXIFTOOL_EXE = _env_path(
	"DFDOF_EXIFTOOL_EXE",
	r"C:\Users\Floris\Documents\exiftool\exiftool.exe",
)

# DatCon is GUI-based, so this paths are launch references rather than CLI invocations.
DATCON_DISPLAY_PATH = _env_path(
	"DFDOF_DATCON_DISPLAY_PATH",
	r"C:\Program Files (x86)\DatCon\DatCon.4.3.0.exe",
)


def is_supported_image_extension(path: str | Path) -> bool:
	"""Return True when the path uses one of the supported image extensions."""

	return Path(path).suffix.lower() in {extension.lower() for extension in SUPPORTED_IMAGE_EXTENSIONS}


def get_txtlog_variant(name: str = "default") -> Path:
	"""Return the configured TXTlogToCSVtool executable for the requested variant."""

	variant = name.lower()
	return {
		"default": TXTLOG_TO_CSV_DEFAULT,
		"exp": TXTLOG_TO_CSV_EXP,
		"mm": TXTLOG_TO_CSV_MM,
	}.get(variant, TXTLOG_TO_CSV_DEFAULT)


