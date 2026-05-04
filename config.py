"""DFDOF Central Configuration.

Stores global variables and functions centrally.
"""

from __future__ import annotations

import os
from pathlib import Path


HASH_ALGORITHMS = ["sha256", "sha1"]
SUPPORTED_IMAGE_EXTENSIONS = (".E01", ".001", ".zip")

SOURCE_CLASSIFICATION_TYPES = {
	"ios_controller",
	"android_controller",
	"drone_sd",
	"drone_flight_storage",
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


# Default functions
def _env_path(name: str, default: str) -> Path:
	"""Resolve a tool path from the environment, falling back to a default."""

	return Path(os.environ.get(name, default))


# Default tool locations, always adjust to environment
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

# DatCon is GUI-based, so not CLI invocable
DATCON_DISPLAY_PATH = _env_path(
	"DFDOF_DATCON_DISPLAY_PATH",
	r"C:\Program Files (x86)\DatCon\DatCon.4.3.0.exe",
)
