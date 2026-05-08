"""DFDOF Central Configuration.

Stores global variables and functions centrally.
"""

from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path

DJI_APP_DOMAINS = {
	"ios": {
		"com.dji.pilot": "DJI GO",
		"com.dji.go": "DJI GO 4",
		"dji.pilot": "DJI Pilot",
	},
	"android": {
		"com.dji.go": "DJI GO",
		"dji.go.v4": "DJI GO 4",
		"dji.pilot": "DJI Pilot",
	},
}

SOURCE_CLASSIFICATION_TYPES = {
	"controller_ios",
	"controller_android",
	"drone_sd",
	"drone_flight_storage",
}

DRONE_LOGS = "drone_logs"
FLIGHT_RECORDS = "flight_records"
FLIGHT_LOGS = "flight_logs"
MEDIA = "media"
DATABASES = "databases"
ACCOUNT_DATA = "account_data"
DEVICE_AND_BACKUP_INFO = "device_and_backup_info"

ARTEFACT_CATEGORIES = (
	DRONE_LOGS,
	FLIGHT_RECORDS,
	FLIGHT_LOGS,
	MEDIA,
	DATABASES,
	ACCOUNT_DATA,
	DEVICE_AND_BACKUP_INFO,
)

ARTEFACT_CATEGORY_SET = frozenset(ARTEFACT_CATEGORIES)
EVIDENCE_TYPE_INPUT = "input"
EVIDENCE_TYPE_PARSED = "parsed"
EVIDENCE_TYPE_EXTRACTED = "extracted"

EVIDENCE_TYPES = (
	EVIDENCE_TYPE_INPUT,
	EVIDENCE_TYPE_PARSED,
	EVIDENCE_TYPE_EXTRACTED,
)

EVIDENCE_TYPE_SET = frozenset(EVIDENCE_TYPES)
HASH_ALGORITHMS = ["sha1", "sha256"]
SUPPORTED_IMAGE_EXTENSIONS = (".E01", ".001", ".zip")
MAX_SUMMARY_LENGTH = 125


# Default functions
def _env_path(name: str, default: str) -> Path:
	return Path(os.environ.get(name, default))


def summarise_text(value: str, limit: int = MAX_SUMMARY_LENGTH) -> str:
	if len(value) <= limit:
		return value
	return value[: limit - 3] + "..."


def utc_now_iso() -> str:
	return datetime.now(timezone.utc).isoformat()


def output_dir() -> Path:
	documents = Path.home() / "Documents"
	if documents.exists():
		return documents / "dfdof_output"
	else:
		return Path.home() / "dfdof_output"


# Default tool locations, always adjust to local environment
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
