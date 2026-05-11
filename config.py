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

# Source identification types
IDENTIFICATION_CONTROLLER_IOS = "controller_ios"
IDENTIFICATION_CONTROLLER_ANDROID = "controller_android"
IDENTIFICATION_DRONE_SD = "drone_sd"
IDENTIFICATION_DRONE_FLIGHT_STORAGE = "drone_flight_storage"
IDENTIFICATION_UNCLASSIFIED = "unclassified"

SOURCE_IDENTIFICATION_TYPES = {
	IDENTIFICATION_CONTROLLER_IOS,
	IDENTIFICATION_CONTROLLER_ANDROID,
	IDENTIFICATION_DRONE_SD,
	IDENTIFICATION_DRONE_FLIGHT_STORAGE,
}
SOURCE_IDENTIFICATION_TYPES = frozenset(SOURCE_IDENTIFICATION_TYPES)

# Acquisition method types
ACQUISITION_LOGICAL = "logical"
ACQUISITION_PHYSICAL = "physical"
ACQUISITION_IOS_PARSER = "ios_parser"
ACQUISITION_LOGICAL_READER = "logical_reader"
ACQUISITION_TSK_MOUNTER = "tsk_mounter"

# Evidence types (core)
EVIDENCE_TYPE_INPUT = "input"
EVIDENCE_TYPE_PARSED = "parsed"
EVIDENCE_TYPE_EXTRACTED = "extracted"

# Artefact categories
DRONE_LOGS = "drone_logs"
FLIGHT_RECORDS = "flight_records"
FLIGHT_LOGS = "flight_logs"
MEDIA = "media"
DATABASES = "databases"
ACCOUNT_DATA = "account_data"
DEVICE_AND_BACKUP_INFO = "device_and_backup_info"

EXTENSION_ZIP = [".zip"]
EXTENSION_PHYSICAL = [".E01", ".001"]
SUPPORTED_IMAGE_EXTENSIONS = tuple(EXTENSION_PHYSICAL) + tuple(EXTENSION_ZIP)
MAX_SUMMARY_LENGTH = 125


# Default functions
def _env_path(name: str, default: str) -> Path:
	"""Helper to get a Path from an environment variable, with a default fallback."""
	return Path(os.environ.get(name, default))


def summarise_text(value: str, limit: int = MAX_SUMMARY_LENGTH) -> str:
	"""Summarise a long text value for logging, truncating and adding ellipsis if it exceeds the limit."""
	if len(value) <= limit:
		return value
	return value[: limit - 3] + "..."


def utc_now_iso() -> str:
	"""Get the current UTC time as an ISO 8601 string."""
	return datetime.now(timezone.utc).isoformat()


def output_dir() -> Path:
	"""Determine the output directory for extracted evidence and logs."""
	documents = Path.home() / "Documents"
	if documents.exists():
		return documents / "dfdof_output"
	else:
		return Path.home() / "dfdof_output"


# Default tool locations
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
