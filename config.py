"""DFDOF Central Configuration.

Stores global variables and functions centrally.
"""

from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path
import shutil

# DJI app domains
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
IDENTIFICATION_UNCLASSIFIED = "not_identified"

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

# Evidence types
EVIDENCE_TYPE_INPUT = "input"
EVIDENCE_TYPE_PARSED = "parsed"
EVIDENCE_TYPE_EXTRACTED = "extracted"

# Artefact extraction
DRONE_LOGS = "drone_logs"
FLIGHT_RECORDS = "flight_records"
FLIGHT_LOGS = "flight_logs"
IMAGES = "images"
VIDEOS = "videos"
DATABASES = "databases"
ACCOUNT_DATA = "account_data"
DEVICE_AND_BACKUP_INFO = "device_and_backup_info"

ARTEFACT_EXTENSIONS = {
	DRONE_LOGS: {".DAT"},
	FLIGHT_RECORDS: {".txt"},
	FLIGHT_LOGS: {".txt", ".dat"},
	IMAGES: {".jpg", ".jpeg", ".thumbnail", ".THM"},
	VIDEOS: {".mp4", ".MP4", ".mov", ".info"},
	DATABASES: {".db", ".sqlite"},
	ACCOUNT_DATA: {".plist", ".xml"},
	# Does not need to contain Device and Backup Info (already handled in P2)
}

ARTEFACT_PATHS = {
	DRONE_LOGS: {"FlightRecords/MCDatFlightRecords/"},
	FLIGHT_RECORDS: {"FlightRecords/"},
	FLIGHT_LOGS: {"FlightLogs/", "LOG/", "Logs/"},
	IMAGES: {"CACHE_IMAGE/", "videoCache/", "100MEDIA/", "THM/100/"},
	VIDEOS: {"DJI_RECORD/", "videoCache/", "100MEDIA/", "THM/100/"},
	DATABASES: {"db/", "dbData/", ".space_db/"},
	# Account data directly found via DJI app domains
	# Device and Backup Info already handled in P2
}

ARTEFACT_DATABASES_INCLUDES = {"mbgl-offline", "djiFMDB", "datastore", "dji", "flysafe_areas_djigo"}
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


def clear_and_make(path: Path) -> None:
	"""Clear a directory if it exists and create it."""
	if path.exists():
		shutil.rmtree(path)
	path.mkdir(parents=True, exist_ok=True)


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
