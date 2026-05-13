"""DFDOF Central Configuration.

Stores global variables and functions centrally.
"""

from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path
import shutil

# For identification in phase 1
CONTROLLER_IOS_INCLUDES = {"Manifest.db", "Info.plist"}
CONTROLLER_ANDROID_INCLUDES = {'data/data/dji', 'data/data/com.dji', 'sdcard/dji', 'sdcard/DJI'}
DRONE_FLIGHT_STORAGE_INCLUDES = {"FLY", "DJI_ASSISTANT_EXPORT_FILE"}
DRONE_SD_INCLUDES = {"DCIM", "MISC"}

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

# Acquisition method types
ACQUISITION_LOGICAL = "logical"
ACQUISITION_PHYSICAL = "physical"
ACQUISITION_IOS_PARSER = "ios_parser"
ACQUISITION_ANDROID_PARSER = "android_parser"
ACQUISITION_LOGICAL_READER = "logical_reader"
ACQUISITION_PHYSICAL_READER = "physical_reader"

# Evidence types
EVIDENCE_TYPE_INPUT = "input"
EVIDENCE_TYPE_PARSED = "parsed"
EVIDENCE_TYPE_EXTRACTED = "extracted"

# Android backup_info.json schema
BACKUP_INFO_SCHEMA = {
	"Build Version": None,
	"Device Name": None,
	"GUID": None,
	"Installed Applications": [],
	"Last Backup Date": None,
	"Product Name": None,
	"Product Type": None,
	"Product Version": None,
	"Serial Number": None,
	"Unique Identifier": None,
}

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
	IMAGES: {".jpg", ".jpeg", ".thumbnail"},
	VIDEOS: {".mp4", ".mov", ".info"},
	DATABASES: {".db"},
	# ACCOUNT_DATA: For Android .xml and for iOS .plist
	# DEVICE_AND_BACKUP_INFO: already handled in phase 2
}

# These paths are only used on the controller
ARTEFACT_PATHS = {
	DRONE_LOGS: {"FlightRecords/", "FlightRecords/MCDatFlightRecords/"},
	FLIGHT_RECORDS: {"FlightRecord", "FlightRecords/"},
	FLIGHT_LOGS: {"FlightLogs/", "LOG/", "Logs/"},
	IMAGES: {"CACHE_IMAGE/", "videoCache/"},
	VIDEOS: {"DJI_RECORD/", "videoCache/"},
	DATABASES: {"db/", "dbData/", ".space_db/"},
	# ACCOUNT_DATA: derived via DJI_APP_DOMAINS
	# DEVICE_AND_BACKUP_INFO: already handled in phase 2
}

ARTEFACT_EXTENSIONS_DRONE_SD = {".MP4", ".THM"}
ARTEFACT_DATABASES_INCLUDES = {"mbgl-offline", "datastore", "dji", "flysafe_areas_djigo"}
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
EXTRACT_DJI_EXE = _env_path(
	"DFDOF_EXTRACT_DJI_EXE",
	r"C:\Program Files (x86)\CsvView\ExtractDJI.exe",
)
