# DFDOF — Drone Forensic Decision and Orchestration Framework

> **Proof of concept.** Developed as a Master's thesis project by Floris Krijger, MSc Security and Network Engineering, University of Amsterdam (April – June 2026). This is not a production-ready system. Further testing, validation across additional drone models, and robustness improvements are required before operational use.

DFDOF is an automated forensic pipeline for DJI drone evidence. It ingests iOS and Android controller backups, physical drone images, and DCIM SD cards, processes them through eight sequential phases, and produces a structured forensic baseline report (PDF) with SHA-256 and SHA-1 chain-of-custody hashes for every derived artefact.

---

## Table of Contents

- [Requirements](#requirements)
- [External Tools](#external-tools)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [Inputs](#inputs)
- [Output](#output)
- [Pipeline Overview](#pipeline-overview)
- [Running Tests](#running-tests)
- [Disclaimer](#disclaimer)

---

## Requirements

- **Python** 3.11 or higher
- **Operating system:** Windows (tool paths in `config.py` default to Windows; Linux/macOS requires path adjustments)
- **Python packages:**

```
fpdf2>=2.8
matplotlib>=3.10
pandas>=2.0
pytest>=8.0        # test suite only
```

---

## External Tools

DFDOF depends on the following external tools. They must be installed separately and their paths configured in `config.py` (see [Configuration](#configuration)).

| Tool | Version used | Purpose | Source |
|---|---|---|---|
| **DatCon** | 4.3.0 | Decode `.DAT` drone flight logs to CSV + KML | [o-w.com/datcon](https://datfile.net/) |
| **CsvView / TXTlogToCSVtool** | 2018-06-11 | Convert FlightRecord `.txt` files to CSV | [o-w.com/csvview](https://datfile.net/) |
| **CsvView / ExtractDJI** | 1.4.3 | Extract `.DAT` files from drone storage images | [o-w.com/csvview](https://datfile.net/) |
| **ExifTool** | 12.x | Extract metadata from images and video files | [exiftool.org](https://exiftool.org/) |
| **The Sleuth Kit (TSK)** | 4.15.0 | Enumerate and extract files from physical `.E01`/`.001` images | [sleuthkit.org](https://www.sleuthkit.org/) |

> **Note on DatCon:** DatCon is a GUI application. DFDOF launches it as a subprocess and pauses, prompting the operator to run the conversion manually and confirm when done.

---

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/<your-username>/DFDOF.git
cd DFDOF
```

### 2. Create and activate a virtual environment

```bash
python -m venv .venv

# Windows
.venv\Scripts\activate

# macOS / Linux
source .venv/bin/activate
```

### 3. Install Python dependencies

```bash
pip install -r requirements.txt
```

### 4. Install external tools

Install each tool from the table above and note their executable paths. Then update `config.py` (see [Configuration](#configuration)).

---

## Configuration

Open `config.py` and update the default paths under the section marked **"Default tool locations — ADJUST TO YOUR ENVIRONMENT"**:

```python
SLEUTH_KIT_BIN = Path(r"C:\path\to\sleuthkit\bin")
EXTRACT_DJI_EXE = Path(r"C:\path\to\CsvView\ExtractDJI.exe")
DATCON          = Path(r"C:\path\to\DatCon\DatCon.4.3.0.exe")
TXTLOGTOCSV     = Path(r"C:\path\to\CsvView\executables\TXTlogToCSVtool.exe")
EXIFTOOL        = Path(r"C:\path\to\exiftool\exiftool.exe")
```

Also update the version strings if your installed versions differ (these appear in the audit log and report):

```python
VERSION_EXTRACT_DJI = "1.4.3"
VERSION_DATCON      = "4.3.0"
VERSION_TXTLOGTOCSV = "2018-06-11"
```

**Alternatively**, set environment variables to override defaults without editing the file:

| Variable | Overrides |
|---|---|
| `DFDOF_SLEUTH_KIT_BIN` | `SLEUTH_KIT_BIN` |
| `DFDOF_EXTRACT_DJI_EXE` | `EXTRACT_DJI_EXE` |
| `DFDOF_DATCON` | `DATCON` |
| `DFDOF_TXTLOGTOCSV` | `TXTLOGTOCSV` |
| `DFDOF_EXIFTOOL` | `EXIFTOOL` |

---

## Usage

### Start command

```bash
python main.py --operator "Your Name" --case-id "CASE-001" \
               --evidence-dir "C:\path\to\evidence" \
               --state-path state.json
```

All arguments are optional. If omitted, the pipeline will prompt for them interactively at startup.

### Flags

| Flag | Description | Default |
|---|---|---|
| `--operator` | Name of the operator running the analysis | prompted |
| `--case-id` | Unique identifier for this case | prompted |
| `--evidence-dir` | Path to the directory containing all evidence files | prompted |
| `--state-path` | Path to write the state file | `state.json` |

### Interactive source identification (Phase 1)

After Phase 1 classifies the evidence files, the pipeline displays a summary table and prompts the operator to confirm before any extraction begins. For each input file it shows the detected source type, acquisition method, and confidence.

If a file cannot be automatically identified, the operator is prompted to assign it manually from the following source types:

| Type | Description |
|---|---|
| `controller_ios` | iOS controller backup (iTunes logical `.zip`) |
| `controller_android` | Android controller backup (logical `.zip` or physical `.E01`/`.001`) |
| `drone_sd` | Drone SD card or internal storage (physical `.E01`/`.001`) |
| `drone_flight_storage` | Drone dedicated flight storage partition (physical image) |

The pipeline will not proceed past Phase 1 until the operator types `yes` to confirm all classifications.

### DatCon interaction (Phase 4)

For each `.DAT` drone log, the pipeline launches DatCon as a GUI and pauses. The operator must:

1. Open the `.DAT` file in DatCon
2. Set output: Time Axis = Recording Start, CSV at 30 Hz with Event Log enabled, KML Ground Track enabled
3. Export the file
4. Type `done` in the terminal to continue, or `error` to skip the file

---

## Inputs

Place all evidence files for a case in a single flat directory and pass that path via `--evidence-dir`. DFDOF identifies file types automatically by content signatures and file extensions.

| Evidence type | Accepted formats |
|---|---|
| iOS controller backup | `.zip` (must contain `Manifest.db` and `Info.plist`) |
| Android controller backup | `.zip` (logical) or `.E01` / `.001` (physical) |
| Drone SD card / internal storage | `.E01` or `.001` physical image |
| Drone flight storage | `.E01` or `.001` physical image |

---

## Output

All output is written to:

```
~/Documents/dfdof_output/<case-id>/
```

(Falls back to `~/dfdof_output/<case-id>/` if `Documents` does not exist.)

### Output structure

```
<case-id>/
  state.json                               # complete case record — all phases, hashes, findings
  <case-id>_forensic_baseline.pdf          # automated PDF report
  p2_image_parsing/
    controller_ios_parsed/                 # parsed iOS backup domain tree + backup_info.json
    controller_android_parsed/             # backup_info.json and device metadata
  p3_artefact_extraction/
    controller_ios/                        # extracted artefacts per category
    controller_android/
    drone_sd_1/
    _rejected/                             # zero-byte files moved here
  p4_decision_and_orchestration/
    controller_ios/
      drone_logs/                          # DatCon CSV + KML
      flight_records/                      # TXTlogToCSV CSV
      images/ videos/                      # ExifTool JSON
      account_data/                        # parsed account preferences
  p5_normalisation_and_anomaly_checking/
    controller_ios/
      drone_logs/                          # norm_*.csv (UTC-normalised)
      flight_records/                      # norm_*.csv
  p6_multisource_correlation/
    timeline_flight01.json                 # unified per-flight event timeline
    timeline_flight02.json
  p8_automated_reporting/
    flight_01_fr_telemetry.png             # flight record sensor plots
    flight_01_drone_telemetry.png          # drone log sensor plots
    flight_01_track.png                    # GPS ground track
```

### `state.json`

The primary forensic record. Contains every phase output, all artefact SHA-256 and SHA-1 hashes, anomaly flags, tool invocation logs with return codes, and the full P7 analytical conclusions. Written atomically after each phase so the pipeline can be inspected at any point.

### PDF report

The automated forensic baseline report (`<case-id>_forensic_baseline.pdf`) includes:

- Evidence intake with full SHA-256 and SHA-1 hashes
- Pipeline execution summary and anomaly flags
- Device and account identification with confidence levels
- Per-flight analysis: correlation outcome, key events, warnings, correlated media
- Sensor telemetry plots (altitude, speed, attitude, battery, GPS quality)
- Flight ground track (GPS scatter, dual-source overlay if both FR and drone log matched)
- Artefact coverage tables
- Further investigation items
- Full artefact hash manifest (Appendix A)
- Evidence derivation summary (Appendix B)
- DFDOF proof of concept overview and disclaimer (Appendix C)

---

## Pipeline Overview

| Phase | Name | Key inputs | Key outputs |
|---|---|---|---|
| P1 | Provenance and Integrity | Evidence directory | Classified Evidence objects, SHA-256/SHA-1 hashes |
| P2 | Image Parsing | Raw evidence files | Parsed directory trees, `backup_info.json` |
| P3 | Artefact Extraction | Parsed directories | Categorised artefacts per source |
| P4 | Decision and Orchestration | Extracted artefacts | DatCon CSV/KML, flight record CSV, EXIF JSON, account data |
| P5 | Normalisation and Anomaly Checking | Decoded artefacts | UTC-normalised CSVs, anomaly observations |
| P6 | Multi-Source Correlation | Normalised CSVs | `timeline_flightXX.json` per identified flight |
| P7 | Analysis and Validation | All phase outputs | Conclusions dict in `state.json` |
| P8 | Automated Reporting | `state.json` + normalised CSVs | PDF report + PNG plot files |

---

## Running Tests

```bash
pytest                                               # all 388 tests
pytest -v                                            # verbose output
pytest tests/test_p6_multisource_correlation.py      # single file
```

---

## Disclaimer

This proof of concept was developed as a Master's thesis project and has been tested on a limited set of DJI Mavic Air evidence (iOS and Android, logical acquisition). It is not a finished, production-ready system. Before use in any operational or legal context, further testing, validation across additional drone models and evidence types, and robustness improvements are required. The author accepts no liability for conclusions drawn from automated pipeline output without independent expert verification.
