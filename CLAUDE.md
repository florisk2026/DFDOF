# DFDOF — Claude Context Index

**Drone Forensic Decision and Orchestration Framework** — automated 8-phase forensic pipeline for DJI drone evidence. Inputs: iOS/Android controller backups (ZIP), physical drone images (.E01/.001), DCIM SD cards. Integrity: SHA-256 + SHA-1 chain-of-custody on every artefact. Atomic state persisted to `state.json`. Entry point: `main.py`; phases run P1→P8 sequentially.

---

## Phase Map

| Phase | File | Responsibility | Key State Output | Consumes |
|---|---|---|---|---|
| P1 | `phases/p1_provenance.py` | Classify inputs (ZIP/E01/001), build input `Evidence` objects (`skip_hash=True`), operator override loop | `phase_outputs["p1_provenance"]["identified_evidence"]` | Nothing (reads `evidence_directory`) |
| P2 | `phases/p2_image_parsing.py` | Decrypt/decompress iOS backup → domain tree; extract Android metadata → `backup_info.json`; produce `DEVICE_AND_BACKUP_INFO` Evidence + Observations | `phase_outputs["p2_image_parsing"]["parsed_evidence"]`, `["derived_observations"]` | P1 `identified_evidence` |
| P3 | `phases/p3_artefact_extraction.py` | Root-driven category extraction: discovers DJI app roots → recurses inside configured per-platform category paths → filters by extension → rejects empty files → wraps as Evidence | `phase_outputs["p3_artefact_extraction"]["extracted_artefacts"]` | P2 parsed dirs |
| P4 | `phases/p4_decision_and_orchestration.py` | Conditional tool dispatch per artefact category + account data field extraction | `phase_outputs["p4_decision_and_orchestration"]["decision_and_orchestration_artefacts"]`, `["derived_observations"]` | P3 `extracted_artefacts` |
| P5 | `phases/p5_normalisation_and_anomaly_checking.py` | CSV normalisation + 9 shared + format-specific anomaly checks + column-level checks; database empty-row check; flight_log format detection + readability; opaque-extension image decoding | `phase_outputs["p5_normalisation_and_anomaly_checking"]["normalised_artefacts"]`, `["derived_anomalies"]` | P3 (databases, flight_logs), P4 (all others) |
| P6 | `phases/p6_multisource_correlation.py` | Multi-source temporal + spatial correlation; deduplicates FR candidates (multi-app); builds per-flight unified event timeline; correlates EXIF/flight_log/video-duration observations | `phase_outputs["p6_multisource_correlation"]["flights"]`, `["flight_count"]`; `timeline_flightXX.json` per flight | P5 normalised CSVs + anomalies |
| P7 | `phases/p7_analysis_and_validation.py` | Consumes P2–P6 outputs: source/artefact coverage, tool status, account/drone identity, per-flight analysis, uncorrelated artefacts, coverage score, forensic statements | `phase_outputs["p7_analysis_and_validation"]` (full analysis dict) | P2–P6 outputs |
| P8 | `phases/p8_automated_reporting.py` | Generate PDF forensic baseline report from P7 outputs | `phase_outputs["p8_automated_reporting"]["report_path"]` | P2–P7 outputs, P5 normalised CSVs, P6 timelines |

---

## Core Module Index

### `config.py`
Centralised constants only. No business logic.

- **Source detection sets**: `CONTROLLER_IOS_INCLUDES = {"Manifest.db", "Info.plist"}`, `CONTROLLER_ANDROID_INCLUDES = {"data/data/dji", "data/data/com.dji", "sdcard/dji", "data/dji", "data/com.dji"}`, `DRONE_FLIGHT_STORAGE_INCLUDES = {"FLY", "DJI_ASSISTANT_EXPORT_FILE"}`, `DRONE_SD_INCLUDES = {"DCIM", "MISC"}`. The `"data/dji"` and `"data/com.dji"` tokens handle physical Android images where the data partition is mounted at root (one fewer `data/` prefix than logical backups).
- **Identification constants**: `IDENTIFICATION_CONTROLLER_IOS = "controller_ios"`, `IDENTIFICATION_CONTROLLER_ANDROID = "controller_android"`, `IDENTIFICATION_DRONE_SD = "drone_sd"`, `IDENTIFICATION_DRONE_FLIGHT_STORAGE = "drone_flight_storage"`, `IDENTIFICATION_UNCLASSIFIED = "not_identified"`
- **`SOURCE_IDENTIFICATION_TYPES`** (ordered list): `[android, ios, drone_sd, drone_flight_storage]` — canonical iteration order for all phases. Do not use `sorted()` on it.
- **Evidence type tokens**: `EVIDENCE_TYPE_INPUT`, `_PARSED`, `_EXTRACTED`, `_DECODED`, `_NORMALISED`
- **Acquisition method tokens**: `ACQUISITION_LOGICAL = "logical"`, `_PHYSICAL = "physical"`, `_PARSER_IOS = "parser_ios"`, `_PARSER_ANDROID = "parser_android"`, `_EXTRACT_LOGICAL = "extract_logical"`, `_EXTRACT_PHYSICAL = "extract_physical"`, `_DATCON = "datcon"`, `_EXTRACT_DJI = "extractdji"`, `_TXTLOGTOCSV = "txtlogtocsvtool"`, `_EXIFTOOL = "exiftool"`, `_SELECT_ACCOUNT_DATA = "p4_decision_and_orchestration"`, `_NORMALISE = "p5_normalisation_and_anomaly_checking"`
- **Artefact category tokens**: `ACCOUNT_DATA`, `DATABASES`, `DEVICE_AND_BACKUP_INFO`, `DRONE_LOGS`, `FLIGHT_LOGS`, `FLIGHT_RECORDS`, `IMAGES`, `VIDEOS`
- **`CONTROLLER_ARTEFACT_CATEGORIES`**: alphabetical list of 7 controller categories (excludes `DEVICE_AND_BACKUP_INFO`)
- **`ARTEFACT_EXTENSIONS`**: category → file extensions for controller sources; `FLIGHT_LOGS: {".txt", ".dat", ""}` includes extensionless files; `IMAGES: {".jpg", ".jpeg", ".thumbnail"}`, `VIDEOS: {".mp4", ".mov", ".info"}`
- **`ARTEFACT_EXTENSIONS_DRONE_SD`**: `{IMAGES: {".JPG", ".JPEG", ".THM"}, VIDEOS: {".MP4", ".MOV"}}` — drone SD only; category → extensions dict, consistent with `ARTEFACT_EXTENSIONS`; mixed case normalised to lowercase in module-level caches (`_ARTEFACT_EXTENSIONS_DRONE_SD_LOWER`, `_DRONE_SD_EXT_TO_CATEGORY` in P3; `_DRONE_SD_EXTS_LOWER` in P1)
- **`IOS_ARTEFACT_PATHS`** / **`ANDROID_ARTEFACT_PATHS`**: category → directory path tokens for P3 extraction
- **`DJI_APP_DOMAINS`**: ios/android → bundle-id → display name; used by P3 for root discovery
- **Tool paths** (overridable via env vars `DFDOF_*`): `SLEUTH_KIT_BIN`, `TSK_MMLS`, `TSK_FLS`, `TSK_ICAT`, `EXTRACT_DJI_EXE`, `DATCON`, `TXTLOGTOCSV`, `EXIFTOOL`
- **Tool version strings** (not CLI-obtainable): `VERSION_EXTRACT_DJI = "1.4.3"`, `VERSION_DATCON = "4.3.0"`, `VERSION_TXTLOGTOCSV = "2018-06-11"`
- **`BACKUP_INFO_SCHEMA`**: legacy raw-key schema (Pascal-case); P2 normalises to snake_case before observations
- **`MAX_SUMMARY_LENGTH = 125`**; `SUPPORTED_IMAGE_EXTENSIONS = tuple(EXTENSION_PHYSICAL) + tuple(EXTENSION_ZIP)` (used by P1 to enumerate evidence directory)
- **Helpers**: `utc_now_iso()`, `output_dir()` → `~/Documents/dfdof_output` or `~/dfdof_output`, `clear_and_make(path)`, `summarise_text(value, limit=125)`, `_env_path(name, default)`, `_write_no_output(path)`, `_has_real_output(path)` — sentinel helpers; see below.
- **`_NO_OUTPUT_FILENAME = "_no_output.txt"`**, **`_NO_OUTPUT_CONTENT = "This phase has no output"`** — every phase output directory is always created; if nothing was written into it, `_write_no_output(path)` places this sentinel file inside. `_has_real_output(path)` returns `True` if any non-sentinel file exists under `path`.

### `evidence.py`

```python
@dataclass
class Evidence:
    source_path: Path | str          # original forensic identifier
    stored_path: Path | str | None   # disk location (defaults to source_path)
    parent: Evidence | None          # parent Evidence (for derived files)
    acquisition_method: str | None
    type: str                        # EVIDENCE_TYPE_* constant
    artefact_category: str | None
    source_identification: str | None
    hash_note: str | None
    skip_hash: bool                  # defers hashing
    # Computed fields (immutable once set):
    sha256: str; sha1: str; hash_timestamp: str; parent_sha256: str | None
    size: int                        # recursive for directories
```

Key invariants:
- `_IMMUTABLE_ONCE_SET = frozenset({"sha256", "sha1", "hash_timestamp", "parent_sha256"})` — `__setattr__` raises `AttributeError` if any field is reassigned when already truthy.
- `__post_init__` copies `source_identification` from `parent.source_identification` when parent is provided and field is not set explicitly.
- `from_dict()` uses `cls.__new__(cls)` (bypasses `__post_init__`, no re-hashing).
- Root extraction directories are **never** wrapped in Evidence. Only `backup_info.json` and raw functional artefacts are valid Evidence objects.
- `hash_file(path)` → `(sha256_hex, sha1_hex)`, chunked 1 MB reads.
- `make_evidence(*, source_path, stored_path, parent, acquisition_method, type, artefact_category, source_identification, skip_hash, hash_note)` — preferred factory.

### `observation.py`

```python
@dataclass
class Content:
    stored_path: str | None          # denormalised source path (for P6/P7 lookup)
    evidence_sha256: str             # links back to source Evidence
    evidence_category: str | None
    acquisition_method: str | None
    observations: list[Any]          # arbitrary key→value parsed data

@dataclass
class Observation:
    content: Content
```

- `make_observation(*, stored_path, evidence_sha256, evidence_category, acquisition_method, observations)` — factory; `stored_path` defaults to `None` but every production call site passes it.
- Observations carry parsed metadata without mutating Evidence objects. `stored_path` is denormalised so P6/P7 can resolve the source file without a hash lookup.

### `state.py`

```python
@dataclass
class State:
    case_id: str; operator: str
    evidence_directory: str | None
    start_time: str                  # utc_now_iso()
    input_evidence: list[Evidence]
    phase_outputs: dict[str, Any]   # keyed by phase name
    tool_invocation_log: list[dict[str, Any]]
    anomaly_flags: list[str]        # append-only
    completed_phases: list[str]
```

- **`raise_anomaly(phase, identification, message, *, category, index)`** — formats `[p<N> - <evidence type>[ - <category>]]: <message>`; for `IDENTIFICATION_DRONE_SD` with `index` set, label becomes `drone sd <N>`. Never raises, only appends.
- **`save(path)`** — atomic write via `.tmp` rename (`target.with_suffix(suffix + ".tmp")`).
- **`log_tool_invocation(...)`** — prefers stderr over stdout for the `std_summary` field.
- **`log_command_result(...)`** — auto-probes TSK tool version via `_get_tsk_tool_version()` for `mmls/fls/icat`.

### `main.py`

CLI entry point. `_build_parser()` defines: `--operator`, `--case-id`, `--evidence-dir`, `--state-path` (default `state.json`). `run_phases()` drives P1→P8 sequentially. Input hashes computed with `skip_hash=True` at P1 construction time; `_compute_evidence_hashes()` runs after P1 classifies sources. After all phases, `state.json` is copied to `output_dir() / case_id /`.

### `reporting/report_builder.py` and `reporting/plots.py`

P8 reporting package. `build_report(state, output_path, plots_dir)` is the single entry point called by `run_phase_8()`.

**Layout constants** (`report_builder.py`):
- `_FONT = "Helvetica"` (latin-1; all text routed through `_safe()` to replace unencodable chars)
- `_MARGIN_L = _MARGIN_R = 15 mm`, `_MARGIN_T = 22 mm`, `_PAGE_W = 210 mm`, `_USABLE_W = 180 mm`
- `_LINE_H = 4.5` — compact body line height

**`_safe(text)`** — normalises typographic characters before latin-1 encoding: em-dash→`-`, en-dash→`-`, curly quotes→straight, NBSP→space, `�`→`?`.

**fpdf2 pitfalls**:
- `pdf.ln()` with no argument advances by the last cell's height; `pdf.ln(N)` adds N mm on top of current position (additive, not absolute). Always use `pdf.ln()` (no arg) to advance after a cell row, then `pdf.ln(N)` only for inter-block gaps.
- Mixing Helvetica and Courier fonts mid-row does not affect cell height but may affect visual baseline.
- **`_table` supports multi-line cells**: data rows use `multi_cell(w, base_h, text, new_x="RIGHT", new_y="TOP")` with per-row height computed from `max(cell.count("\n") + 1)`. Shorter cells are padded with trailing `"\n"` to match row height. Pass `"\n"`-joined strings for multi-value cells; the `_device_identification` function does this when `value` is a list.

**PDF sections** (in order): cover page → chain of custody (P1 hashes) → pipeline summary → device identification → flight section(s) → artefact coverage → data quality + anomaly detail → further investigation → Appendix A (hash manifest) → Appendix B (evidence derivation) → Appendix C (tool invocation log) → Appendix D (DFDOF overview).

**`_flight_section()`** produces per-flight pages: correlation summary, flight metrics, key events table, warnings, correlated artefacts, sensor telemetry plots (FR 4-panel + drone log 6-panel), and ground track scatter. The "Correlation and Flight Window" subsection renders one block per `flights_identified` segment: SHA-256 hash (`_kv_hash`), source filename (`_kv`, derived from `_sha_to_name` which maps sha256 → `Path(source_path).name` of the P5 artefact — no `norm_` prefix), Start, End, Duration. Each telemetry plot is followed by a GPS measurement uncertainty note rendered as italic 7pt grey (`set_font(_FONT, "I", 7)`, `set_text_color(120, 120, 120)`, `multi_cell(_USABLE_W, _LINE_H, ...)`), matching the ground track caption style: the FR note covers satellite count ranges (≥10 good / <4 poor) and their effect on positional reliability; the drone log note covers hDOP thresholds (< 1.5 very precise / > 5.0 flagged), DJI ±1.5 m manufacturer spec, and a brief Bayesian LR context statement. Ground track uses `h=220 mm` constraint, `w=int(_USABLE_W*0.80)`, centred. If a KML file exists (resolved via `_find_kml_path(state, dl_csv)`), a forensic evidence disclosure note appears below the track.

**`_p5_anomaly_detail()`** — per-file breakdown of P5 checks. Groups `derived_anomalies` by `evidence_category` in order `databases → drone_logs → flight_logs → flight_records → account_data → images → videos`. For `images`/`videos`, resolves original media filename via `evidence_sha256 → P3/P4 artefact` dict (not the `_exif.json` sidecar name). Recognised keys: `database_empty`, `format`/`entries`, `exif_contains_no_norm_time`, `exif_contains_no_gps`, all `_ROW_CHECKS` (list of row indices), all `_COL_CHECKS` (list of column names). Informational keys `norm_date`, `norm_time`, `gps_latitude`, `gps_longitude`, `offset_time` are silently skipped.

**`reporting/plots.py`** — three public functions:
- `plot_flight_record(csv_path, events, flight_id, tmp_dir)` — 4-panel figure (altitude+speed / attitude / battery / GPS); columns: `OSD.height [m]`, `CALC.hSpeed [m/s]`, `OSD.pitch/roll/yaw`, `CENTER_BATTERY.relativeCapacity`, `OSD.gpsNum`. Event markers overlaid via `_parse_event_times()`.
- `plot_drone_log(csv_path, flight_id, tmp_dir)` — 6-panel 3×2 figure (IMU altitude, GPS hDOP, velocity N/E/D, accelerometer magnitude, IMU attitude, GPS satellite count). Uses `IMUCalcs(0):height:C`, `GPS:hDOP`, `IMUCalcs(0):vel[N/E/D]:C`, `IMUCalcs(0):accelComposite:C` (falls back to raw axes), `IMU_ATTI(0):[roll/pitch/yaw]:C`, `IMU_ATTI(0):numSats`.
- `plot_flight_track(fr_csv, dl_csv, kml_path, flight_id, tmp_dir)` — lat/lon scatter coloured by altitude. When both sources available: stacked 2×1 subplots (nrows=2, figsize `(11, 20)`). **Shared colormap** (`plasma`) and shared `vmin`/`vmax` across both panels so colours are directly comparable. Returns PNG path or `None` if no GPS data.

**`_find_kml_path(state, dl_csv)`** — given the P5 normalised drone log CSV (e.g. `norm_FLY005.csv`), strips the `norm_` prefix to recover the DatCon output stem (`FLY005`), then scans `tool_invocation_log` for the `datcon` entry whose `output_paths` contains a `.csv` with that stem and returns the corresponding `.kml` path. Returns `None` when `dl_csv` is `None` (FR-only flight).

**`tools/` directory** — confirmed files: `datcon.py`, `exiftool.py`, `extractdji.py`, `txtlogtocsv.py`. No `sqlite.py`, `djilogparser.py`, or `drop.py` exist.

**Runtime dependencies** (from `requirements.txt`): `fpdf2>=2.8`, `matplotlib>=3.10`, `pandas>=2.0`; test deps: `pytest>=8.0`.

---

## Parsing Module Index

| File | Key Functions | Behaviour |
|---|---|---|
| `parsing/extract_logical.py` | `extract_logical_files()`, `ensure_unique_path()`, `copy_zip_member()`, `enumerate_zip_listing()` | ZIP member extraction with flat-basename output and SHA-256 verification. `ensure_unique_path()` avoids collisions by scanning parent dir once. `copy_zip_member()` streams 1 MB chunks and returns SHA-256; caller verifies against `hash_file()`. No `state` parameter — provenance covered by Evidence objects. |
| `parsing/extract_physical.py` | `extract_tsk_image()`, `enumerate_image_listing()`, `parse_mmls_offset()`, `run_command()` | Sleuth Kit (mmls/fls/icat) physical image extraction. `parse_mmls_offset()` returns best sector offset (skips start=0, unallocated, meta rows; prefers primary/logical). icat output written to `<out>.tmp` then renamed atomically; `.tmp` unlinked on failure. |
| `parsing/parser_ios.py` | `parse_ios_backup()` → `ConversionResult` | iTunes backup: reads `Manifest.db` for hash→domain mappings, exports files into `domains/` tree. Produces `backup_info.json` and a CSV index. |
| `parsing/parser_android.py` | `parse_android_source()` → `ParsedAndroidResult` | 2-layer metadata: `DeviceInfo.xml` / `ApplicationInfo.xml` → sys props (`ro.serialno`, `net.hostname`, `packages.list`). Assembles `backup_info.json`. Target files: `{"DeviceInfo.xml", "ApplicationInfo.xml", "ro.serialno", "net.hostname", "packages.list"}`. |
| `parsing/utils_parse.py` | see below | Path sanitisation, plist/XML/JSON parsing, scalar normalisation, field extraction |

**`utils_parse.py` key helpers:**
- `sanitise_path(relative_path)` — strips `..`, replaces unsafe chars with `_`
- `safe_segment(value)` — single path segment sanitisation
- `normalise_path(value, *, to_lower)` — `PurePosixPath.as_posix().lstrip("./")`. **Do not use** inside P3 Android extraction loops — those use `.replace("\\","/").lower()` for consistency.
- `normalise_scalar(value)` — strips/coerces to `str | None`
- `parse_plist_file(path)` — lenient, returns `{}`; `parse_plist_strict(path)` — raises on failure, wraps non-dict roots as `{"value": data}`
- `parse_android_xml_map(path)` — Android SharedPreferences `<map>` → name→value dict
- `parse_json_file(path)` — returns `{}` on failure
- `parse_java_properties(path)` — Java `.properties` key=value; handles `#`/`!` comments and backslash escapes
- `match_labeled_value(text, labels: tuple[str, ...])` — pattern-cached per labels tuple; matches `key: value`, `key=value`, and plist XML form. **Must pass a tuple, not a list**.
- `decode_base64(value)` — base64 → UTF-8 string, `None` on failure
- `ieee754_long_to_degrees(value)` — Java long bit-pattern → decimal degrees string
- `decode_cllocation_bplist(value: bytes|str)` — CLLocation NSKeyedArchive binary plist → `{"find_aircraft_last_latitude": ..., "find_aircraft_last_longitude": ..., "find_aircraft_last_altitude": ..., "find_aircraft_last_hacc": ...}`; reads `objects[1]` directly (not UID refs)
- `decode_bytes_blobs(data, _safe)` — recursively decodes `{"__bytes_base64": "..."}` blobs; tries plistlib then UTF-8
- `extract_fields(raw, field_map)` — declarative field extractor: `{"canonical": ([key1, key2], decode_fn_or_None)}`

---

## Tools Module Index

### `tools/datcon.py` — DatCon 4.3.0

| Aspect | Detail |
|---|---|
| Launch | `subprocess.Popen([str(DATCON)])` — GUI tool, no stdin piping |
| Required outputs | `<stem>.csv` + `<stem>.kml` (checked via `"".join(p.suffixes).lower()`) |
| Validation | `_datcon_output_missing(files)` returns `True` if either `.csv` or `.kml` absent |
| User interaction | Loop on `input("done"/"error")`; `"error"` → logs invocation with `return_code=1`, raises P4 anomaly, returns `[]`; incomplete files → prints warning and loops |
| Settings expected | Time Axis: Recording Start; CSV: 30 Hz, Event Log enabled; Log Files section: all disabled; KML: Ground Track enabled |
| Failure handling | `FileNotFoundError` → logs with `return_code=127`, raises P4 anomaly, returns `[]` |
| Returns | `list[Evidence]` — one per output file, `EVIDENCE_TYPE_DECODED`, `ACQUISITION_DATCON` |

### `tools/extractdji.py` — ExtractDJI 1.4.3

| Aspect | Detail |
|---|---|
| Launch | `subprocess.Popen([str(EXTRACT_DJI_EXE), str(dat_path), str(output_dir)])` |
| Required outputs | ≥1 `FLY*.DAT` file in output dir |
| User interaction | Loop on `input("done"/"skip"/"error")`; `"skip"` → logs a failed invocation with stderr noting only GIMBAL files were produced and returns `[]`; `"error"` → logs invocation with `return_code=1`, raises P4 anomaly, returns `[]` |
| Collision handling | `ensure_unique_path()` applied to each `FLY*.DAT` before Evidence creation |
| Returns | `list[Evidence]` — `EVIDENCE_TYPE_EXTRACTED`, `ACQUISITION_EXTRACT_DJI` |

### `tools/exiftool.py` — ExifTool (version probed)

| Aspect | Detail |
|---|---|
| Command | `exiftool -a -u -g1 -s -ee -json -n <file>` |
| Output file | `<stem>_exif.json` — raw stdout written directly |
| JSON shape | Top-level list with one grouped record; nested blocks `File`, `QuickTime`, `Track1`, `PNG`, `JFIF`, `Composite`, etc. |
| Field sets | `_EXIF_IMAGE_FIELDS` (images) / `_EXIF_VIDEO_FIELDS` (videos) — both defined in `tools/exiftool.py`, not `config.py` |
| Version cache | `_EXIFTOOL_VERSION` — probed once via `-ver`, cached as empty string on failure (no retry for the process lifetime) |
| Zero date | `"0000:00:00 00:00:00"` excluded from filtered metadata |
| Returns | `(Evidence | None, Observation | None)` |

### `tools/txtlogtocsv.py` — TXTlogToCSVtool 2018-06-11

| Aspect | Detail |
|---|---|
| Exe resolution | Configured path first; then `shutil.which(exe_path.name)` fallback |
| Command | `[str(resolved_exe), str(txt_path), str(csv_path)]` |
| Failure conditions | exe not found, `OSError`, non-zero return code, missing/empty CSV → all raise anomaly and return `None` |
| Cleanup | Empty output dir removed on failure |
| Returns | `Evidence | None` — `EVIDENCE_TYPE_DECODED`, `ACQUISITION_TXTLOGTOCSV` |

---

## Known Pitfalls

- **`output_dir` import vs locals in p4** — `config.output_dir()` is imported by name into `p4_decision_and_orchestration.py`. Loop-local output directories are named `tool_output_dir` to avoid shadowing the import.
- **`_PHASE_NAME` convention** — P2, P3, P4, P5, and P6 define `_PHASE_NAME = Path(__file__).stem` at module level. All uses of the phase's own name string reference this constant, not a literal.
- **`SOURCE_IDENTIFICATION_TYPES` is an ordered list** — canonical source order: android → ios → drone_sd → drone_flight_storage. All phases iterate it directly (no `sorted()`).
- **Drone SD folder numbering** — all phases call `find_input_evidence_list_by_identification(state, IDENTIFICATION_DRONE_SD)` and use `enumerate(..., start=1)`. Because `state.input_evidence` order is fixed after P1, the same source always gets the same number in every phase.
- **`find_input_evidence_list_by_identification` operator override** — `identified_by_operator_as` always takes precedence over `identified_as` when set; synced back to `evidence.source_identification` in `prompt_phase_1_summary_and_confirm`. This is the single lookup used by P2, P3, P4, P5.
- **ExifTool JSON shape** — file is a top-level list containing one grouped record with nested blocks. P5 must read nested fields recursively; cannot assume a flat dict. `File.MIMEType` drives opaque image decoding; `QuickTime`/`ExifIFD` drive timestamps; `GPSCoordinates` accepted for videos.
- **`_parse_account_file` dispatcher in p4** — routes by suffix (`.plist`/`.xml`/`.json`). For `.xml`, selects `_ANDROID_DJI_PILOT_FIELDS` if `"pilot"` is in the stem, else `_ANDROID_DJI_GO4_FIELDS`. Returns `(raw_safe, filtered)` — `raw_safe` is `json_safe(raw)` with `FIND_AIRCRAFT_LAST_LOCATION.LAST_LOCATION` already decoded in-place.
- **`_decode_find_aircraft_location` patches raw_safe in-place** — reads `LAST_LOCATION` bytes from `raw`, decodes via `decode_cllocation_bplist`, removes the blob from `raw_safe["FIND_AIRCRAFT_LAST_LOCATION"]`, inlines decoded coordinate fields. `LAST_LOCATION` is always `bytes` (from plist) or absent (JSON re-parse); no `{"__bytes_base64": ...}` form appears on disk after first run.
- **`decode_cllocation_bplist` reads values directly from `objects[1]`** — CLLocation stores coordinate floats as direct values, not UID references. Do not add UID-indirection logic.
- **`json_safe` datetime formatting** — datetimes serialised as `isoformat(timespec="seconds")` + `"Z"` when no timezone offset, ensuring plist `<date>` values render as `"2018-04-19T17:24:45Z"` not with microseconds.
- **`compact_json` does NOT sort keys** — uses insertion order only. Do not add `sort_keys=True`.
- **`compact_json` collapses scalar arrays and two P5 column-check keys** — integer-only arrays collapsed to single line; `contains_no_value` and `contains_constant_value` string arrays also collapsed. Single-key `{"evidence_sha256": "..."}` objects collapsed to one line.
- **DatCon required outputs are `.csv` and `.kml` only** — event log (`.log.txt`) and config log (`.config.txt`) are disabled. Validation uses `"".join(p.suffixes).lower()` to match compound extensions.
- **DatCon height column is `IMUCalcs(0):height`** — P5 uses this (sensor-fused, Kalman-filtered) for `altitude_negative`, `altitude_spike`, and `motor_airborne_off`. `IMU_ATTI(0):relativeHeight` (raw barometric) is not used because it can legitimately drift below 0 m, producing false positives.
- **`Clock:offsetTime` is seconds** — a float in seconds (e.g. `575.545`), not ticks. `clock_val - prev_clock` gives elapsed seconds directly.
- **P5 column-level checks** — `contains_no_value` and `contains_constant_value` list **column header names**, not row IDs. Computed as a post-pass. `[NORM]:*` columns are excluded.
- **P5 opaque-extension image decoding** — `.thumbnail` and `.THM` are decoded via `MIMEType` from their ExifTool JSON. `_MIME_TO_EXT = {"image/jpeg": ".jpg", "image/png": ".png", ...}`. Only fires when source extension is in `_OPAQUE_IMAGE_EXTENSIONS = {".thumbnail", ".thm"}`.
- **P3–P5 output ordering** — All phase output lists (`extracted_artefacts`, `decision_and_orchestration_artefacts`, `derived_observations`, `normalised_artefacts`) are sorted at the end of `run_phase_*` by `(artefact_category, stored_path)` to guarantee deterministic `state.json` output regardless of ZIP/filesystem enumeration order. `derived_anomalies` in P5 was already sorted by `_anomaly_sort_key` (id_rank, category, stored_path).
- **P3 module-level caches are built at import time** — `_ARTEFACT_EXTENSIONS_LOWER` and `_ARTEFACT_EXTENSIONS_DRONE_SD_LOWER` computed once at module load. If `ARTEFACT_EXTENSIONS` is patched at runtime (e.g. `monkeypatch`), these dicts will be stale.
- **P1 detection functions take pre-normalised listing** — `_is_ios_logical_backup()` etc. accept `norm: list[str]` (output of `[normalise_path(p) for p in listing]`). `identify_source()` normalises once and passes the result to all four. Direct test calls must pass a pre-normalised list.
- **`_decode_image` / `_process_exif` accept optional `exif_data`** — P5's `ACQUISITION_EXIFTOOL` branch loads the JSON once and passes it to both to avoid double file read. Omitting `exif_data` is correct outside this loop — functions self-load.
- **ExifTool version probe cached for process lifetime** — empty string cached on failure, no retry. Tests patching `subprocess.run` after a failed probe will see the cached result.
- **`SourceRecord` is a dataclass in P1, dicts everywhere else** — `run_phase_1` stores `[r.to_dict() for r in p1_outputs]`. All downstream code reads from `state.phase_outputs["p1_provenance"]["identified_evidence"]` as plain `dict[str, Any]`.
- **`_augment_csv` driver vs format wrappers** — `_augment_csv` owns file I/O, `_apply_shared_checks`, and `_check_column_values`. Each format wrapper defines three closures: `_bind(header)`, `_norm_header(header, idx)`, `_process_row(row_id, padded, idx, acc)` returning 8-tuple. Mutable prev-clock/prev-dt state uses a single-element `list[float | None]` so closures can mutate it.
- **P3 uses `.replace("\\", "/").lower()` throughout for Android extraction** — `_android_discover_scope_roots` and Android logical loop normalise with `name.replace("\\","/").lower()`. `normalise_path` is **not** used in these paths.
- **P5 flight_log handling reads P3 directly** — `FLIGHT_LOGS` artefacts skipped by P4, handled in P5 by a loop reading `p3_artefact_extraction.extracted_artefacts` filtered to `artefact_category == FLIGHT_LOGS`.
- **`_norm_msg` cross-format log normalisation** — iOS `.dat` logs (`json_array_log`) use `[Warning] msg` while FlightRecord CSVs (`APP_WARN`) use `Warning:msg`; punctuation varies; non-breaking spaces (`\xa0`) and Unicode replacement chars (`�`) appear. `_norm_msg`: lowercase → strip NBSP/`�` → collapse punctuation (`[,.:;!?[]]`) → normalise whitespace.
- **P6 `sha_to_source` covers P3 + P4 artefacts** — must include P3 artefacts because `FLIGHT_LOGS` are extracted in P3 and skipped by P4; flight_log P5 observations reference P3 sha256s. Constructed as `{a.get("sha256"): a.get("source_identification") for a in (*p4_artefacts, *p3_artefacts)}`.
- **P6 FR deduplication before correlation** — `_deduplicate_fr_candidates` runs on `fr_candidates` before the FR↔drone matching loop. Two FRs are considered the same physical flight when their temporal overlap ≥ `_OVERLAP_MIN_S` (60 s) AND their duration difference < `_FR_DEDUP_DURATION_DIFF_S` (5 s). The candidate with more GPS points is kept; ties keep the first. This prevents flight count inflation when multiple DJI apps record the same flight.
- **P6 `app_version` in candidate dict and event source strings** — `_build_candidate` reads `DETAILS.appVersion` from rows via `_fr_log_start_extras` and stores it as `cand["app_version"]`. All six event-building functions (`_boundary_events`, `_peak_height_event`, `_motor_events`, `_fly_mode_events`, `_log_message_events`, `_state_change_events`) append ` (v<version>)` to the `source` field when `app_version` is non-null. Drone log candidates have `app_version=None` (no DETAILS columns) and are unaffected.
- **P3 Android extraction: two-stage bundle ID resolution** — Primary source is P2's `backup_info.json` `"Installed Applications"` list. If that list is empty (acquisition tool produced no `ApplicationInfo.xml` or `packages.list`), P3 falls back to probing all known bundle IDs from `DJI_APP_DOMAINS["android"]` in `config.py` directly against the archive/image member paths. If roots are found via fallback, an anomaly is raised (`"falling back to config-defined bundle IDs for extraction"`) and extraction continues normally. If no roots are found even after fallback, extraction is aborted with anomaly `"no known DJI app directories found in archive/image"`. iOS uses `_ios_discover_app_roots` (no fallback needed — domain directories are always present in the parsed tree). `_scope_filter_entries` is the physical-branch helper that mirrors the logical member-filter loop.
- **P3 physical Android `_scope_filter_entries`** — takes `precomputed_entries: list[tuple[str, int, str]]`, `scope_roots`, `path_tokens`, `ext_set`. Constructs `category_roots` as Cartesian product, filters entries by `path_lower.startswith(cat_root)` (case-insensitive — fls output preserves filesystem casing, scope roots are always lowercase). Deduplicates by normalised path. The filtered `scoped_entries` are passed directly to `extract_tsk_image` with `include_paths=None` — no substring filter inside `extract_tsk_image`.
- **`.info` sidecar files in P4/P5** — `VIDEOS` artefacts with `.info` extension are parsed by `parse_java_properties()` in P4. P5 emits GPS-only observations for these (no timestamp, since `CaptureDate` is local time without timezone).
- **P6 `_build_flight_dict` event ordering** — events from both FR and drone candidates are collected then sorted by timestamp string. `_bbox` is an internal key stripped before writing `timeline_flightXX.json`.
- **P6 flight ID assignment is post-sort** — `flight_id` values (`flight_01`, `flight_02`, …) are assigned by iterating `enumerate(flights, start=1)` **after** `flights.sort(...)`. This guarantees `flight_01` always has the earliest start timestamp. Do not assign IDs during the matching loop — they would be based on discovery order, not chronological order.
- **P3 drone flight storage extracts to `drone_logs/` subfolder** — DAT files are extracted to `drone_flight_dir / safe_segment(DRONE_LOGS)` (i.e. `drone_flight_storage/drone_logs/`), not directly into `drone_flight_storage/`. This matches the category-subfolder pattern used for all controller sources.
- **P3 drone flight storage supports both ZIP and physical images** — `_extract_flight_storage_sources()` handles ZIP archives (exported DAT files) and `.001`/`.E01` physical images. The physical branch uses `extract_tsk_image()` with cached P1 `image_metadata` entries (same as drone SD physical), filtering to `.dat` extension only. `SYS.DJI` and other non-DAT files are skipped at the entry-filter step before `extract_tsk_image()` is called. Test: `test_run_phase_3_drone_flight_storage_physical` — patches `parsing.extract_physical.run_command` (not `p3.run_command`) because `extract_tsk_image` calls `run_command` from its own module namespace.
- **P6 drone log GPS timestamps are firmware-garbage before GPS fix** — DatCon `GPS:dateTimeStamp` emits year-3236 sentinels and year-1980 GPS-epoch defaults before the drone's GPS module acquires a proper lock. `_get_ts()` rejects years outside `_VALID_YEAR_MIN=2006`–`_VALID_YEAR_MAX=2099`. `_anchor_drone_timestamps()` then derives absolute UTC for all rows by combining the first valid GPS timestamp with `Clock:offsetTime` (a monotonic counter that is always reliable): `UTC(row) = anchor_utc + (row_clock - anchor_clock) s`. Drone candidates use the injected `[DERIVED]:UTC` column, not `[NORM]:GPS:dateTimeStamp`, for temporal correlation and `time_index`.
- **P7/P8 confidence labels** — `"corroborated"` means values agree AND at least one source is drone-side (independent corroboration); `"controller-only"` means values agree but all observations came from the controller ZIP only. Renamed from `"multi-source"`/`"single-source"` to avoid confusion with the Sources count column in the report.
- **DatCon GPS column naming varies by drone platform** — Newer platforms (Mavic Air, etc.) use `GPS:Lat`/`GPS:Long`; Phantom 3 and older platforms use `GPS(0):Lat`/`GPS(0):Long`. Similarly, motor-state and fly-mode column names differ. P6 uses `_DRONE_LAT_CANDIDATES`, `_DRONE_LON_CANDIDATES`, `_DRONE_MODE_CANDIDATES`, `_DRONE_MOTOR_CANDIDATES` (ordered tuples) resolved via `resolve_col(header, *candidates)` at candidate-build time. Resolved column names are stored in the candidate dict (`lat_col`, `lon_col`, `mode_col`, `motor_col`). If a column resolves to `""`, the corresponding event type (motor/fly-mode) is silently skipped. `resolve_col` is in `phases/utils_phase.py`; it tries exact match for each candidate first, then a prefix fallback for DatCon `:C`/`:D` type suffixes.
- **`resolve_col(header, *candidates)` in utils_phase** — returns the first candidate column name found in `header`. Tries all candidates as exact matches first; then falls back to prefix matching (column name starts with `candidate + ":"` or `candidate + " "`). Returns `None` if no candidate matches. Generalises P5's private `_find_col(header, base)` (which returns an index for a single base) to support multiple candidates and return the matched name.
- **P6 corroboration pass for controller-cached drone logs** — DJI apps (Go 4, Fly) cache a copy of the drone's raw DAT log on the controller device (e.g. `FlightRecords/MCDatFlightRecords/`). These are extracted as `DRONE_LOGS` by P3 and processed by DatCon in P4. After the primary FR↔DL matching loop and the solo-FR loop, a corroboration pass iterates unmatched DL candidates whose `source_identification` is in `_CONTROLLER_SOURCES = frozenset({IDENTIFICATION_CONTROLLER_IOS, IDENTIFICATION_CONTROLLER_ANDROID})`. For each, it computes the composite time window (min-start, max-end) of every existing flight and checks temporal overlap against `_OVERLAP_MIN_S` and `_OVERLAP_MIN_FRACTION`. The best-matching flight receives an extra `flights_identified` entry (no event building — events are captured from the primary DL). Composite windows are fixed at primary-match extent and NOT updated when a corroborating entry is added, preventing cascading matches. A controller DL with no sufficiently overlapping flight stays as a solo unmatched flight. `flights_identified` can therefore have 3 entries for a fully-corroborated flight (FR + drone-side DL + controller-cached DL).
- **P6 DL spanning multiple flights (known limitation)** — DJI logs from drone power-on to power-off in a single DAT/CSV, but a pilot may land, reconnect the app, and take off again within one power cycle. This produces one DL covering multiple FR sessions (e.g. DL 18:22–18:35 with motor-off gap at 18:28–18:29, FR1 18:25–18:28, FR2 18:29–18:34). P6 correctly identifies these as two separate flights (motor off between them = distinct flights), but both flights draw telemetry from the same DL CSV. `_flight_csv_paths` assigns the DL to the first flight that references it in `flights_identified`; the second flight gets no DL plot and no drone-side ground track. Splitting the DL CSV by motor-on/off segment and assigning segments per flight is a v2 enhancement — not implemented in this proof of concept.

---

## Structural Rules

1. **Object Segregation** — Root extraction directories are never wrapped in `Evidence`. Only `backup_info.json` and raw functional artefacts get Evidence objects.
2. **Provenance Lineage** — Every derived artefact must set `parent_sha256` to its source Evidence's `sha256`.
3. **Path Flattening** — Logical extractions write flat basenames via `extract_logical_files()`. Physical extractions flattened by `_flatten_extracted_files()` inside `parser_android.py`. Fresh Evidence object created via `Evidence.from_dict({**item.to_dict(), "stored_path": str(target_path)})` — original hashes preserved.
4. **Normalised Metadata Keys** — Values from `backup_info.json` must use exactly these scalar keys: `product_name`, `product_version`, `device_name`, `backup_date`, `serial_number`, `unique_identifier`, `installed_dji_apps`.
5. **`_PHASE_NAME` constant** — every active phase defines `_PHASE_NAME = Path(__file__).stem` and references it consistently.
6. **`CONTROLLER_ARTEFACT_CATEGORIES` ordering** — alphabetical; P4/P5 iterate it for per-source per-category processing.

---

## Forensic Guardrails

- **Immutability** — `Evidence._IMMUTABLE_ONCE_SET = frozenset({"sha256", "sha1", "hash_timestamp", "parent_sha256"})`. `__setattr__` raises `AttributeError` if any of these fields is reassigned when already truthy. `from_dict()` uses `cls.__new__(cls)` to bypass `__post_init__` and set all fields cleanly.
- **Fault Tolerance** — Empty DB schemas, corrupt XML, 0-byte logs → catch silently, call `state.raise_anomaly()`, continue pipeline. Never raise from anomaly paths.
- **Dual Hashing** — Every Evidence object carries SHA-256 (primary) + SHA-1 (secondary) computed at construction time using 1 MB chunks (`hash_file()`).
- **Zero-byte rejection** — `_filter_empty()` in P3 moves 0-byte extracted files to `output_dir()/case_id/_rejected/` (case-scoped). No Evidence objects created for rejected files. Anomaly: `"empty file moved to _rejected: <name>"`.
- **icat atomic write** — icat output written to `<out_path>.tmp`, returncode validated, then `icat_tmp.replace(out_path)`. On failure: `.tmp` unlinked, `RuntimeError` raised. Applies in `extract_physical.py` and P3's `_extract_drone_sd_physical`.
- **State atomic write** — `state.save()` writes to `.tmp` then renames, preventing partial state on crash.
- **ZIP member verification** — `extract_logical_files()` verifies `archive_hash == file_hash` (both SHA-256) after extraction; raises `RuntimeError` on mismatch.

---

## Schemas

### `backup_info.json` (canonical P2 output)

```json
{
  "product_name":        "iPhone 8",
  "product_version":     "13.5",
  "device_name":         "My iPhone",
  "backup_date":         "2020-06-01T12:00:00+00:00",
  "serial_number":       "F2LT4XXXXXXX",
  "unique_identifier":   "abcd1234...",
  "installed_dji_apps":  ["com.dji.go", "dji.go.v4"]
}
```

### `state.json` shape

```json
{
  "operator": "...",
  "case_id": "...",
  "start_time": "...",
  "evidence_directory": "...",
  "completed_phases": ["p1_provenance", "p2_image_parsing", "..."],
  "anomaly_flags": ["[p1 - controller ios]: ..."],
  "input_evidence": [{"source_path": "...", "sha256": "...", "...": "..."}],
  "phase_outputs": {
    "p1_provenance": {
      "completed_at": "...",
      "identified_evidence": [{"source_path": "...", "identified_as": "controller_ios", "...": "..."}],
      "operator_final_confirmation": {"accepted": true, "timestamp": "..."},
      "image_metadata": {}
    },
    "p3_artefact_extraction": {"extracted_artefacts": ["..."]},
    "p4_decision_and_orchestration": {
      "decision_and_orchestration_artefacts": ["..."],
      "derived_observations": ["..."]
    },
    "p5_normalisation_and_anomaly_checking": {
      "normalised_artefacts": ["..."],
      "derived_anomalies": ["..."]
    },
    "p6_multisource_correlation": {
      "flight_count": 1,
      "flights": [{"stored_path": "...", "flight_id": "flight_01", "...": "..."}]
    },
    "p7_analysis_and_validation": {"...": "see analysis.json schema below"}
  },
  "tool_invocation_log": [{"timestamp": "...", "tool_name": "datcon", "version": "4.3.0", "...": "..."}]
}
```

### `timeline_flightXX.json` (P6 output per flight)

```json
{
  "generated_at": "2024-01-01T00:00:00+00:00",
  "flight_id": "flight_01",
  "flights_identified": [
    {"evidence_sha256": "abc...", "start": "2018-04-19T11:24:46+00:00",
     "end": "2018-04-19T11:34:21+00:00", "duration_s": 575.0}
  ],
  "correlation_metadata": {
    "matched": true, "rule": "primary", "confidence": "high",
    "overlap_s": 571.0, "median_distance_m": 4.32, "match_rate": 0.9871
  },
  "plausibly_correlated": ["p5:sha256hex..."],
  "possibly_correlated": [
    {"source": "controller_ios: flight_logs", "source_pointer": "p5:sha256hex...",
     "data": {"format": "json_array_log", "entry_count": 42}}
  ],
  "events": [
    {
      "timestamp": "2018-04-19T11:24:46+00:00",
      "timezone": "UTC",
      "source": "controller_ios:flight_records",
      "source_pointer": "sha256hex:0",
      "event": "Log started",
      "data": {"latitude": 52.1, "longitude": 4.3, "altitude": 10.0, "serial_drone": "..."},
      "confidence": "high"
    }
  ]
}
```

`_bbox` is an internal field stripped before writing. State summary under `phase_outputs["p6_multisource_correlation"]` omits `events`.

### Event labels (canonical)

`Log started`, `Log ended`, `Motor turned on`, `Motor turned off`, `Reached peak height`, `Fly mode changed`, `Log message`, `Record mode changed`, `Photo mode changed`, `SD storage is full`, `Plausible media metadata correlation found`

### P7 `analysis.json` shape (stored in state)

Full key list of `phase_outputs["p7_analysis_and_validation"]`:
```
completed_at:                 ISO timestamp
flight_count_analysed:        int
source_coverage:              [{"source": "controller_android", "detected": true}, ...]
artefact_coverage:            [{"category": "databases", "count": 3, "notes": [...]}, ...]
artefact_coverage_per_source: [{"source": "controller_ios", "artefacts": [{"category": "...", "count": N}, ...]}, ...]
tool_status:                  [{"tool": "datcon", "invocation_count": 2, "success_count": 2, "status": "ok"}, ...]
account_and_drone_analysis: {
  "drone_serial":        {"value": "...", "corroboration_sources": ["p4:sha...", "sha:rowID"], "confidence": "multi-source"},
  "drone_name":          {"value": "...", "corroboration_sources": [...], "confidence": "single-source"},
  "device_name":         {"value": "...", "corroboration_sources": [...], "confidence": "inconsistent"},
  "account_email":       {"value": "...", "corroboration_sources": [...], "confidence": "inconsistent"},
  "dji_app_version":     {"value": "...", "corroboration_sources": [...], "confidence": "..."},
  "installed_dji_apps":  {"value": [...], "corroboration_sources": [...], "confidence": "..."}
}
flight_analyses: [{
  "flight_id": "flight_01", "matched": true, "correlation_confidence": "high",
  "source_count": 2, "event_count": 47, "high_confidence_event_count": 32,
  "peak_height_m": 42.3, "distance_travelled": 1234.5,
  "photo_taken": false, "number_photos_taken": null,
  "video_taken": true, "duration_recording": 575.0,
  "flight_record_complete": true,
  "flight_modes_observed": ["AutoTakeoff", "GPS", "Atti"],
  "possibly_correlated_count": 2, "plausibly_correlated_count": 1,
  "corroboration_sources": ["sha...", "sha...", "sha..."]
}]
uncorrelated_artefacts:   [{"evidence_sha256": "..."}]
coverage_score: {
  "evidence_sources_detected":        {"value": 3, "total": 4},
  "artefact_categories_with_data":    {"value": 5, "total": 7},
  "flights_with_primary_correlation": {"value": 1, "total": 1},
  "tools_succeeded":                  {"value": 3, "total": 4}
}
conclusions: {
  "case_overview":         ["N evidence source(s) detected: ...", "N flight(s) identified ..."],
  "device_identification": ["Drone serial number: ... (confidence: single-source).", ...],
  "flight_analysis":       ["N media file(s) plausibly correlated by timestamp.", ...],
  "media_analysis":        ["Flight record indicates video recording was initiated.", ...],
  "database_analysis":     ["N database(s) empty (controller_ios) - no records available.", ...],
  "data_quality":          ["Flight_records: N file(s) with row anomalies detected.", ...],
  "further_investigation": ["N flight record(s) could not be correlated ...", ...]
}
```

---

## P5 Flight Log Formats

P5 auto-detects format and extracts `{"timestamp": ..., "message": ...}` pairs. **Readability probe runs first**: reads the first `8192` bytes; if the non-printable character ratio (excluding `\t\n\r`) is > `0.15`, the file is flagged `{"non_readable": True}` and no format classification is attempted. If the file cannot be decoded as UTF-8 at all it is also non-readable.

Detection order (first regex match against the full text wins):

| Format | Detection regex | Trigger pattern | Entry structure |
|---|---|---|---|
| `json_array_log` | `_JSON_ARRAY_LOG_RE` | Matches `["YYYY-MM-DD HH:MM:SS","level","msg"]` | `{"timestamp": "2018-04-19 11:25:15", "message": "[Warning] msg"}` — level prepended in `[brackets]` when non-empty |
| `bracketed_log` (comma) | `_BRACKET_RE` | Matches `[ts, msg]` — comma-separated inside brackets | `{"timestamp": "2018-04-19 11:24:46", "message": "signal lost"}` |
| `bracketed_log` (inline) | `_BRACKET_INLINE_RE` | Matches `[ts]msg` — message follows closing bracket on same line | `{"timestamp": "2018-04-19 11:24:46.601", "message": "check upgrade"}` |
| `crash_dump` | `_CRASH_SECTION_RE` | Matches `=+ Crash =+` section header (case-insensitive) | Java exception: `{"type": "java_exception", "exception": "...", "message": "..."}` or thread crash: `{"type": "thread_crash", "name": "..."}` |
| `heading_log` | `_HEADING_TS_RE` | Matches `## HH:MM:SS` on its own line | `{"timestamp": "11:39:46", "message": "Taking Off"}` — message is the next non-empty line |
| `unknown` | none of the above | — | `[]` — observation still recorded with format key |

**Important ordering note**: `crash_dump` is checked after both `bracketed_log` variants and before `heading_log`. A crash log that also contains bracketed entries will match `bracketed_log` first.

`_norm_msg` normalisation (used in P6 flight log correlation): lowercase → replace NBSP (`\xa0`) and `�` with space → collapse `[,.:;!?[]]` punctuation to space → normalise whitespace.

---

## P5 Anomaly Checks

### Thresholds (exact constants from code)

| Constant | Value | Applies to |
|---|---|---|
| `_BATTERY_CELL_MIN_V` | `2.8` V | FR `battery_cell_voltage_out_of_range` |
| `_BATTERY_CELL_MAX_V` | `4.4` V | FR `battery_cell_voltage_out_of_range` |
| `_BATTERY_CELL_IMBALANCE_V` | `0.3` V | FR `battery_cell_imbalance` |
| `_BATTERY_TEMP_MIN_C` | `-20.0` °C | FR `battery_temperature_out_of_range` |
| `_BATTERY_TEMP_MAX_C` | `80.0` °C | FR `battery_temperature_out_of_range` |
| `_QUATERNION_NORM_EPS` | `0.01` | DatCon `quaternion_invalid` |
| `_GPS_HDOP_THRESHOLD` | `5.0` | DatCon `gps_accuracy_poor` |
| `_GPS_POOR_FIX_SATS` | `4` | both — `gps_poor_fix` fires when satellite count `< 4` |
| `_SPEED_THRESHOLD_MS` | `80.0` m/s | both — `coordinate_jump` |
| `_ALTITUDE_SPIKE_MS` | `20.0` m/s | both — `altitude_spike` fires when `|Δh/Δt| > 20.0` |
| `_TIMESTAMP_GAP_S` | `60.0` s | both — `timestamp_gap` fires when gap `> 60.0 s` |
| `_ALTITUDE_NEGATIVE_M` | `-0.1` m | both — `altitude_negative` fires when height `< -0.1 m` |
| `_MOTOR_AIRBORNE_HEIGHT_M` | `1.0` m | both — `motor_airborne_off` fires when height `> 1.0 m` |

### 9 Shared Checks (DatCon + FlightRecord)

These run inside `_apply_shared_checks()`, called for every data row via `_augment_csv()`.

| Check key | Exact trigger condition |
|---|---|
| `timestamp_regression` | `clock_delta_s < 0.0` — current high-freq clock value is earlier than previous |
| `timestamp_gap` | `clock_delta_s > 60.0` — gap between consecutive rows exceeds 60 s |
| `zero_coordinate` | `lat == 0.0 AND lon == 0.0` — only fires when both are exactly zero (not missing) |
| `missing_gps` | lat **or** lon cannot be parsed as float / is empty — fires instead of `zero_coordinate` |
| `coordinate_jump` | implied horizontal speed > 80.0 m/s, computed as `haversine(prev, cur) / gps_dt_s`; only when GPS Δt ≥ 0.1 s and both rows have valid non-zero coordinates |
| `altitude_negative` | height < −0.1 m (raw float from height column) |
| `altitude_spike` | `|height - prev_height| / clock_delta_s > 20.0`; only when `clock_delta_s > 0.0` and both heights are available |
| `motor_airborne_off` | motor is `off` AND height > 1.0 m; requires both motor state and height to be parseable |
| `gps_poor_fix` | satellite count (integer) < 4 |

**DatCon clock source**: `Clock:offsetTime` (float, seconds since recording start). Delta used for `timestamp_regression`, `timestamp_gap`, `altitude_spike`. `[NORM]:GPS:dateTimeStamp` (1 Hz GPS UTC) used for `coordinate_jump` only.

**DatCon motor state**: `Controller:motor_state` column. Parsed as float; `motor_on = (float_val != 0.0)`. Column found via `_find_col()` which matches on prefix, handling DatCon `:C`/`:D` suffixes.

**FlightRecord clock source**: `[NORM]:CUSTOM.updateTime` (ISO 8601 UTC). Delta computed as `(cur_dt - prev_dt).total_seconds()`. Used for all four interval-based checks (`timestamp_regression`, `timestamp_gap`, `altitude_spike`, and the Δt denominator for `coordinate_jump`). The same column is used for `coordinate_jump` GPS Δt (FlightRecord has 10 Hz GPS aligned with the timestamp).

**FlightRecord motor state**: `OSD.isMotorUp` column. Parsed as `motor_on = (motor_str == "True")` — exact string comparison.

### DatCon-Specific Checks

Run inside `_process_row` of `_augment_datcon_csv()`.

| Check key | Exact trigger condition |
|---|---|
| `gps_accuracy_poor` | `GPS:hDOP > 5.0` (float) |
| `quaternion_invalid` | `|sqrt(quatW²+quatX²+quatY²+quatZ²) − 1.0| > 0.01`; only fires when all four components parse successfully |
| `attitude_out_of_bounds` | `|roll| > 180.0` **or** `|pitch| > 90.0`; roll checked first — if roll fires, pitch is not checked for that row |

### FlightRecord-Specific Checks

Run inside `_process_row` of `_augment_flight_record_csv()`.

| Check key | Exact trigger condition |
|---|---|
| `battery_cell_voltage_out_of_range` | For each of up to 6 cell columns (`CENTER_BATTERY.voltageCell1–6 [V]`): if cell value parses as non-zero float and is `< 2.8` or `> 4.4`, the **row** is appended to this check's list. Fires per-row once per out-of-range cell found; zero-valued cells are skipped. |
| `battery_cell_imbalance` | After collecting all non-zero cell voltages for a row: if `len(cells) >= 2` and `max(cells) − min(cells) > 0.3`, the row is flagged. |
| `battery_temperature_out_of_range` | `CENTER_BATTERY.temperature [C]` float is `< -20.0` or `> 80.0` |
| `motor_on_empty_battery` | `OSD.isMotorUp == "True"` AND `CENTER_BATTERY.relativeCapacity` float `<= 0` |

### Column-Level Checks (both formats, post-pass)

Run in `_check_column_values()` after all rows are processed, using accumulated per-column value lists.

| Check key | Value in observation | Trigger |
|---|---|---|
| `contains_no_value` | list[str] of column header names | Column has **no** non-empty, non-`"nan"` values across all rows |
| `contains_constant_value` | list[str] of column header names | Column has exactly **one** distinct non-empty, non-`"nan"` value across all rows |

All `[NORM]:*` columns are excluded from both checks. Values stored in the observation are column **header name strings**, not row indices.

### EXIF Checks (images and videos)

Run in `_process_exif()` against the ExifTool JSON sidecar. The observation's `evidence_sha256` is set to the **parent** sha256 (original media file), not the JSON's own sha256.

| Check key | Trigger |
|---|---|
| `exif_contains_no_norm_time` | `parse_exif_date` returns `None` — date absent, zero, or has no UTC-confirmable timezone offset |
| `exif_contains_no_gps` | `GPSLatitude`/`GPSLongitude` (flat fields) or `GPSCoordinates` (combined string) cannot be parsed to a lat/lon pair |

`_process_exif` logic: extracts `OffsetTimeOriginal` or `OffsetTimeDigitized` from ExifTool JSON and appends it to `DateTimeOriginal`/`CreateDate` before calling `parse_exif_date`. If no offset field is present, `parse_exif_date` returns `None` (empty timezone → timezone unknown). The early-exit guard is removed — an observation is always emitted when `_exif_root` succeeds, since at least one flag or correlation value is always present.

Informational keys also stored in the same observation dict when present (not anomalies, silently skipped by `_p5_anomaly_detail`): `norm_date`, `norm_time` (format `"HH:MM:SS+00:00"`), `gps_latitude`, `gps_longitude`, `offset_time`.

### Database Check

`database_empty`: opens SQLite in read-only URI mode (`sqlite:///path?mode=ro`); returns `True` if the database has no tables, or all tables have zero rows. Corrupt or non-SQLite files return `False` (no anomaly). Fires once per empty `.db` file as a `derived_anomaly` observation. The `evidence_sha256` in the observation links to the database artefact. Ordered before CSV/log observations because it processes `DATABASES` artefacts first in the P5 source loop, which iterates in `SOURCE_IDENTIFICATION_TYPES` order.

---

## P6 Correlation Rules

### Correlation thresholds (exact constants)

| Constant | Value | Purpose |
|---|---|---|
| `_OVERLAP_MIN_S` | `60.0` s | Minimum temporal overlap (seconds) required for primary rule |
| `_OVERLAP_MIN_FRACTION` | `0.75` | Minimum overlap as fraction of the **shorter** flight's duration |
| `_SPATIAL_WINDOW_S` | `2.0` s | Half-width of the bisect window for nearest-neighbour GPS matching (±2 s) |
| `_SPATIAL_MAX_MEDIAN_M` | `25.0` m | Maximum allowed median haversine distance to accept a spatial match |
| `_SPATIAL_MIN_PAIRS` | `5` | Minimum matched GPS point pairs required to compute a valid median distance |
| `_FR_DEDUP_DURATION_DIFF_S` | `5.0` s | Maximum duration difference between two FR candidates to be considered the same flight |
| `has_usable_gps` | `gps_count >= 10` | Whether a candidate has enough GPS rows for spatial correlation |

### Candidate dict structure

Built by `_build_candidate()`. The dict holds references (not copies) to the row list and header.

| Field | Type | Contents |
|---|---|---|
| `evidence_dict` | dict | Serialised Evidence dict from P5 |
| `rows` | list[dict[str,str]] | All CSV rows, each a dict keyed by header name; short rows padded with `""` |
| `header` | list[str] | Column header names |
| `ts_col` / `lat_col` / `lon_col` | str | Canonical column name constants used for GPS/time lookup |
| `start_dt` / `end_dt` | datetime (UTC-aware) | Earliest and latest parseable timestamps in the CSV |
| `duration_s` | float | `(end_dt - start_dt).total_seconds()` |
| `gps_count` | int | Number of rows with non-zero, non-null lat and lon |
| `has_usable_gps` | bool | `gps_count >= 10` |
| `time_index` | list[tuple[datetime,int]] \| None | Sorted `(dt, row_index)` pairs for O(log n) bisect lookup. Populated for drone log candidates before matching; `None` in FR candidates. |
| `app_version` | str \| None | Read from `DETAILS.appVersion` in the first populated DETAILS row. `None` for drone log candidates (no DETAILS columns). |

### FR deduplication (`_deduplicate_fr_candidates`)

Runs on all FR candidates **before** the FR↔drone matching loop. Two FRs are considered the same physical flight if:
- Their temporal overlap ≥ `_OVERLAP_MIN_S` (60 s), **AND**
- Their duration difference < `_FR_DEDUP_DURATION_DIFF_S` (5 s)

The candidate with more GPS points is kept; ties keep the first occurrence. This prevents flight count inflation when multiple DJI apps (e.g. DJI Go 4 + DJI Fly) record the same flight.

### Primary Correlation Rule (`_correlate_primary`)

Both candidates must have `has_usable_gps = True`. The rule passes if **both** conditions hold:

1. **Temporal**: `overlap_s >= 60.0` AND `overlap_s >= 0.90 * min(duration_fr, duration_drone)`
2. **Spatial**: Median haversine distance of nearest-neighbour GPS pairs ≤ 25 m, with ≥ 5 matched pairs

Spatial matching uses a ±2 s bisect window on the drone candidate's `time_index`. For each FR row with valid GPS, the nearest drone row within that window is found; the haversine distance is computed. `match_rate = matched_pairs / fr_gps_total` is also stored in the output. `overlap_fraction = overlap_s / min_dur` is stored for auditability.

**Confidence** from `_confidence_from_distance(median_m)`:
- `median_m < 5.0` → `"high"` (within DJI ±3 m horizontal spec)
- `median_m < 15.0` → `"medium"` (within ICAO SPS 13 m 95th-percentile)
- `median_m <= 25.0` → `"low"` (approaching acceptance ceiling)

Unmatched FR or drone log candidates each become their own solo flight with `correlation_metadata = {"matched": False}`.

### EXIF correlation (`_correlate_exif_observations`)

Processes all P5 `derived_anomalies` where `acquisition_method == ACQUISITION_NORMALISE`. Only entries with at least a datetime **or** GPS coordinate are considered.

- **Plausible** (datetime match): Requires both `norm_date` and `norm_time` in the observation. `norm_time` carries an explicit `+00:00` suffix (UTC confirmed by `parse_exif_date`). The combined ISO 8601 timestamp `f"{norm_date}T{norm_time}"` is parsed by `_exif_obs_datetime` into a timezone-aware datetime and checked against every `flights_identified` segment using `_flight_covers_dt()`. If it falls within a segment → `"p5:<sha>"` appended to `plausibly_correlated`; a `"Plausible media metadata correlation found"` event is added to the flight's event list.
- **Possible** (GPS-only, no datetime): Only entered when `has_dt` is **False** and the observation has GPS coordinates. The lat/lon is checked against the flight's `_bbox` (union of all GPS bounding boxes from matched candidates). If inside → entry appended to `possibly_correlated`.
- An observation with both datetime and GPS takes the **plausible** path only; the GPS-only path is not entered.

### Flight log correlation (`_correlate_flight_log_observations`)

For each P5 `derived_anomalies` entry with `evidence_category == FLIGHT_LOGS`:
- Skips entries with `format == "crash_dump"` or no message entries.
- Normalises all observation messages with `_norm_msg`.
- Checks whether `norm_messages.issubset(flight_log_messages[flight_idx])` — i.e. every message from the flight log must appear in the flight's `"Log message"` events.
- On match: appended to `possibly_correlated` with `{"format": fmt, "entry_count": len(valid_entries)}`.

### Video duration correlation (`_correlate_video_duration`)

For each P4 `derived_observations` entry with `evidence_category == VIDEOS` and `acquisition_method == ACQUISITION_EXIFTOOL`:
- Extracts `Duration` (seconds float) from the ExifTool observation.
- Compares against `duration_recording` from the first `"Log ended"` event in each flight.
- Match criterion: `|video_duration - log_duration| < 2.0 s`.
- On match: appended to `possibly_correlated` with `{"video_duration_s": ..., "log_duration_s": ...}`.

### Event building

Six functions emit events into the unified timeline. All six append `" (v<version>)"` to the `source` field when `app_version` is non-null:

| Function | Events emitted |
|---|---|
| `_boundary_events` | `"Log started"` (with `_fr_log_start_extras` / `_drone_log_start_extras` data), `"Log ended"` (with distance, height, homepoint distance, photo/video counts) |
| `_peak_height_event` | `"Reached peak height"` at the row with maximum height value |
| `_motor_events` | `"Motor turned on"` / `"Motor turned off"` — emits on initial state and every transition; FR uses `"TRUE"`/`"FALSE"`, drone uses `"1"`/`"0"` |
| `_fly_mode_events` | `"Fly mode changed"` — one event per value transition |
| `_log_message_events` | `"Log message"` — one event per non-empty warn/tip/log column value |
| `_state_change_events` | `"Record mode changed"`, `"Photo mode changed"`, `"SD storage is full"` — transition-based; SD uses `include_initial=False` |

### Event confidence (`_event_confidence`)

Assigned by checking the timestamp string and the GPS coordinate dict:

- GPS present (non-null, non-zero lat/lon) AND timestamp is UTC (`"+00:00"`, `"+0000"`, or `"Z"` suffix) → `"high"`
- GPS present **or** UTC timestamp (but not both) → `"medium"`
- Neither GPS nor UTC timestamp → `"low"`

---

## P7 Analysis Rules

### Identity field collection (`_collect_all_identity_sources`)

Fields are driven by **`_P4_IDENTITY_FIELDS`** — a module-level registry of `(p4_key, display_label, platforms | None)` tuples defined in `p7_analysis_and_validation.py`. Adding a key to any P4 field-map dict and to this registry is sufficient for the field to flow through P7 analysis and the P8 report table automatically.

The third element is a `frozenset[str]` of `source_identification` values that carry this field, or `None` if the field can appear on any platform. Two module-level shorthands: `_IOS = frozenset({"controller_ios"})`, `_ANDROID = frozenset({"controller_android"})`. The "not found" logic in `_forensic_conclusions` silently skips platform-specific fields when the relevant source was not detected in the case, preventing spurious `further_investigation` notices (e.g. `find_aircraft_*` fields on an Android-only case).

**Three sources feed the `fields` dict:**

1. **P2** — `installed_dji_apps` and `device_name` (from `product_name`) are collected explicitly from `DEVICE_AND_BACKUP_INFO` observations. These are P2-only fields not in `_P4_IDENTITY_FIELDS`.

2. **P4** — all keys in `_P4_IDENTITY_FIELDS` are looked up in `ACCOUNT_DATA` observations. Out-key equals p4_key except for three renames defined in `_P4_KEY_TO_OUT_KEY`:
   - `aircraft_sn` → `drone_serial`
   - `cached_product_name` → `drone_name`
   - `app_version` → `dji_app_version`

3. **P6 timeline** — `_P6_TIMELINE_FIELDS` maps exactly three drone-side event data keys to out-keys: `serial_drone→drone_serial`, `name_drone→drone_name`, `dji_app_version→dji_app_version`. **These are the only fields that receive corroboration from an independent drone-side source (DatCon DAT log).** This block is kept explicit — making it generic would obscure the forensic significance of drone-side vs controller-side evidence.

P6 timeline events are read from the stored `timeline_flightXX.json` file (not the compact state summary). `source_type` is `"drone"` if the event's `source` string contains `IDENTIFICATION_DRONE_SD` or `IDENTIFICATION_DRONE_FLIGHT_STORAGE`; otherwise `"controller"`.

**`device_platform`** (P4 key) maps to out-key `device_platform` — it is a separate field from `device_name` (P2-only). Both appear in the report.

### Confidence assignment (`_build_account_and_drone_analysis`)

| Condition | Confidence |
|---|---|
| All collected values agree AND at least one `source_type == "drone"` | `"multi-source"` |
| All collected values agree AND all sources are controller-side | `"single-source"` |
| Values disagree across sources | `"inconsistent"` |

`drone_name` comparison uses `_norm_drone_name()`: strips prefix up to the first `"-"`, removes spaces, lowercases. Distinct normalised names → `"inconsistent"`. `installed_dji_apps` compares full list values (as sorted-tuple); multiple distinct lists → stored as a list-of-lists with `"multi-source"` or `"single-source"`.

### Per-flight analysis (`_analyse_flight`)

Reads `timeline_flightXX.json` from `flight_compact["stored_path"]`. Derives:
- `peak_height_m` — from the first `"Reached peak height"` event's `data.relative_height`
- `distance_travelled` — from the first `"Log ended"` event's `data.distance_travelled`
- `number_photos_taken` — from the first `"Log ended"` event's `data.number_photos_taken`
- `duration_recording` — from the first `"Log ended"` event's `data.duration_recording`
- `distance_to_homepoint` — from the first `"Log ended"` event's `data.distance_to_homepoint`
- `flight_record_complete` — `True` if `distance_to_homepoint < 5.0 m AND log_ended_height < 5.0 m`; `None` if either field is absent
- `photo_taken` — any `"Photo mode changed"` event where `photo_mode` is not `"no"` or empty
- `video_taken` — any `"Record mode changed"` event where `record_mode` is not `"no"` or empty
- `flight_modes_observed` — ordered list of distinct fly modes from `"Fly mode changed"` events (insertion order, no duplicates)

### Uncorrelated artefacts (`_uncorrelated_artefacts`)

A P3 artefact is **uncorrelated** if its full lineage chain (all ancestors + all descendants via `_build_lineage_map`) shares no sha256 with the referenced set. The referenced set is built from:
- `flights_identified[*].evidence_sha256` (P5 normalised flight/drone sources)
- `plausibly_correlated[*]` (stripping `"p5:"` prefix)
- `possibly_correlated[*].source_pointer` (stripping `"p5:"` or `"p4:"` prefix)
- `account_and_drone_analysis[*].corroboration_sources[*]` (stripping `"p2:"`, `"p4:"`, `"p5:"` prefixes and `:rowID` suffixes)

### `_artefact_coverage` EXIF counters

Eight counters for images/videos: `img_with_norm_time`, `img_with_gps`, `img_no_norm_time`, `img_no_gps` (mirror for videos). Incremented mutually exclusively per obs: `exif_contains_no_norm_time` → no-counter; `norm_date` present → with-counter. Same logic for GPS (`exif_contains_no_gps` vs `gps_latitude is not None`). Notes emitted positive-first (`_NOTE_WITH_*` then `_NOTE_MISSING_*`). Four module-level sentinel constants (`_NOTE_MISSING_NORM_TIME`, `_NOTE_MISSING_GPS`, `_NOTE_WITH_NORM_TIME`, `_NOTE_WITH_GPS`) are used both in note f-strings and in `_forensic_conclusions` substring matches to keep them in sync.

### Tool status logic (`_tool_status`)

- `rc == 0` or `rc is None` counts as a success.
- Status: `"ok"` if `success_count == invocation_count`, `"failed"` if `success_count == 0`, `"partial"` otherwise.

### `_forensic_conclusions` section rules

Returns `dict[str, list[str]]` with seven keys. Section order is fixed (insertion order in function body):

| Section key | What it contains | Goes to `further_investigation` instead when |
|---|---|---|
| `case_overview` | Source count, flight count, matched/confidence breakdown | — |
| `device_identification` | Serial, drone model, controller device name, app version, installed apps, email | Any field has `confidence == "inconsistent"` or is absent entirely |
| `flight_analysis` | Plausibly/possibly correlated media counts | Unmatched flights, incomplete flight records |
| `media_analysis` | Video/photo capture indicators; positive EXIF notes ("contain(s) normalised EXIF timestamp / EXIF GPS coordinates") with "correlation is possible" context; negative EXIF notes ("missing (normalisable) EXIF timestamp / missing EXIF GPS coordinates") with "not possible without additional context" | Photos taken → investigate both SD and controller |
| `database_analysis` | Empty database statements | Non-empty databases → investigate |
| `data_quality` | Row anomalies, empty/constant columns, unreadable logs, crash dumps, format info | — |
| `further_investigation` | Overflow from inconsistent fields, unmatched flights, incomplete records, non-empty databases, photo investigation; `"Note: no <field> found - Device and account information."` for each absent identity field (drone serial, drone model, controller device name, DJI app version, installed apps, account e-mail) | — |

## Tests & Running

### Test files (21 files)

```
tests/test_evidence.py              # Evidence hashing, immutability, from_dict round-trip
tests/test_observation.py           # Observation round-trip, stored_path serialisation
tests/test_state.py                 # Tool invocation logging, TSK version detection, atomic save
tests/test_main.py                  # Phase orchestration workflow
tests/test_utils_parse.py           # All utils_parse helpers (decode_base64, ieee754, plist, CLLocation, etc.)
tests/test_utils_phase.py           # json_safe, compact_json, date/time parsing, haversine_m, resolve_col
tests/test_p1_provenance.py         # Source classification (identify_source, _is_* functions)
tests/test_p2_image_parsing.py      # iOS/Android parsing phase
tests/test_p3_artefact_extraction.py# Root discovery, category extraction, empty file rejection
tests/test_p4_decision_and_orchestration.py  # Tool dispatch, account data parsing
tests/test_p5_normalisation_and_anomaly_checking.py  # All anomaly checks and CSV augmentation
tests/test_p6_multisource_correlation.py     # Correlation geometry, event building
tests/test_p7_analysis_and_validation.py     # Coverage score, forensic statements
tests/test_parser_ios.py            # iTunes backup parsing
tests/test_parser_android.py        # Android metadata parsing
tests/test_extract_logical.py       # ZIP extraction, collision handling, hash verification
tests/test_extract_physical.py      # TSK command building, mmls/fls parsing
tests/test_tools_datcon.py          # DatCon output validation
tests/test_tools_exiftool.py        # ExifTool invocation, JSON shape handling
tests/test_tools_extractdji.py      # ExtractDJI output validation
tests/test_tools_txtlogtocsv.py     # TXTlogToCSV exe resolution, failure paths
```

**420 tests** across 21 files.

---

## Files & Commands

### Run the pipeline

```bash
python main.py --operator "Analyst Name" --case-id "CASE-001" \
               --evidence-dir "C:\path\to\evidence" \
               --state-path state.json
```

Arguments are prompted interactively if omitted. The pipeline runs P1→P8 in sequence; state is saved after each phase.

### Environment variables (tool path overrides)

| Variable | Default |
|---|---|
| `DFDOF_SLEUTH_KIT_BIN` | `C:\Users\Floris\Documents\sleuthkit\bin` |
| `DFDOF_EXTRACT_DJI_EXE` | `C:\Program Files (x86)\CsvView\ExtractDJI.exe` |
| `DFDOF_DATCON` | `C:\Program Files (x86)\DatCon\DatCon.4.3.0.exe` |
| `DFDOF_TXTLOGTOCSV` | `C:\Program Files (x86)\CsvView\executables\TXTlogToCSVtool.exe` |
| `DFDOF_EXIFTOOL` | `C:\Users\Floris\Documents\exiftool\exiftool.exe` |
| `DFDOF_TSK_MMLS` | auto-derived from `DFDOF_SLEUTH_KIT_BIN` |
| `DFDOF_TSK_FLS` | auto-derived from `DFDOF_SLEUTH_KIT_BIN` |
| `DFDOF_TSK_ICAT` | auto-derived from `DFDOF_SLEUTH_KIT_BIN` |

### Run tests

```bash
pytest --rootdir=.                # all tests (must be run from project root)
pytest tests/test_p5_normalisation_and_anomaly_checking.py  # single file
pytest -v             # verbose
```

Tests require the working directory to be the project root (`c:\Users\Floris\Documents\DFDOF`) so that `import config` resolves correctly. Running `pytest` from a subdirectory causes `ModuleNotFoundError: No module named 'config'`.

### Output structure

```
~/Documents/dfdof_output/<case_id>/
  p2_image_parsing/
    controller_android_parsed/    # backup_info.json + metadata
    controller_ios_parsed/        # domains/ tree + backup_info.json
  p3_artefact_extraction/
    controller_android/           # by category
    controller_ios/
    drone_sd_1/ drone_sd_2/ ...
    drone_flight_storage/
      drone_logs/                 # DAT files from flight storage ZIP
    _rejected/                    # 0-byte files
  p4_decision_and_orchestration/
    <source_id>/
      drone_logs/                 # <stem>.csv, <stem>.kml (DatCon)
      flight_records/             # <stem>.csv (TXTlogToCSV)
      images/ videos/             # <stem>_exif.json (ExifTool)
      account_data/               # parsed account JSON
  p5_normalisation_and_anomaly_checking/
    <source_id>/
      drone_logs/                 # norm_<stem>.csv
      flight_records/             # norm_<stem>.csv
      images/                     # decoded .thumbnail/.THM files
  p6_multisource_correlation/
    timeline_flight01.json
    timeline_flight02.json ...
  p8_automated_reporting/
    <flight_id>_fr_telemetry.png  # 4-panel flight record sensor plot
    <flight_id>_drone_telemetry.png # 6-panel drone log sensor plot
    <flight_id>_track.png         # flight ground track scatter
  <case_id>_forensic_baseline.pdf # main report
  state.json                      # copy of case state
```

---

## How to Verify

```bash
# 1. Run the full test suite
pytest

# 2. Verify state.json is valid after a run
python -c "import json; s=json.load(open('state.json')); print(list(s['phase_outputs'].keys()))"

# 3. Check ExifTool is found and version cached correctly
python -c "from tools.exiftool import _get_exiftool_version; print(_get_exiftool_version())"

# 4. Verify DatCon output validation logic
python -c "
from tools.datcon import _datcon_output_missing
from pathlib import Path
files = [Path('fly001.csv'), Path('fly001.kml')]
print('missing:', _datcon_output_missing(files))  # should print: missing: False
"

# 5. Verify SOURCE_IDENTIFICATION_TYPES order
python -c "from config import SOURCE_IDENTIFICATION_TYPES; print(SOURCE_IDENTIFICATION_TYPES)"
# Expected: ['controller_android', 'controller_ios', 'drone_sd', 'drone_flight_storage']

# 6. Verify compact_json array collapsing
python -c "
from phases.utils_phase import compact_json
data = {'contains_no_value': ['col_a', 'col_b'], 'rows': [1, 2, 3]}
print(compact_json(data))
"

# 7. Check P5 thresholds
python -c "
from phases.p5_normalisation_and_anomaly_checking import (
    _BATTERY_CELL_MIN_V, _BATTERY_CELL_MAX_V, _SPEED_THRESHOLD_MS, _TIMESTAMP_GAP_S
)
print(_BATTERY_CELL_MIN_V, _BATTERY_CELL_MAX_V, _SPEED_THRESHOLD_MS, _TIMESTAMP_GAP_S)
"  # Expected: 2.8 4.4 80.0 60.0

# 8. Verify tool paths are correctly resolved
python -c "import config; print('DATCON:', config.DATCON); print('EXIFTOOL:', config.EXIFTOOL)"
```

---

## Changelog (vs. previous CLAUDE.md)

1. **Rewrote Phase Map table** — added "Consumes" column and exact state key paths for all outputs.
2. **Expanded Core Module Index** — added exact field lists for `Evidence`, `Observation`, `Content`; added `hash_file()` signature; added `State.log_command_result` and `_get_tsk_tool_version`; added `main.py` section with all CLI flags.
3. **Rewrote Parsing Module Index** — added `extract_physical.py` helpers, `parser_ios.py` `ConversionResult` dataclass, `parser_android.py` `TARGET_FILES` set.
4. **Rewrote Tools Module Index** — structured as tables with exact command flags, return types, and failure paths.
5. **Expanded Known Pitfalls** — added `.info` sidecar handling, `_build_flight_dict` event ordering, P6 `sha_to_source` construction, `compact_json` single-key object collapsing, ExifTool version cache note.
6. **Added Schemas section** — full `state.json` structural example, full `analysis.json` key list (P7), full `timeline_flightXX.json` example with event schema.
7. **P5 Flight Log Formats** — added all regex constant names; added crash_dump thread variant.
8. **P5 Anomaly Checks** — separated into table of exact threshold constants with source variable names; clarified DatCon vs FlightRecord clock source for each check.
9. **P6 Correlation Rules** — added full candidate dict schema; noted `_bbox` is stripped before write; added event confidence rules.
10. **Added Tests section** — listed all 21 test files with one-line descriptions, confirmed 388 test count.
11. **Added Files & Commands section** — full output directory structure, environment variable table, test commands.
12. **Added "How to Verify" section** — copyable shell commands for key code claims.
13. **Removed** the `> claude.md is not definite, and may be outdated.` disclaimer (replaced by accurate content).
14. **(Previous revision)** — Added full `reporting/report_builder.py` and `reporting/plots.py` module documentation; moved P8 from TODOs to Core Module Index; confirmed `tools/` contains only 4 files (no sqlite/djilogparser/drop); corrected `main.py` description to P1→P8; added `requirements.txt` dependencies; noted `pytest` must run from project root; updated TODOs to remove resolved items.
15. **(This revision)** — P1: added `"data/dji"` and `"data/com.dji"` to `CONTROLLER_ANDROID_INCLUDES` for physical Android image classification. P3: fixed case-sensitivity bug in `_scope_filter_entries` (fls paths are mixed-case; comparison now uses `path_lower`); replaced `_remove_empty_dir` entirely with `_no_output.txt` sentinel pattern (`_write_no_output`/`_has_real_output` in `config.py`) across all phases P2–P8. P4: added `product_type`, `aircraft_model_code`, `fly_controller_sn` to Android field maps; `product_type` to iOS field map. P7/P8: replaced three separate hardcoded field lists with single `_P4_IDENTITY_FIELDS` registry; added `_P4_KEY_TO_OUT_KEY` and `_P6_TIMELINE_FIELDS` constants; P8 `_device_identification` now imports and iterates the registry automatically. Added Find Aircraft coordinate fields to registry. Test count: **397**.
16. **(This revision)** — P7: `_P4_IDENTITY_FIELDS` tuple shape extended from `(p4_key, label)` to `(p4_key, label, platforms | None)`; added `_IOS` and `_ANDROID` module-level frozenset shorthands. iOS-only fields (`find_aircraft_*`, `last_launch`, `last_flight_date`) tagged `_IOS`; Android-only fields (`last_latitude`, `last_longitude`, `account_uid`, `account_nickname`, `device_uuid`, `fly_controller_sn`, `aircraft_model_code`) tagged `_ANDROID`. `_forensic_conclusions` "not found" guard now skips platform-specific fields silently when that source was not detected. All iteration sites updated to star-unpack (`*_`). Test count: **397**.
17. **(This revision)** — P3: DAT files from drone flight storage now extracted to `drone_flight_storage/drone_logs/` subfolder (was flat into `drone_flight_storage/`); test assertions added. P6: `flight_id` values reassigned after `flights.sort(...)` so `flight_01` is always the earliest-start flight; `test_flight_ids_assigned_in_chronological_order` added. P7: four positive EXIF counters and sentinel constants (`_NOTE_WITH_NORM_TIME`, `_NOTE_WITH_GPS`, `_NOTE_MISSING_NORM_TIME`, `_NOTE_MISSING_GPS`) added; positive notes emitted before negative in `artefact_coverage`; two new `elif` branches in `_forensic_conclusions`. P8: `_find_kml_path(state, dl_csv)` now per-drone-log (matches stem via tool_invocation_log); `_sha_to_name` dict added; `{label} Name` row added below SHA-256 in flight section; chain-of-custody hash blocks now use `pdf.ln(); pdf.ln(3)` spacing. Test count: **403**.
18. **(This revision)** — P1: fixed `_is_ios_logical_backup()` regex from `[0-9a-fA-F]{2}/[0-9a-fA-F]{2}/` (two nested hex dirs — never occurs in iTunes backups) to `(?:^|/)[0-9a-fA-F]{2}/[0-9a-fA-F]{40}$` (2-char dir + 40-char SHA-1 filename); raised threshold from 50 to 200 (complete backup always has 300+). P7/P8: renamed confidence labels — `"single-source"` → `"controller-only"`, `"multi-source"` → `"corroborated"` — to eliminate confusion with the Sources count column in the report table; badge display updated accordingly. P6: added `_VALID_YEAR_MIN=2006`, `_VALID_YEAR_MAX=2099` year guard to `_get_ts()` to reject DatCon GPS firmware sentinels (year 1980 = GPS epoch default, year 3236 = DJI uninitialized value); added `_anchor_drone_timestamps(rows, ts_col, clock_col)` which uses the first valid GPS timestamp as UTC anchor and `Clock:offsetTime` (a monotonic counter, always reliable) to derive absolute UTC for all drone log rows — fixes correlation failure when GPS lock was not acquired until after the flight record ended; drone candidate building now injects `[DERIVED]:UTC` column and uses it for `_build_candidate()` and `_build_time_index()`; `_DRONE_CLOCK_COL="Clock:offsetTime"`, `_DRONE_COMPUTED_TS_COL="[DERIVED]:UTC"` added as constants; `timedelta` added to imports. Test count: **406**.

20. **(This revision)** — P6: lowered `_OVERLAP_MIN_FRACTION` from `0.90` to `0.75`; updated comment to reflect that DAT logs start at drone power-on while FRs start at app connection (~30–60 s later), and FRs may extend past DAT log end — making 90% too strict for real-world data. `test_insufficient_overlap_fraction_unmatched` updated (offset 15 s → 25 s, fraction 0.83 → 0.71 < 0.75); new `test_overlap_fraction_0_83_matches_with_spatial_confirmation` added to encode the real-world pattern that now correctly matches. Test count: **415**.

19. **(This revision)** — P6: replaced four hardcoded single-column constants (`_DRONE_LAT_COL`, `_DRONE_LON_COL`, `_DRONE_MODE_COL`, `_DRONE_MOTOR_COL`) with ordered candidate tuples (`_DRONE_LAT_CANDIDATES` etc.) to handle DatCon GPS column name differences across drone platforms (Phantom 3 uses `GPS(0):Lat`/`GPS(0):Long`; newer platforms use `GPS:Lat`/`GPS:Long`). `resolve_col(header, *candidates)` added to `phases/utils_phase.py` — tries exact match then prefix fallback for DatCon `:C`/`:D` suffixes; resolves to `None` when not found. Drone candidate building now resolves all four column families at runtime and stores them in the candidate dict; `_event_data_drone` converted to a factory that captures resolved lat/lon column names; motor/fly-mode event building guards on resolved columns (`if motor_col:` / `if mode_col:`). `_compute_spatial` zero-coordinate guard added to reject pre-GPS-lock `(0.0, 0.0)` drone rows from haversine distance calculations. Test count: **414**.

21. **(This revision)** — P6: added second-pass corroboration loop for controller-cached drone logs (`MCDatFlightRecords/`). `IDENTIFICATION_CONTROLLER_IOS`/`_ANDROID` added to P6 imports; `_CONTROLLER_SOURCES = frozenset({...})` constant added. After the solo-FR loop, composite time windows are built from all existing flights' `flights_identified` entries; unmatched DL candidates from controller sources are checked against these windows; those meeting `_OVERLAP_MIN_S` and `_OVERLAP_MIN_FRACTION` are appended to the best-matching flight's `flights_identified` without event building, and excluded from the solo-DL loop. `_make_drone_artefact()` helper extracted in the test file; `_build_p6_state` extended with `extra_drone_paths` parameter; 4 new tests added. P8: `clear_and_make(plots_dir)` instead of `mkdir(exist_ok=True)` so stale plots from previous runs are deleted. Test count: **419**.

22. **(This revision)** — P3: Android extraction now has a two-stage bundle ID fallback. When P2's `backup_info.json` has an empty `"Installed Applications"` list (acquisition tool produced no `ApplicationInfo.xml` or `packages.list`), P3 probes all known bundle IDs from `DJI_APP_DOMAINS["android"]` in config.py against the archive/image paths. If roots are found, extraction continues with an informational anomaly; only aborts if no known DJI dirs are found at all. Both logical and physical branches updated. Two stale tests renamed and updated (`test_run_phase_3_android_logical_no_installed_apps_no_known_dirs_raises_anomaly`, `test_android_physical_no_installed_apps_no_known_dirs_raises_anomaly`) — their ZIP/image content changed to use non-DJI paths so the abort path is still exercised; one new test added (`test_run_phase_3_android_logical_fallback_when_no_installed_apps`) for the fallback success path. Known Pitfall updated. Test count: **420**.

23. **(This revision)** — P3: `_extract_flight_storage_sources()` physical image branch added. Previously the `else` clause raised `"unsupported archive format"` for `.001`/`.E01` inputs; now it calls `extract_tsk_image()` with cached P1 `image_metadata` entries, filtering to `.dat` extension before calling the extractor (so `SYS.DJI` and other non-DAT files are excluded). Known Pitfall added: physical branch test patches `parsing.extract_physical.run_command` (not `p3.run_command`) because `extract_tsk_image` resolves `run_command` from its own module namespace. Test count: **421**.
