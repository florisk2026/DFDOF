"""DFDOF Phase 8 — sensor and track plot generation.

All functions return a Path to a saved PNG in tmp_dir, or None on failure.
Callers embed the PNG into the PDF; no display output is produced.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import matplotlib
matplotlib.use("Agg")  # non-interactive backend — must be set before pyplot import
import matplotlib.pyplot as plt
import matplotlib.ticker as ticker
import pandas as pd


# Public API

def plot_flight_record(
    csv_path: Path,
    events: list[dict[str, Any]],
    flight_id: str,
    tmp_dir: Path,
) -> Path | None:
    """4-panel flight-record figure: altitude+speed / attitude / battery / GPS.

    Returns PNG path or None if the CSV cannot be loaded.
    """
    df = _load_csv(csv_path)
    if df is None:
        return None

    t = _seconds_from_start(df, "[NORM]:CUSTOM.updateTime")
    if t is None:
        return None

    event_times = _parse_event_times(events, df)

    fig, axes = plt.subplots(4, 1, figsize=(10, 10), sharex=True)
    fig.suptitle(f"Flight Record Telemetry - {flight_id}", fontsize=11, fontweight="bold")

    # Panel A — altitude + speed (dual axis)
    ax_a  = axes[0]
    ax_a2 = ax_a.twinx()
    _plot_series(ax_a,  t, df, "OSD.height [m]",    "Height (m)",    "steelblue")
    _plot_series(ax_a2, t, df, "CALC.hSpeed [m/s]", "H-Speed (m/s)", "darkorange", linestyle="--")
    ax_a.set_ylabel("Height (m)",    color="steelblue",  fontsize=8)
    ax_a2.set_ylabel("H-Speed (m/s)", color="darkorange", fontsize=8)
    ax_a.set_title("Altitude and Horizontal Speed", fontsize=9)
    _add_event_markers(ax_a, event_times)

    # Panel B — attitude
    ax_b = axes[1]
    for col, colour, lbl in (
        ("OSD.pitch", "crimson",    "Pitch"),
        ("OSD.roll",  "seagreen",   "Roll"),
        ("OSD.yaw",   "darkorchid", "Yaw"),
    ):
        _plot_series(ax_b, t, df, col, lbl, colour)
    ax_b.set_ylabel("Degrees", fontsize=8)
    ax_b.set_title("Attitude (Pitch / Roll / Yaw)", fontsize=9)
    ax_b.legend(fontsize=7, loc="upper right")
    _add_event_markers(ax_b, event_times)

    # Panel C — battery
    ax_c      = axes[2]
    batt_col  = "CENTER_BATTERY.relativeCapacity"
    _plot_series(ax_c, t, df, batt_col, "Battery (%)", "goldenrod")
    ax_c.set_ylabel("Battery (%)", fontsize=8)
    ax_c.set_ylim(0, 105)
    ax_c.set_title("Battery Capacity", fontsize=9)
    _add_event_markers(ax_c, event_times)
    _annotate_if_zero(ax_c, df, batt_col)

    # Panel D — GPS satellite count
    ax_d = axes[3]
    _plot_series(ax_d, t, df, "OSD.gpsNum", "Satellites", "teal")
    ax_d.set_ylabel("# Satellites", fontsize=8)
    ax_d.set_xlabel("Seconds from recording start", fontsize=8)
    ax_d.set_title("GPS Satellite Count", fontsize=9)
    ax_d.yaxis.set_major_locator(ticker.MaxNLocator(integer=True))
    _add_event_markers(ax_d, event_times)

    fig.tight_layout(rect=[0, 0, 1, 0.96])
    out = tmp_dir / f"{flight_id}_fr_telemetry.png"
    fig.savefig(out, dpi=150, bbox_inches="tight")
    plt.close(fig)
    return out


def plot_drone_log(
    csv_path: Path,
    flight_id: str,
    tmp_dir: Path,
) -> Path | None:
    """6-panel drone-log figure (3 rows x 2 cols):
      E — IMU-fused altitude        F — GPS hDOP
      G — Velocity components N/E/D H — Accelerometer magnitude
      I — IMU attitude (roll/pitch/yaw) J — GPS satellite count

    Returns PNG path or None on failure.
    """
    df = _load_csv(csv_path)
    if df is None:
        return None

    t_col = "Clock:offsetTime"
    if t_col not in df.columns:
        return None
    t = pd.to_numeric(df[t_col], errors="coerce")

    fig, axes = plt.subplots(3, 2, figsize=(14, 10))
    fig.suptitle(f"Drone Log Telemetry - {flight_id}", fontsize=11, fontweight="bold")

    ax_e, ax_f = axes[0]
    ax_g, ax_h = axes[1]
    ax_i, ax_j = axes[2]

    # Panel E — IMU-fused altitude
    col_e = "IMUCalcs(0):height:C"
    _plot_series(ax_e, t, df, col_e, "Height (m)", "steelblue")
    ax_e.set_ylabel("Fused Height (m)", fontsize=8)
    ax_e.set_xlabel("Time (s)", fontsize=7)
    ax_e.set_title("IMU-Fused Altitude", fontsize=9)
    _annotate_if_zero(ax_e, df, col_e)

    # Panel F — GPS hDOP
    col_f = "GPS:hDOP"
    _plot_series(ax_f, t, df, col_f, "hDOP", "tomato")
    ax_f.set_ylabel("hDOP", fontsize=8)
    ax_f.set_xlabel("Time (s)", fontsize=7)
    ax_f.set_title("GPS Horizontal Dilution Of Precision", fontsize=9)
    ax_f.axhline(5.0, color="orange", linestyle=":", linewidth=1, alpha=0.8,
                 label="Poor-fix threshold (5.0)")
    ax_f.legend(fontsize=7)
    _annotate_if_zero(ax_f, df, col_f)

    # Panel G — velocity N/E/D components
    for col, colour, lbl in (
        ("IMUCalcs(0):velN:C", "steelblue",  "North"),
        ("IMUCalcs(0):velE:C", "seagreen",   "East"),
        ("IMUCalcs(0):velD:C", "tomato",     "Down"),
    ):
        _plot_series(ax_g, t, df, col, lbl, colour)
    ax_g.set_ylabel("Velocity (m/s)", fontsize=8)
    ax_g.set_xlabel("Time (s)", fontsize=7)
    ax_g.set_title("IMU Velocity Components (N / E / D)", fontsize=9)
    ax_g.legend(fontsize=7, loc="upper right")
    ax_g.axhline(0, color="grey", linewidth=0.5, linestyle=":")

    # Panel H — accelerometer magnitude (composite if available, else compute)
    accel_composite = "IMU_ATTI(0):accelComposite:C"
    if accel_composite in df.columns:
        _plot_series(ax_h, t, df, accel_composite, "Accel |a|", "darkorchid")
        _annotate_if_zero(ax_h, df, accel_composite)
    else:
        # Compute magnitude from raw axes
        ax_vals = pd.to_numeric(df.get("IMU_ATTI(0):accelX", pd.Series(dtype=float)), errors="coerce")
        ay_vals = pd.to_numeric(df.get("IMU_ATTI(0):accelY", pd.Series(dtype=float)), errors="coerce")
        az_vals = pd.to_numeric(df.get("IMU_ATTI(0):accelZ", pd.Series(dtype=float)), errors="coerce")
        mag = (ax_vals**2 + ay_vals**2 + az_vals**2) ** 0.5
        if mag.dropna().empty:
            ax_h.text(0.5, 0.5, "Accelerometer data not available",
                      transform=ax_h.transAxes, ha="center", va="center",
                      fontsize=8, color="grey", style="italic")
        else:
            ax_h.plot(t, mag, "darkorchid", linewidth=0.8)
    ax_h.set_ylabel("|Accel| (m/s^2)", fontsize=8)
    ax_h.set_xlabel("Time (s)", fontsize=7)
    ax_h.set_title("Accelerometer Magnitude", fontsize=9)
    ax_h.axhline(9.81, color="orange", linestyle=":", linewidth=0.8, alpha=0.7, label="1g (9.81)")
    ax_h.legend(fontsize=7)

    # Panel I — IMU attitude
    for col, colour, lbl in (
        ("IMU_ATTI(0):roll:C",  "crimson",    "Roll"),
        ("IMU_ATTI(0):pitch:C", "seagreen",   "Pitch"),
        ("IMU_ATTI(0):yaw:C",   "darkorchid", "Yaw"),
    ):
        _plot_series(ax_i, t, df, col, lbl, colour)
    ax_i.set_ylabel("Degrees", fontsize=8)
    ax_i.set_xlabel("Time (s)", fontsize=7)
    ax_i.set_title("IMU Attitude (Roll / Pitch / Yaw)", fontsize=9)
    ax_i.legend(fontsize=7, loc="upper right")

    # Panel J — GPS satellite count
    col_j = "IMU_ATTI(0):numSats"
    _plot_series(ax_j, t, df, col_j, "Satellites", "teal")
    ax_j.set_ylabel("# Satellites", fontsize=8)
    ax_j.set_xlabel("Time (s)", fontsize=7)
    ax_j.set_title("GPS Satellite Count", fontsize=9)
    ax_j.yaxis.set_major_locator(ticker.MaxNLocator(integer=True))
    _annotate_if_zero(ax_j, df, col_j)

    fig.tight_layout(rect=[0, 0, 1, 0.96])
    out = tmp_dir / f"{flight_id}_drone_telemetry.png"
    fig.savefig(out, dpi=150, bbox_inches="tight")
    plt.close(fig)
    return out


def plot_flight_track(
    fr_csv: Path | None,
    dl_csv: Path | None,
    kml_path: Path | None,
    flight_id: str,
    tmp_dir: Path,
) -> Path | None:
    """Lat/lon scatter coloured by altitude.

    When both sources are available they are placed in a 1x2 subplot so each
    track is individually readable. When only one source exists a single plot
    is produced. Returns PNG path or None if no GPS data is available.
    """
    fr_data = _extract_track_data(fr_csv, "flight_record") if fr_csv else None
    dl_data = _extract_track_data(dl_csv, "drone_log")     if dl_csv else None

    if fr_data is None and dl_data is None:
        return None

    both = fr_data is not None and dl_data is not None
    nrows = 2 if both else 1
    fig, axes = plt.subplots(nrows, 1, figsize=(11, 10 * nrows))
    if nrows == 1:
        axes = [axes]

    fig.suptitle(f"Flight Ground Track - {flight_id}", fontsize=11, fontweight="bold")

    # Shared colormap and altitude range so colours are directly comparable.
    _CMAP = "plasma"
    if both:
        all_alt = pd.concat([fr_data[2], dl_data[2]])
        vmin, vmax = float(all_alt.min()), float(all_alt.max())
    else:
        single_alt = (fr_data or dl_data)[2]
        vmin, vmax = float(single_alt.min()), float(single_alt.max())

    def _draw(ax, data, title, start_marker, end_marker):
        lon, lat, alt = data
        sc = ax.scatter(lon, lat, c=alt, cmap=_CMAP, vmin=vmin, vmax=vmax,
                        s=5, linewidths=0, alpha=0.9)
        plt.colorbar(sc, ax=ax, label="Height (m)", fraction=0.04, pad=0.04)
        ax.plot(lon.iloc[0],  lat.iloc[0],  start_marker, markersize=9, label="Start", zorder=6)
        ax.plot(lon.iloc[-1], lat.iloc[-1], end_marker,   markersize=9, label="End",   zorder=6)
        ax.set_title(title, fontsize=10, fontweight="bold")
        ax.set_xlabel("Longitude (WGS84)", fontsize=8)
        ax.set_ylabel("Latitude (WGS84)",  fontsize=8)
        ax.legend(fontsize=8)
        ax.tick_params(labelsize=7)

    idx = 0
    if fr_data is not None:
        _draw(axes[idx], fr_data, "Flight Record", "g^", "rs")
        idx += 1
    if dl_data is not None:
        _draw(axes[idx], dl_data, "Drone Log", "b^", "ms")

    note = "Coordinates are WGS84. No base map. Colour represents relative height (m)."
    if kml_path and kml_path.exists():
        note += f"   |   KML: {kml_path.name}"
    fig.text(0.5, 0.005, note, ha="center", fontsize=8, color="dimgrey")

    fig.tight_layout(rect=[0, 0.03, 1, 0.96])
    out = tmp_dir / f"{flight_id}_track.png"
    fig.savefig(out, dpi=150, bbox_inches="tight")
    plt.close(fig)
    return out


# Internal helpers

def _load_csv(path: Path) -> "pd.DataFrame | None":
    try:
        df = pd.read_csv(path, low_memory=False)
        return df if not df.empty else None
    except Exception:
        return None


def _seconds_from_start(df: pd.DataFrame, ts_col: str) -> "pd.Series | None":
    if ts_col not in df.columns:
        return None
    ts = pd.to_datetime(df[ts_col], utc=True, errors="coerce")
    valid = ts.dropna()
    if valid.empty:
        return None
    t0 = valid.iloc[0]
    return (ts - t0).dt.total_seconds()


def _plot_series(ax, t: pd.Series, df: pd.DataFrame, col: str,
                 label: str, colour: str, linestyle: str = "-") -> None:
    if col not in df.columns:
        return
    y = pd.to_numeric(df[col], errors="coerce")
    ax.plot(t, y, colour, linewidth=0.8, label=label, linestyle=linestyle)


def _annotate_if_zero(ax, df: pd.DataFrame, col: str) -> None:
    """Add an italic note if the column is absent, empty, or all-zero."""
    if col not in df.columns:
        ax.text(0.5, 0.5, "Data column not present in this log",
                transform=ax.transAxes, ha="center", va="center",
                fontsize=8, color="grey", style="italic")
        return
    vals = pd.to_numeric(df[col], errors="coerce").dropna()
    if vals.empty or (vals == 0).all():
        ax.text(0.5, 0.5, "Value recorded as 0 throughout\n(data not available)",
                transform=ax.transAxes, ha="center", va="center",
                fontsize=8, color="grey", style="italic")


def _extract_track_data(
    csv_path: Path, source_type: str
) -> "tuple[pd.Series, pd.Series, pd.Series] | None":
    """Load CSV and return (lon, lat, alt) Series with zero/NaN rows removed."""
    df = _load_csv(csv_path)
    if df is None:
        return None

    if source_type == "drone_log":
        lat_col = "IMUCalcs(0):Lat:C"
        lon_col = "IMUCalcs(0):Long:C"
        alt_col = "IMUCalcs(0):height:C"
    else:
        lat_col = "OSD.latitude"
        lon_col = "OSD.longitude"
        alt_col = "OSD.height [m]"

    if lat_col not in df.columns or lon_col not in df.columns:
        return None

    lat  = pd.to_numeric(df[lat_col], errors="coerce")
    lon  = pd.to_numeric(df[lon_col], errors="coerce")
    mask = lat.notna() & lon.notna() & (lat != 0.0) & (lon != 0.0)
    lat, lon = lat[mask], lon[mask]
    if lat.empty:
        return None

    alt = pd.to_numeric(df[alt_col], errors="coerce")[mask] if alt_col in df.columns else pd.Series([0.0] * len(lat))
    return lon, lat, alt


def _parse_event_times(events: list[dict], df: pd.DataFrame) -> dict[str, list[float]]:
    """Convert timeline event timestamps to seconds-from-start for marker overlay."""
    ts_col = "[NORM]:CUSTOM.updateTime"
    t = _seconds_from_start(df, ts_col)
    if t is None:
        return {}
    ts_series = pd.to_datetime(df[ts_col], utc=True, errors="coerce")
    t0 = ts_series.dropna().iloc[0] if ts_series.dropna().size > 0 else None
    if t0 is None:
        return {}

    result: dict[str, list[float]] = {
        "motor_on": [], "motor_off": [], "peak": [], "warning": [],
    }
    for ev in events:
        raw_ts = ev.get("timestamp")
        if not raw_ts:
            continue
        try:
            ev_dt    = pd.to_datetime(raw_ts, utc=True)
            offset_s = (ev_dt - t0).total_seconds()
        except Exception:
            continue
        name = ev.get("event", "")
        msg  = ev.get("data", {}).get("log_message", "")
        if name == "Motor turned on":
            result["motor_on"].append(offset_s)
        elif name == "Motor turned off":
            result["motor_off"].append(offset_s)
        elif name == "Reached peak height":
            result["peak"].append(offset_s)
        elif name == "Log message" and "Warning" in msg:
            result["warning"].append(offset_s)
    return result


def _add_event_markers(ax, event_times: dict[str, list[float]]) -> None:
    specs = [
        ("motor_on",  "green",      "Motor on"),
        ("motor_off", "red",        "Motor off"),
        ("peak",      "steelblue",  "Peak alt."),
        ("warning",   "darkorange", "Warning"),
    ]
    for key, colour, label in specs:
        for i, t in enumerate(event_times.get(key, [])):
            ax.axvline(t, color=colour, linestyle="--", linewidth=0.7, alpha=0.75,
                       label=label if i == 0 else "_nolegend_")
