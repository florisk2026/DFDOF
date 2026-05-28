"""Unit tests for phases/utils_phase.py."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from phases.utils_phase import (
    compact_json,
    drone_sd_label,
    find_input_evidence_list_by_identification,
    haversine_m,
    json_safe,
    parse_datcon_date,
    parse_datcon_time,
    parse_exif_date,
    parse_flightrecord_timestamp,
    parse_iso_timestamp,
    write_json,
)


# --- json_safe ---

def test_json_safe_bytes_encoded_as_base64_blob() -> None:
    result = json_safe(b"\x01\x02\x03")
    assert result == {"__bytes_base64": "AQID"}


def test_json_safe_bytearray_encoded_as_base64_blob() -> None:
    result = json_safe(bytearray(b"abc"))
    assert isinstance(result, dict)
    assert "__bytes_base64" in result


def test_json_safe_naive_datetime_gets_z_suffix() -> None:
    dt = datetime(2018, 4, 19, 17, 24, 49)
    result = json_safe(dt)
    assert result == "2018-04-19T17:24:49Z"


def test_json_safe_aware_datetime_keeps_offset() -> None:
    dt = datetime(2018, 4, 19, 17, 24, 49, tzinfo=timezone.utc)
    result = json_safe(dt)
    assert result.endswith("+00:00")


def test_json_safe_recursive_dict_and_list() -> None:
    payload = {"key": [b"x", 1, None]}
    result = json_safe(payload)
    assert result["key"][0] == {"__bytes_base64": "eA=="}
    assert result["key"][1] == 1
    assert result["key"][2] is None


def test_json_safe_primitives_unchanged() -> None:
    assert json_safe(None) is None
    assert json_safe(42) == 42
    assert json_safe(3.14) == pytest.approx(3.14)
    assert json_safe("hello") == "hello"
    assert json_safe(True) is True


# --- compact_json ---

def test_compact_json_collapses_integer_array() -> None:
    result = compact_json({"ids": [1, 2, 3]})
    assert '"ids": [1, 2, 3]' in result


def test_compact_json_integer_array_has_no_internal_newlines() -> None:
    result = compact_json({"ids": [1, 2, 3]})
    ids_section = result.split('"ids":')[1].split("]")[0]
    assert "\n" not in ids_section


def test_compact_json_collapses_contains_no_value_array() -> None:
    result = compact_json({"contains_no_value": ["col_a", "col_b"]})
    assert '"contains_no_value": ["col_a", "col_b"]' in result


def test_compact_json_collapses_contains_constant_value_array() -> None:
    result = compact_json({"contains_constant_value": ["col_x"]})
    assert '"contains_constant_value": ["col_x"]' in result


def test_compact_json_nested_object_array_not_collapsed() -> None:
    result = compact_json({"items": [{"a": 1}, {"b": 2}]})
    assert '"items": [\n' in result


def test_compact_json_unrelated_string_array_not_collapsed() -> None:
    result = compact_json({"labels": ["a", "b"]})
    assert '"labels": [\n' in result


# --- write_json ---

def test_write_json_creates_file(tmp_path: Path) -> None:
    out = tmp_path / "out.json"
    write_json(out, {"ids": [1, 2, 3]})
    assert out.exists()
    parsed = json.loads(out.read_text(encoding="utf-8"))
    assert parsed["ids"] == [1, 2, 3]


def test_write_json_uses_compact_format(tmp_path: Path) -> None:
    out = tmp_path / "out.json"
    write_json(out, {"ids": [1, 2, 3]})
    assert '"ids": [1, 2, 3]' in out.read_text(encoding="utf-8")


# --- drone_sd_label ---

def test_drone_sd_label_one_indexed() -> None:
    assert drone_sd_label(1) == "drone_sd_1"
    assert drone_sd_label(2) == "drone_sd_2"
    assert drone_sd_label(99) == "drone_sd_99"


# --- parse_datcon_date ---

def test_parse_datcon_date_valid() -> None:
    assert parse_datcon_date("20180419") == "2018-04-19"


def test_parse_datcon_date_wrong_length_returns_none() -> None:
    assert parse_datcon_date("2018041") is None
    assert parse_datcon_date("201804190") is None


def test_parse_datcon_date_non_digit_returns_none() -> None:
    assert parse_datcon_date("abcdefgh") is None
    assert parse_datcon_date("2018/04/19") is None


def test_parse_datcon_date_empty_returns_none() -> None:
    assert parse_datcon_date("") is None


# --- parse_datcon_time ---

def test_parse_datcon_time_valid() -> None:
    assert parse_datcon_time("172449") == "17:24:49"


def test_parse_datcon_time_with_fraction() -> None:
    assert parse_datcon_time("172449.123") == "17:24:49.123"


def test_parse_datcon_time_wrong_length_returns_none() -> None:
    assert parse_datcon_time("1724") is None
    assert parse_datcon_time("1724490") is None


def test_parse_datcon_time_non_digit_returns_none() -> None:
    assert parse_datcon_time("abcdef") is None


def test_parse_datcon_time_empty_returns_none() -> None:
    assert parse_datcon_time("") is None


# --- parse_exif_date ---

def test_parse_exif_date_valid() -> None:
    assert parse_exif_date("2018:04:19 17:24:49") == ("2018-04-19", "17:24:49")


def test_parse_exif_date_positive_offset() -> None:
    assert parse_exif_date("2018:04:19 17:24:49+02:00") == ("2018-04-19", "15:24:49")


def test_parse_exif_date_negative_offset() -> None:
    assert parse_exif_date("2018:04:19 02:00:00-05:00") == ("2018-04-19", "07:00:00")


def test_parse_exif_date_utc_z() -> None:
    assert parse_exif_date("2018:04:19 17:24:49Z") == ("2018-04-19", "17:24:49")


def test_parse_exif_date_subseconds_with_offset() -> None:
    assert parse_exif_date("2018:04:19 17:24:49.123+02:00") == ("2018-04-19", "15:24:49")


def test_parse_exif_date_zero_date_returns_none() -> None:
    assert parse_exif_date("0000:00:00 00:00:00") is None


def test_parse_exif_date_malformed_returns_none() -> None:
    assert parse_exif_date("not-a-date") is None
    assert parse_exif_date("") is None


# --- parse_iso_timestamp ---

def test_parse_iso_timestamp_z_normalised_to_offset() -> None:
    assert parse_iso_timestamp("2018-04-19T17:24:49Z") == "2018-04-19T17:24:49+00:00"


def test_parse_iso_timestamp_explicit_tz_preserved() -> None:
    assert parse_iso_timestamp("2018-04-19T17:24:49+02:00") == "2018-04-19T17:24:49+02:00"


def test_parse_iso_timestamp_naive_gets_utc() -> None:
    assert parse_iso_timestamp("2018-04-19T17:24:49") == "2018-04-19T17:24:49+00:00"


def test_parse_iso_timestamp_empty_returns_none() -> None:
    assert parse_iso_timestamp("") is None


def test_parse_iso_timestamp_invalid_returns_none() -> None:
    assert parse_iso_timestamp("not-a-date") is None


# --- parse_flightrecord_timestamp ---

def test_parse_flightrecord_timestamp_with_subseconds() -> None:
    result = parse_flightrecord_timestamp("2018/04/19 17:25:11.078")
    assert result is not None
    assert "2018-04-19" in result
    assert "+00:00" in result


def test_parse_flightrecord_timestamp_without_subseconds() -> None:
    result = parse_flightrecord_timestamp("2018/04/19 17:25:11")
    assert result is not None
    assert "2018-04-19T17:25:11" in result
    assert "+00:00" in result


def test_parse_flightrecord_timestamp_invalid_returns_none() -> None:
    assert parse_flightrecord_timestamp("") is None
    assert parse_flightrecord_timestamp("2018-04-19 17:25:11") is None


# --- haversine_m ---

def test_haversine_m_same_point_is_zero() -> None:
    assert haversine_m(51.5, -0.1, 51.5, -0.1) == pytest.approx(0.0)


def test_haversine_m_one_degree_longitude_at_equator() -> None:
    # 1 degree longitude at equator ≈ 111 195 m
    assert haversine_m(0.0, 0.0, 0.0, 1.0) == pytest.approx(111_195.0, rel=1e-3)


def test_haversine_m_is_symmetric() -> None:
    d1 = haversine_m(51.5, -0.1, 48.8, 2.3)
    d2 = haversine_m(48.8, 2.3, 51.5, -0.1)
    assert d1 == pytest.approx(d2)


# --- find_input_evidence_list_by_identification ---

def test_find_input_evidence_list_filters_correctly(tmp_path: Path) -> None:
    import config
    from evidence import make_evidence
    from state import State

    f1 = tmp_path / "a.zip"
    f2 = tmp_path / "b.zip"
    f1.write_bytes(b"x")
    f2.write_bytes(b"y")

    ev_ios = make_evidence(
        source_path="a.zip",
        stored_path=f1,
        parent=None,
        acquisition_method=config.ACQUISITION_LOGICAL,
        type=config.EVIDENCE_TYPE_INPUT,
        source_identification=config.IDENTIFICATION_CONTROLLER_IOS,
    )
    ev_android = make_evidence(
        source_path="b.zip",
        stored_path=f2,
        parent=None,
        acquisition_method=config.ACQUISITION_LOGICAL,
        type=config.EVIDENCE_TYPE_INPUT,
        source_identification=config.IDENTIFICATION_CONTROLLER_ANDROID,
    )

    state = State(case_id="FIND-TEST", operator="Tester")
    state.input_evidence = [ev_ios, ev_android]

    result = find_input_evidence_list_by_identification(state, config.IDENTIFICATION_CONTROLLER_IOS)
    assert len(result) == 1
    assert result[0].source_identification == config.IDENTIFICATION_CONTROLLER_IOS


def test_find_input_evidence_list_returns_empty_when_no_match(tmp_path: Path) -> None:
    import config
    from evidence import make_evidence
    from state import State

    f1 = tmp_path / "a.zip"
    f1.write_bytes(b"x")

    ev_ios = make_evidence(
        source_path="a.zip",
        stored_path=f1,
        parent=None,
        acquisition_method=config.ACQUISITION_LOGICAL,
        type=config.EVIDENCE_TYPE_INPUT,
        source_identification=config.IDENTIFICATION_CONTROLLER_IOS,
    )

    state = State(case_id="FIND-TEST-2", operator="Tester")
    state.input_evidence = [ev_ios]

    result = find_input_evidence_list_by_identification(state, config.IDENTIFICATION_CONTROLLER_ANDROID)
    assert result == []
