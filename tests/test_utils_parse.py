"""Unit tests for parsing/utils_parse.py."""

from __future__ import annotations

import base64
import plistlib
import struct
import xml.etree.ElementTree as ET
from pathlib import Path, PurePosixPath

import pytest

from parsing.utils_parse import (
    decode_base64,
    decode_bytes_blobs,
    decode_cllocation_bplist,
    extract_fields,
    ieee754_long_to_degrees,
    match_labeled_value,
    normalise_acquisition_method,
    normalise_path,
    normalise_path_to_posix,
    normalise_scalar,
    parse_android_xml_map,
    parse_java_properties,
    parse_json_file,
    parse_plist_file,
    parse_plist_strict,
    safe_segment,
    sanitise_path,
    to_windows_path,
)


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


# --- decode_bytes_blobs (existing tests retained) ---

def test_decode_bytes_blobs_utf8_text() -> None:
    blob = {"__bytes_base64": _b64(b"hello world")}
    assert decode_bytes_blobs(blob) == "hello world"


def test_decode_bytes_blobs_plist_sub_tree() -> None:
    inner = plistlib.dumps({"key": "value"})
    blob = {"__bytes_base64": _b64(inner)}
    result = decode_bytes_blobs(blob)
    assert result == {"key": "value"}


def test_decode_bytes_blobs_plist_recursive() -> None:
    inner = plistlib.dumps({"nested": "yes"})
    outer = {"top": {"__bytes_base64": _b64(inner)}}
    result = decode_bytes_blobs(outer)
    assert result == {"top": {"nested": "yes"}}


def test_decode_bytes_blobs_opaque_left_unchanged() -> None:
    # b"\x80\x81" is not valid UTF-8 and not a valid plist — must be left as-is
    opaque = b"\x80\x81\x82\x83"
    blob = {"__bytes_base64": _b64(opaque)}
    result = decode_bytes_blobs(blob)
    assert result == blob


def test_decode_bytes_blobs_list_recursed() -> None:
    blob = {"__bytes_base64": _b64(b"item")}
    result = decode_bytes_blobs([blob, "plain"])
    assert result == ["item", "plain"]


def test_decode_bytes_blobs_non_blob_dict_passed_through() -> None:
    data = {"name": "Alice", "age": 30}
    assert decode_bytes_blobs(data) == data


def test_decode_bytes_blobs_with_json_safe_callback() -> None:
    from phases.utils_phase import json_safe

    inner_plist_bytes = plistlib.dumps({"flag": True})
    blob = {"__bytes_base64": _b64(inner_plist_bytes)}
    result = decode_bytes_blobs(blob, json_safe)
    assert result == {"flag": True}


# --- sanitise_path ---

def test_sanitise_path_converts_safely() -> None:
    assert sanitise_path("folder/file.txt") == Path("folder/file.txt")


def test_sanitise_path_strips_parent_traversal() -> None:
    result = sanitise_path("../secret/file.txt")
    assert ".." not in result.parts
    assert "secret" in result.parts


def test_sanitise_path_replaces_unsafe_chars() -> None:
    result = sanitise_path("folder/my file!.txt")
    assert " " not in str(result)
    assert "!" not in str(result)


def test_sanitise_path_empty_parts_become_unnamed() -> None:
    assert sanitise_path("") == Path("unnamed_file")
    assert sanitise_path("/") == Path("unnamed_file")


# --- to_windows_path ---

def test_to_windows_path_converts_slashes() -> None:
    assert to_windows_path("folder/sub/file.txt") == "folder\\sub\\file.txt"


def test_to_windows_path_no_slashes_unchanged() -> None:
    assert to_windows_path("file.txt") == "file.txt"


# --- safe_segment ---

def test_safe_segment_replaces_unsafe_chars() -> None:
    result = safe_segment("hello world!")
    assert " " not in result
    assert "!" not in result


def test_safe_segment_empty_returns_unnamed() -> None:
    assert safe_segment("") == "unnamed"
    assert safe_segment("   ") == "unnamed"


def test_safe_segment_safe_chars_preserved() -> None:
    assert safe_segment("file-name.txt") == "file-name.txt"


# --- normalise_path_to_posix ---

def test_normalise_path_to_posix_returns_pure_posix() -> None:
    result = normalise_path_to_posix("folder\\sub\\file.txt")
    assert isinstance(result, PurePosixPath)
    assert result == PurePosixPath("folder/sub/file.txt")


def test_normalise_path_to_posix_forward_slash_unchanged() -> None:
    result = normalise_path_to_posix("folder/sub/file.txt")
    assert result == PurePosixPath("folder/sub/file.txt")


# --- normalise_scalar ---

def test_normalise_scalar_strips_whitespace() -> None:
    assert normalise_scalar("  hello  ") == "hello"


def test_normalise_scalar_none_returns_none() -> None:
    assert normalise_scalar(None) is None


def test_normalise_scalar_empty_string_returns_none() -> None:
    assert normalise_scalar("") is None
    assert normalise_scalar("   ") is None


def test_normalise_scalar_numeric_coercion() -> None:
    assert normalise_scalar(42) == "42"
    assert normalise_scalar(3.14) == "3.14"


# --- normalise_path ---

def test_normalise_path_backslash_to_forward() -> None:
    assert normalise_path("folder\\sub\\file.txt") == "folder/sub/file.txt"


def test_normalise_path_strips_leading_dotslash() -> None:
    assert normalise_path("./folder/file.txt") == "folder/file.txt"


def test_normalise_path_to_lower() -> None:
    assert normalise_path("Folder/FILE.TXT", to_lower=True) == "folder/file.txt"


def test_normalise_path_to_lower_false_preserves_case() -> None:
    result = normalise_path("Folder/FILE.TXT", to_lower=False)
    assert result == "Folder/FILE.TXT"


# --- normalise_acquisition_method ---

def test_normalise_acquisition_method_strips_and_lowers() -> None:
    assert normalise_acquisition_method("  LOGICAL  ") == "logical"


def test_normalise_acquisition_method_none_returns_empty() -> None:
    assert normalise_acquisition_method(None) == ""


def test_normalise_acquisition_method_empty_returns_empty() -> None:
    assert normalise_acquisition_method("") == ""


# --- parse_plist_file ---

def test_parse_plist_file_missing_path_returns_empty(tmp_path: Path) -> None:
    result = parse_plist_file(tmp_path / "nonexistent.plist")
    assert result == {}


def test_parse_plist_file_malformed_returns_empty(tmp_path: Path) -> None:
    f = tmp_path / "bad.plist"
    f.write_bytes(b"not a plist")
    assert parse_plist_file(f) == {}


def test_parse_plist_file_valid_plist_returns_dict(tmp_path: Path) -> None:
    f = tmp_path / "good.plist"
    f.write_bytes(plistlib.dumps({"key": "value"}))
    assert parse_plist_file(f) == {"key": "value"}


# --- parse_plist_strict ---

def test_parse_plist_strict_malformed_raises(tmp_path: Path) -> None:
    f = tmp_path / "bad.plist"
    f.write_bytes(b"not a plist")
    with pytest.raises(Exception):
        parse_plist_strict(f)


def test_parse_plist_strict_valid_dict_returns_dict(tmp_path: Path) -> None:
    f = tmp_path / "good.plist"
    f.write_bytes(plistlib.dumps({"a": "b"}))
    assert parse_plist_strict(f) == {"a": "b"}


def test_parse_plist_strict_non_dict_root_wrapped(tmp_path: Path) -> None:
    f = tmp_path / "list.plist"
    f.write_bytes(plistlib.dumps(["x", "y"]))
    result = parse_plist_strict(f)
    assert result == {"value": ["x", "y"]}


# --- match_labeled_value ---

def test_match_labeled_value_key_equals_value() -> None:
    text = "SomeField = hello world"
    result = match_labeled_value(text, ("SomeField",))
    assert result == "hello world"


def test_match_labeled_value_key_colon_value() -> None:
    text = "SomeField: hello world"
    result = match_labeled_value(text, ("SomeField",))
    assert result == "hello world"


def test_match_labeled_value_plist_xml_string() -> None:
    text = "<key>SomeField</key><string>plist_value</string>"
    result = match_labeled_value(text, ("SomeField",))
    assert result == "plist_value"


def test_match_labeled_value_missing_returns_none() -> None:
    result = match_labeled_value("unrelated text", ("SomeField",))
    assert result is None


def test_match_labeled_value_uses_tuple_labels() -> None:
    text = "AltField = found"
    result = match_labeled_value(text, ("SomeField", "AltField"))
    assert result == "found"


# --- decode_base64 ---

def test_decode_base64_valid() -> None:
    encoded = base64.b64encode(b"hello").decode("ascii")
    assert decode_base64(encoded) == "hello"


def test_decode_base64_invalid_returns_none() -> None:
    assert decode_base64("!!!not_base64!!!") is None


def test_decode_base64_empty_result_returns_none() -> None:
    assert decode_base64(base64.b64encode(b"").decode("ascii")) is None


# --- ieee754_long_to_degrees ---

def test_ieee754_long_to_degrees_known_value() -> None:
    known_float = 51.5074
    packed = struct.pack(">d", known_float)
    long_val = struct.unpack(">q", packed)[0]
    result = ieee754_long_to_degrees(str(long_val))
    assert result == str(round(known_float, 8))


def test_ieee754_long_to_degrees_invalid_returns_none() -> None:
    assert ieee754_long_to_degrees("not_an_int") is None


# --- parse_android_xml_map ---

def _make_xml_map(items: dict) -> Path:
    return items


def test_parse_android_xml_map_valid(tmp_path: Path) -> None:
    xml = (
        '<?xml version="1.0" encoding="utf-8"?>\n'
        '<map>\n'
        '  <string name="username">testuser</string>\n'
        '  <boolean name="logged_in" value="true"/>\n'
        '</map>'
    )
    f = tmp_path / "prefs.xml"
    f.write_text(xml, encoding="utf-8")
    result = parse_android_xml_map(f)
    assert result["username"] == "testuser"
    assert result["logged_in"] == "true"


def test_parse_android_xml_map_empty_map(tmp_path: Path) -> None:
    xml = '<?xml version="1.0"?><map></map>'
    f = tmp_path / "empty.xml"
    f.write_text(xml, encoding="utf-8")
    assert parse_android_xml_map(f) == {}


def test_parse_android_xml_map_malformed_returns_empty(tmp_path: Path) -> None:
    f = tmp_path / "bad.xml"
    f.write_text("not xml at all", encoding="utf-8")
    assert parse_android_xml_map(f) == {}


# --- decode_cllocation_bplist ---

def _make_cllocation_plist(lat: float, lon: float) -> bytes:
    archive = {
        "$archiver": "NSKeyedArchiver",
        "$version": 100000,
        "$objects": [
            "$null",
            {
                "kCLLocationCodingKeyCoordinateLatitude": lat,
                "kCLLocationCodingKeyCoordinateLongitude": lon,
            },
        ],
    }
    return plistlib.dumps(archive)


def test_decode_cllocation_bplist_bytes_input() -> None:
    data = _make_cllocation_plist(51.5074, -0.1278)
    result = decode_cllocation_bplist(data)
    assert result is not None
    assert result["find_aircraft_last_latitude"] == str(round(51.5074, 8))
    assert result["find_aircraft_last_longitude"] == str(round(-0.1278, 8))


def test_decode_cllocation_bplist_base64_string_input() -> None:
    data = _make_cllocation_plist(48.8566, 2.3522)
    encoded = base64.b64encode(data).decode("ascii")
    result = decode_cllocation_bplist(encoded)
    assert result is not None
    assert "find_aircraft_last_latitude" in result


def test_decode_cllocation_bplist_invalid_returns_none() -> None:
    assert decode_cllocation_bplist(b"not a plist") is None
    assert decode_cllocation_bplist("not_base64!!!") is None


# --- parse_java_properties ---

def test_parse_java_properties_key_equals_value(tmp_path: Path) -> None:
    f = tmp_path / "app.properties"
    f.write_text("host=localhost\nport=8080\n", encoding="utf-8")
    result = parse_java_properties(f)
    assert result["host"] == "localhost"
    assert result["port"] == "8080"


def test_parse_java_properties_comment_lines_skipped(tmp_path: Path) -> None:
    f = tmp_path / "app.properties"
    f.write_text("# comment\n! also comment\nkey=value\n", encoding="utf-8")
    result = parse_java_properties(f)
    assert "key" in result
    assert len(result) == 1


def test_parse_java_properties_backslash_escape(tmp_path: Path) -> None:
    # _RE_BACKSLASH_ESCAPE strips \X to X: \: → :, \t → t, \U → U
    f = tmp_path / "app.properties"
    f.write_text(r"path=C\:\Users\test" + "\n", encoding="utf-8")
    result = parse_java_properties(f)
    assert result["path"] == "C:Userstest"


def test_parse_java_properties_missing_file_returns_empty(tmp_path: Path) -> None:
    assert parse_java_properties(tmp_path / "nonexistent.properties") == {}


# --- parse_json_file ---

def test_parse_json_file_valid(tmp_path: Path) -> None:
    f = tmp_path / "data.json"
    f.write_text('{"key": "value", "num": 42}', encoding="utf-8")
    assert parse_json_file(f) == {"key": "value", "num": 42}


def test_parse_json_file_malformed_returns_empty(tmp_path: Path) -> None:
    f = tmp_path / "bad.json"
    f.write_text("not json", encoding="utf-8")
    assert parse_json_file(f) == {}


def test_parse_json_file_non_dict_root_returns_empty(tmp_path: Path) -> None:
    f = tmp_path / "list.json"
    f.write_text("[1, 2, 3]", encoding="utf-8")
    assert parse_json_file(f) == {}


def test_parse_json_file_missing_returns_empty(tmp_path: Path) -> None:
    assert parse_json_file(Path("/nonexistent/data.json")) == {}


# --- extract_fields ---

def test_extract_fields_first_key_wins() -> None:
    raw = {"key_a": "value_a", "key_b": "value_b"}
    field_map = {"result": (["key_a", "key_b"], None)}
    out = extract_fields(raw, field_map)
    assert out["result"] == "value_a"


def test_extract_fields_fallback_to_second_key() -> None:
    raw = {"key_b": "value_b"}
    field_map = {"result": (["key_a", "key_b"], None)}
    out = extract_fields(raw, field_map)
    assert out["result"] == "value_b"


def test_extract_fields_decode_fn_applied() -> None:
    raw = {"encoded": base64.b64encode(b"decoded text").decode("ascii")}
    from parsing.utils_parse import decode_base64
    field_map = {"result": (["encoded"], decode_base64)}
    out = extract_fields(raw, field_map)
    assert out["result"] == "decoded text"


def test_extract_fields_empty_value_skipped() -> None:
    raw = {"key_a": "", "key_b": "found"}
    field_map = {"result": (["key_a", "key_b"], None)}
    out = extract_fields(raw, field_map)
    assert out["result"] == "found"


def test_extract_fields_no_match_key_absent() -> None:
    raw = {"unrelated": "value"}
    field_map = {"result": (["key_a"], None)}
    out = extract_fields(raw, field_map)
    assert "result" not in out
