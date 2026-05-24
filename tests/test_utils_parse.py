from __future__ import annotations

import base64
import plistlib

from parsing.utils_parse import decode_bytes_blobs


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


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
