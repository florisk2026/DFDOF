from __future__ import annotations

from datetime import datetime, timezone

import config
from observation import Observation, make_observation


def test_observation_round_trip() -> None:
    observation = make_observation(
        stored_path="C:\\evidence\\backup_info.json",
        evidence_sha256="a" * 64,
        evidence_category=config.DEVICE_AND_BACKUP_INFO,
        acquisition_method=config.ACQUISITION_PARSER_IOS,
        observations=[{"device_name": "Test iPhone", "backup_date": "2026-05-04"}],
    )

    round_tripped = Observation.from_dict(observation.to_dict())

    assert round_tripped.to_dict() == observation.to_dict()
    assert round_tripped.content.stored_path == "C:\\evidence\\backup_info.json"
    assert round_tripped.content.evidence_sha256 == "a" * 64
    assert round_tripped.content.evidence_category == config.DEVICE_AND_BACKUP_INFO
    assert round_tripped.content.acquisition_method == config.ACQUISITION_PARSER_IOS


def test_observation_stored_path_in_dict() -> None:
    observation = make_observation(
        stored_path="C:\\output\\norm_FLY029.csv",
        evidence_sha256="c" * 64,
        evidence_category=config.DRONE_LOGS,
        acquisition_method=config.ACQUISITION_DATCON,
        observations=[{}],
    )
    payload = observation.to_dict()
    assert payload["stored_path"] == "C:\\output\\norm_FLY029.csv"


def test_observation_stored_path_none_serialises_as_null() -> None:
    observation = make_observation(
        stored_path=None,
        evidence_sha256="d" * 64,
        evidence_category=config.ACCOUNT_DATA,
        acquisition_method=config.ACQUISITION_PARSER_ANDROID,
        observations=[{}],
    )
    assert observation.content.stored_path is None
    assert observation.to_dict()["stored_path"] is None


def test_observation_json_safe_nested_values() -> None:
    observation = make_observation(
        stored_path="C:\\evidence\\account.json",
        evidence_sha256="b" * 64,
        evidence_category=config.ACCOUNT_DATA,
        acquisition_method=config.ACQUISITION_PARSER_ANDROID,
        observations=[
            {
                "seen_at": datetime(2026, 5, 16, 12, 30, tzinfo=timezone.utc),
                "tags": ("alpha", "beta"),
            }
        ],
    )

    payload = observation.to_dict()

    assert payload["observations"][0]["seen_at"] == "2026-05-16T12:30:00+00:00"
    assert payload["observations"][0]["tags"] == ["alpha", "beta"]
