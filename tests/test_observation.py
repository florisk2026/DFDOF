from __future__ import annotations

from datetime import datetime, timezone

from observation import Observation, make_observation


def test_observation_round_trip() -> None:
    observation = make_observation(
        evidence_sha256="a" * 64,
        evidence_category="device_and_backup_info",
        acquisition_method="parser_ios",
        observations=[{"device_name": "Test iPhone", "backup_date": "2026-05-04"}],
    )

    round_tripped = Observation.from_dict(observation.to_dict())

    assert round_tripped.to_dict() == observation.to_dict()
    assert round_tripped.content.evidence_sha256 == "a" * 64
    assert round_tripped.content.evidence_category == "device_and_backup_info"
    assert round_tripped.content.acquisition_method == "parser_ios"


def test_observation_json_safe_nested_values() -> None:
    observation = make_observation(
        evidence_sha256="b" * 64,
        evidence_category="account_data",
        acquisition_method="parser_android",
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
