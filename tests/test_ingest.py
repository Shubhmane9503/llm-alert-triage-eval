from __future__ import annotations

from datetime import UTC, datetime

import pytest

from triage_eval.ingest import IngestError, iter_json_records, normalize_alert
from triage_eval.models import AlertSource


def test_normalize_wazuh_prefers_iso_timestamp() -> None:
    raw = {
        "timestamp": "2022-01-18T10:00:00+00:00",
        "rule": {
            "id": "5710",
            "level": 10,
            "description": "sshd: Attempt to login using a non-existent user",
        },
        "data": {
            "srcip": "192.0.2.10",
            "srcport": "2222",
        },
        "agent": {"name": "mail"},
        "full_log": "sshd test",
    }
    alert = normalize_alert(raw, scenario="fox", line_number=1)
    assert alert.source == AlertSource.WAZUH
    assert alert.timestamp == datetime(2022, 1, 18, 10, 0, tzinfo=UTC)
    assert alert.rule_id == "5710"
    assert alert.rule_level == 10
    assert alert.source_ip == "192.0.2.10"
    assert alert.source_port == 2222


def test_normalize_suricata_wrapper() -> None:
    raw = {
        "timestamp": "2022-01-18T10:00:00Z",
        "rule": {
            "id": "86601",
            "level": 6,
            "description": "Suricata: Alert - test signature",
        },
        "data": {
            "src_ip": "198.51.100.10",
            "dest_ip": "10.0.0.2",
            "src_port": 44444,
            "dest_port": 80,
            "alert": {
                "signature_id": 2024364,
                "signature": "ET test",
            },
            "http": {
                "url": "/admin",
                "http_user_agent": "scanner",
            },
        },
    }
    alert = normalize_alert(raw, scenario="fox", line_number=2)
    assert alert.source == AlertSource.SURICATA
    assert alert.source_ip == "198.51.100.10"
    assert alert.destination_ip == "10.0.0.2"
    assert alert.url == "/admin"
    assert alert.user_agent == "scanner"


def test_missing_timestamp_is_rejected() -> None:
    with pytest.raises(IngestError, match="missing timestamp"):
        normalize_alert(
            {"rule": {"id": "1", "level": 3}},
            scenario="fox",
        )


def test_invalid_jsonl_is_rejected(tmp_path) -> None:
    path = tmp_path / "bad.json"
    path.write_text('{"ok": true}\nnot-json\n', encoding="utf-8")
    iterator = iter_json_records(path)
    assert next(iterator)[1] == {"ok": True}
    with pytest.raises(IngestError, match="invalid JSON"):
        next(iterator)
