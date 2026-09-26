from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from triage_eval.ingest import (
    IngestError,
    dedupe_ids_event_duplicates,
    iter_json_records,
    normalize_alert,
)
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
    assert alert.raw is None


def test_embedded_ipv4_port_is_split() -> None:
    raw = {
        "timestamp": "2022-01-18T10:00:00Z",
        "rule": {
            "id": "100",
            "level": 3,
            "description": "test",
        },
        "data": {
            "srcip": "192.0.2.10:51515",
            "dstip": "91.189.95.85:80",
        },
    }
    alert = normalize_alert(raw, scenario="fox")
    assert alert.source_ip == "192.0.2.10"
    assert alert.source_port == 51515
    assert alert.destination_ip == "91.189.95.85"
    assert alert.destination_port == 80


def test_bracketed_ipv6_port_is_split() -> None:
    raw = {
        "timestamp": "2022-01-18T10:00:00Z",
        "rule": {
            "id": "100",
            "level": 3,
            "description": "test",
        },
        "data": {
            "srcip": "[2001:db8::1]:443",
            "dstip": "2001:db8::2",
        },
    }
    alert = normalize_alert(raw, scenario="fox")
    assert alert.source_ip == "2001:db8::1"
    assert alert.source_port == 443
    assert alert.destination_ip == "2001:db8::2"
    assert alert.destination_port is None


def test_normalize_suricata_uses_signature_fields() -> None:
    raw = {
        "timestamp": "2022-01-18T10:00:00Z",
        "rule": {
            "id": "86601",
            "level": 3,
            "description": "Suricata: Alert - wrapper",
        },
        "data": {
            "src_ip": "198.51.100.10",
            "dest_ip": "10.0.0.2",
            "src_port": 44444,
            "dest_port": 80,
            "alert": {
                "signature_id": 2024364,
                "signature": "ET test",
                "severity": 2,
            },
        },
    }
    alert = normalize_alert(raw, scenario="fox", line_number=2)
    assert alert.source == AlertSource.SURICATA
    assert alert.rule_id == "2024364"
    assert alert.rule_description == "ET test"
    assert alert.rule_level == 2
    assert alert.wrapper_rule_id == "86601"


def test_rule_20101_duplicate_is_removed() -> None:
    base = {
        "timestamp": "2022-01-18T10:00:00Z",
        "data": {
            "src_ip": "198.51.100.10",
            "dest_ip": "10.0.0.2",
            "alert": {
                "signature_id": 2024364,
                "signature": "ET duplicate",
                "severity": 2,
            },
        },
    }
    direct_raw = {
        **base,
        "rule": {
            "id": "86601",
            "level": 3,
            "description": "Suricata: Alert",
        },
    }
    wrapper_raw = {
        **base,
        "timestamp": "2022-01-18T10:00:00.500000Z",
        "rule": {
            "id": "20101",
            "level": 6,
            "description": "IDS event.",
        },
    }
    direct = normalize_alert(
        direct_raw,
        scenario="fox",
        line_number=1,
    )
    wrapper = normalize_alert(
        wrapper_raw,
        scenario="fox",
        line_number=2,
    )
    result = list(
        dedupe_ids_event_duplicates([direct, wrapper])
    )
    assert len(result) == 1
    assert result[0].wrapper_rule_id == "86601"
    assert result[0].rule_id == "2024364"


def test_same_signature_outside_one_second_is_kept() -> None:
    first = normalize_alert(
        {
            "timestamp": "2022-01-18T10:00:00Z",
            "rule": {"id": "86601", "level": 3},
            "data": {
                "src_ip": "198.51.100.10",
                "dest_ip": "10.0.0.2",
                "alert": {
                    "signature_id": 1,
                    "signature": "same",
                    "severity": 1,
                },
            },
        },
        scenario="fox",
        line_number=1,
    )
    second = first.model_copy(
        update={
            "alert_id": "other",
            "timestamp": first.timestamp + timedelta(seconds=2),
            "wrapper_rule_id": "20101",
        }
    )
    assert len(
        list(dedupe_ids_event_duplicates([first, second]))
    ) == 2


def test_missing_timestamp_is_rejected() -> None:
    with pytest.raises(IngestError, match="missing timestamp"):
        normalize_alert(
            {"rule": {"id": "1", "level": 3}},
            scenario="fox",
        )


def test_invalid_ip_is_rejected() -> None:
    with pytest.raises(IngestError, match="invalid IP"):
        normalize_alert(
            {
                "timestamp": "2022-01-18T10:00:00Z",
                "rule": {"id": "1", "level": 3},
                "data": {"srcip": "not-an-ip"},
            },
            scenario="fox",
        )


def test_invalid_jsonl_is_rejected(tmp_path) -> None:
    path = tmp_path / "bad.json"
    path.write_text('{"ok": true}\nnot-json\n', encoding="utf-8")
    iterator = iter_json_records(path)
    assert next(iterator)[1] == {"ok": True}
    with pytest.raises(IngestError, match="invalid JSON"):
        next(iterator)
