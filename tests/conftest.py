from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest

from triage_eval.models import AlertSource, NormalizedAlert


@pytest.fixture
def alert_factory():
    def factory(**overrides: Any) -> NormalizedAlert:
        values: dict[str, Any] = {
            "alert_id": "a1",
            "scenario": "fox",
            "source": AlertSource.WAZUH,
            "timestamp": datetime(2022, 1, 18, 10, 0, tzinfo=UTC),
            "rule_id": "1001",
            "rule_level": 8,
            "rule_description": "Synthetic test alert",
            "source_ip": "10.0.0.10",
            "destination_ip": "10.0.0.20",
            "source_port": 12345,
            "destination_port": 443,
            "host": "web-1",
            "location": "test",
            "full_log": "synthetic",
            "url": None,
            "user_agent": None,
            "raw": {"synthetic": True},
        }
        values.update(overrides)
        return NormalizedAlert(**values)

    return factory
