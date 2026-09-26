from __future__ import annotations

from datetime import timedelta

import pytest

from triage_eval.group import group_alerts
from triage_eval.labels import label_alert, label_group
from triage_eval.models import AttackWindow


def _window(alert) -> AttackWindow:
    epoch = alert.timestamp.timestamp()
    return AttackWindow(
        scenario=alert.scenario,
        attack="scan",
        start=epoch - 60,
        end=epoch + 60,
    )


def test_in_window_attacker_is_malicious(alert_factory) -> None:
    alert = alert_factory(source_ip="203.0.113.5")
    label = label_alert(
        alert,
        [_window(alert)],
        {"fox": {"203.0.113.5"}},
    )
    assert label.malicious is True
    assert label.attack_phase == "scan"


def test_in_window_other_host_is_benign(alert_factory) -> None:
    alert = alert_factory(source_ip="10.0.0.10")
    label = label_alert(
        alert,
        [_window(alert)],
        {"fox": {"203.0.113.5"}},
    )
    assert label.malicious is False


def test_outside_window_is_benign(alert_factory) -> None:
    alert = alert_factory(source_ip="203.0.113.5")
    epoch = alert.timestamp.timestamp()
    window = AttackWindow(
        scenario="fox",
        attack="scan",
        start=epoch + 3600,
        end=epoch + 7200,
    )
    label = label_alert(
        alert,
        [window],
        {"fox": {"203.0.113.5"}},
    )
    assert label.malicious is False


def test_group_is_malicious_if_any_member_is(alert_factory) -> None:
    first = alert_factory(
        alert_id="a1",
        source_ip="203.0.113.5",
    )
    second = alert_factory(
        alert_id="a2",
        source_ip="203.0.113.5",
        timestamp=first.timestamp + timedelta(seconds=90),
    )
    groups = group_alerts([first, second])
    epoch = first.timestamp.timestamp()
    window = AttackWindow(
        scenario="fox",
        attack="scan",
        start=epoch - 1,
        end=epoch + 30,
    )
    label = label_group(
        groups[0],
        [window],
        {"fox": {"203.0.113.5"}},
    )
    assert label.malicious is True
    assert label.mixed_member_labels is True


def test_missing_attacker_mapping_fails_closed(alert_factory) -> None:
    alert = alert_factory()
    with pytest.raises(ValueError, match="no attacker hosts configured"):
        label_alert(alert, [_window(alert)], {})
