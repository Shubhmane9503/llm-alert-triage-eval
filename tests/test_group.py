from __future__ import annotations

from datetime import timedelta

from triage_eval.group import group_alerts


def test_same_key_inside_window_merges(alert_factory) -> None:
    first = alert_factory(alert_id="a1")
    second = alert_factory(
        alert_id="a2",
        timestamp=first.timestamp + timedelta(minutes=4),
    )
    groups = group_alerts([first, second], window_seconds=300)
    assert len(groups) == 1
    assert groups[0].member_count == 2


def test_outside_window_splits(alert_factory) -> None:
    first = alert_factory(alert_id="a1")
    second = alert_factory(
        alert_id="a2",
        timestamp=first.timestamp + timedelta(minutes=6),
    )
    groups = group_alerts([first, second], window_seconds=300)
    assert len(groups) == 2


def test_different_rule_splits(alert_factory) -> None:
    first = alert_factory(alert_id="a1", rule_id="1001")
    second = alert_factory(alert_id="a2", rule_id="1002")
    groups = group_alerts([first, second], window_seconds=300)
    assert len(groups) == 2
