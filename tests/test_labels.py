from __future__ import annotations

from datetime import timedelta

import pytest

from triage_eval.group import group_alerts
from triage_eval.labels import label_alert, label_group
from triage_eval.models import AttackWindow, LabelStatus


def _config() -> dict:
    return {
        "scenarios": {
            "fox": {
                "attacker_ips": {
                    "192.168.130.77",
                    "172.17.130.196",
                }
            }
        },
        "phase_rules": {
            "dirb": {"dirb"},
            "privilege_escalation": {
                "attacker_change_user",
                "escalated_sudo_command",
                "5304",
                "5402",
                "5501",
                "5502",
                "user successfully changed uid",
                "successful sudo to root executed",
                "pam: login session opened",
                "pam: login session closed",
            },
        },
    }


def _window(alert, phase: str = "dirb") -> AttackWindow:
    epoch = alert.timestamp.timestamp()
    return AttackWindow(
        scenario=alert.scenario,
        attack=phase,
        start=epoch - 60,
        end=epoch + 60,
    )


def test_vpn_sourced_dirb_alert_is_malicious(alert_factory) -> None:
    alert = alert_factory(
        source_ip="172.17.130.196",
        host="intranet",
        rule_description="Apache web access",
    )
    label = label_alert(
        alert,
        [_window(alert, "dirb")],
        _config(),
    )
    assert label.status == LabelStatus.MALICIOUS
    assert label.evidence == "attacker_or_vpn_ip"


def test_host_only_privesc_rule_is_malicious(alert_factory) -> None:
    alert = alert_factory(
        source_ip="10.0.0.22",
        destination_ip=None,
        host="intranet",
        rule_id="5402",
        rule_description="Successful sudo to ROOT executed.",
        full_log="sudo: local privilege escalation event",
    )
    label = label_alert(
        alert,
        [_window(alert, "privilege_escalation")],
        _config(),
    )
    assert label.status == LabelStatus.MALICIOUS
    assert label.evidence == (
        "victim_host_rule_family:privilege_escalation"
    )


def test_in_window_without_evidence_is_uncertain(alert_factory) -> None:
    alert = alert_factory(
        source_ip="10.0.0.10",
        host="intranet",
        rule_description="unrelated activity",
    )
    label = label_alert(
        alert,
        [_window(alert, "dirb")],
        _config(),
    )
    assert label.status == LabelStatus.UNCERTAIN
    assert label.malicious is None


def test_outside_window_is_benign(alert_factory) -> None:
    alert = alert_factory(source_ip="172.17.130.196")
    epoch = alert.timestamp.timestamp()
    window = AttackWindow(
        scenario="fox",
        attack="dirb",
        start=epoch + 3600,
        end=epoch + 7200,
    )
    label = label_alert(alert, [window], _config())
    assert label.status == LabelStatus.BENIGN


def test_group_malicious_beats_uncertain(alert_factory) -> None:
    first = alert_factory(
        alert_id="a1",
        source_ip="10.0.0.10",
        host="intranet",
        rule_description="dirb scanner request",
    )
    second = alert_factory(
        alert_id="a2",
        source_ip="10.0.0.10",
        host="intranet",
        rule_description="unrelated activity",
        timestamp=first.timestamp + timedelta(seconds=30),
    )
    group = group_alerts([first, second])[0]
    label = label_group(
        group,
        [_window(first, "dirb")],
        _config(),
    )
    assert label.status == LabelStatus.MALICIOUS
    assert label.mixed_member_labels is True


def test_missing_scenario_mapping_fails_closed(alert_factory) -> None:
    alert = alert_factory()
    config = _config()
    config["scenarios"] = {}
    with pytest.raises(ValueError, match="no labeling config"):
        label_alert(alert, [_window(alert)], config)
