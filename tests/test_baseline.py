from __future__ import annotations

import pytest

from triage_eval.baseline import predict_baseline, tune_baseline
from triage_eval.group import group_alerts
from triage_eval.models import (
    BaselineParameters,
    Disposition,
    GroupLabel,
)


def test_threshold_and_noise_allowlist(alert_factory) -> None:
    high = alert_factory(
        alert_id="a1",
        rule_id="high",
        rule_level=10,
    )
    noise = alert_factory(
        alert_id="a2",
        rule_id="noise",
        rule_level=12,
    )
    groups = group_alerts([high, noise])
    params = BaselineParameters(
        rule_level_threshold=7,
        noise_rule_ids=["noise"],
        tuned_on_scenarios=["fox"],
        fn_weight=5,
        min_noise_support=1,
        max_noise_malicious_rate=0,
    )
    by_rule = {group.rule_id: group for group in groups}
    assert (
        predict_baseline(by_rule["high"], params)
        == Disposition.ESCALATE
    )
    assert (
        predict_baseline(by_rule["noise"], params)
        == Disposition.LIKELY_BENIGN
    )


def test_tuning_rejects_heldout_scenario(alert_factory) -> None:
    alert = alert_factory(scenario="harrison")
    group = group_alerts([alert])[0]
    label = GroupLabel(
        group_id=group.group_id,
        scenario="harrison",
        malicious=True,
    )
    with pytest.raises(ValueError, match="outside"):
        tune_baseline(
            [group],
            [label],
            scenarios=["fox", "russellmitchell"],
            min_noise_support=1,
        )
