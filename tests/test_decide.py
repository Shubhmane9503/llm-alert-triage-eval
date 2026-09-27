from __future__ import annotations

from triage_eval.decide import decide_group
from triage_eval.group import group_alerts
from triage_eval.llm import ModelCall
from triage_eval.models import BaselineParameters, Disposition


def _params() -> BaselineParameters:
    return BaselineParameters(
        rule_level_threshold=7,
        noise_rule_ids=[],
        tuned_on_scenarios=["fox"],
        fn_weight=5,
        min_noise_support=1,
        max_noise_malicious_rate=0,
    )


def test_valid_model_output_is_used(alert_factory) -> None:
    group = group_alerts([alert_factory(rule_level=10)])[0]

    def call(_):
        return ModelCall(
            output={
                "summary": "Suspicious high-level rule.",
                "disposition": "escalate",
                "confidence": 0.9,
                "citations": [{"field": "rule_level", "quote": "10"}],
            },
            model="mock",
            input_tokens=10,
            output_tokens=5,
            latency_ms=1,
        )

    result, audit = decide_group(group, _params(), call, run_id="r1")
    assert result.disposition == Disposition.ESCALATE
    assert result.llm_unavailable is False
    assert result.fallback is False
    assert result.attempts == 1
    assert len(audit) == 1
    assert audit[0].validation_ok
    assert audit[0].fallback is False


def test_one_retry_then_success(alert_factory) -> None:
    group = group_alerts([alert_factory()])[0]
    calls = 0

    def call(_):
        nonlocal calls
        calls += 1
        output = (
            "not-json"
            if calls == 1
            else {
                "summary": "Need review.",
                "disposition": "needs_more_data",
                "confidence": 0.4,
                "citations": [],
            }
        )
        return ModelCall(output, "mock", 1, 1, 1)

    result, audit = decide_group(group, _params(), call, run_id="r1")
    assert calls == 2
    assert result.disposition == Disposition.NEEDS_MORE_DATA
    assert result.attempts == 2
    assert result.fallback is False
    assert [item.validation_ok for item in audit] == [False, True]
    assert audit[0].disposition == Disposition.ESCALATE
    assert audit[0].fallback is False
    assert audit[1].fallback is False


def test_retry_failure_falls_back_to_rules(alert_factory) -> None:
    group = group_alerts([alert_factory(rule_level=10)])[0]
    calls = 0

    def call(_):
        nonlocal calls
        calls += 1
        return ModelCall("not-json", "mock", 1, 1, 1)

    result, audit = decide_group(group, _params(), call, run_id="r1")
    assert calls == 2
    assert result.disposition == Disposition.ESCALATE
    assert result.llm_unavailable is True
    assert result.fallback is True
    assert result.fallback_reason
    assert result.attempts == 2
    assert len(audit) == 2
    assert all(not item.validation_ok for item in audit)
    assert all(item.disposition == Disposition.ESCALATE for item in audit)
    assert audit[0].fallback is False
    assert audit[1].fallback is True
    assert audit[1].fallback_reason


def test_no_close_disposition_exists() -> None:
    values = {item.value for item in Disposition}
    assert "closed" not in values
    assert "close" not in values
    assert "suppress" not in values
