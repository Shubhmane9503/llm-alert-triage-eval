from __future__ import annotations

import pytest

from triage_eval.group import group_alerts
from triage_eval.models import Disposition
from triage_eval.validate import TriageValidationError, validate_triage_response


def _group(alert_factory):
    return group_alerts(
        [
            alert_factory(
                rule_description="Known scanner noise",
                full_log="scan request",
            )
        ]
    )[0]


def test_valid_output_is_accepted(alert_factory) -> None:
    response = validate_triage_response(
        {
            "summary": "Scanner-like activity.",
            "disposition": "likely_benign",
            "confidence": 0.8,
            "citations": [
                {"field": "rule_description", "quote": "scanner"}
            ],
        },
        _group(alert_factory),
    )
    assert response.disposition == Disposition.LIKELY_BENIGN


@pytest.mark.parametrize(
    "payload",
    [
        "not-json",
        {
            "summary": "x",
            "disposition": "closed",
            "confidence": 0.5,
            "citations": [],
        },
        {
            "summary": "x",
            "disposition": "escalate",
            "confidence": 2,
            "citations": [],
        },
        {
            "summary": "x",
            "disposition": "escalate",
            "confidence": 0.5,
            "citations": [],
            "extra": 1,
        },
    ],
)
def test_schema_failures_are_rejected(
    alert_factory,
    payload,
) -> None:
    with pytest.raises(TriageValidationError):
        validate_triage_response(payload, _group(alert_factory))


def test_nonexistent_citation_field_is_rejected(alert_factory) -> None:
    with pytest.raises(TriageValidationError, match="does not exist"):
        validate_triage_response(
            {
                "summary": "x",
                "disposition": "escalate",
                "confidence": 0.5,
                "citations": [
                    {"field": "made_up", "quote": "x"}
                ],
            },
            _group(alert_factory),
        )


def test_non_substring_quote_is_rejected(alert_factory) -> None:
    with pytest.raises(TriageValidationError, match="exact substring"):
        validate_triage_response(
            {
                "summary": "x",
                "disposition": "escalate",
                "confidence": 0.5,
                "citations": [
                    {
                        "field": "rule_description",
                        "quote": "malware",
                    }
                ],
            },
            _group(alert_factory),
        )


def test_likely_benign_requires_citation(alert_factory) -> None:
    with pytest.raises(TriageValidationError, match="requires"):
        validate_triage_response(
            {
                "summary": "x",
                "disposition": "likely_benign",
                "confidence": 0.5,
                "citations": [],
            },
            _group(alert_factory),
        )
