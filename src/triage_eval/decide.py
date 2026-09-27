from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime

from .baseline import predict_baseline
from .llm import ModelCall
from .models import (
    AlertGroup,
    AuditRecord,
    BaselineParameters,
    DecisionResult,
)
from .validate import validate_triage_response

ModelCallable = Callable[[AlertGroup], ModelCall]


def decide_group(
    group: AlertGroup,
    params: BaselineParameters,
    call_model: ModelCallable,
    *,
    run_id: str,
) -> tuple[DecisionResult, list[AuditRecord]]:
    """Run guarded LLM triage with exactly one retry and deterministic fallback."""

    baseline = predict_baseline(group, params)
    audit: list[AuditRecord] = []
    last_error: str | None = None

    for attempt in (1, 2):
        started_at = datetime.now(UTC)
        call: ModelCall | None = None
        try:
            call = call_model(group)
            validated = validate_triage_response(call.output, group)
        except Exception as exc:
            last_error = f"{type(exc).__name__}: {exc}"
            terminal = attempt == 2
            audit.append(
                AuditRecord(
                    run_id=run_id,
                    group_id=group.group_id,
                    model=call.model if call is not None else "unavailable",
                    started_at=started_at,
                    latency_ms=call.latency_ms if call is not None else 0.0,
                    input_tokens=call.input_tokens if call is not None else 0,
                    output_tokens=call.output_tokens if call is not None else 0,
                    disposition=baseline,
                    confidence=None,
                    validation_ok=False,
                    validation_error=last_error,
                    llm_unavailable=True,
                    fallback=terminal,
                    fallback_reason=last_error if terminal else None,
                    attempt=attempt,
                )
            )
            continue

        audit.append(
            AuditRecord(
                run_id=run_id,
                group_id=group.group_id,
                model=call.model,
                started_at=started_at,
                latency_ms=call.latency_ms,
                input_tokens=call.input_tokens,
                output_tokens=call.output_tokens,
                disposition=validated.disposition,
                confidence=validated.confidence,
                validation_ok=True,
                llm_unavailable=False,
                fallback=False,
                fallback_reason=None,
                attempt=attempt,
            )
        )
        return (
            DecisionResult(
                group_id=group.group_id,
                disposition=validated.disposition,
                confidence=validated.confidence,
                summary=validated.summary,
                citations=validated.citations,
                llm_unavailable=False,
                validation_error=None,
                fallback=False,
                fallback_reason=None,
                attempts=attempt,
            ),
            audit,
        )

    return (
        DecisionResult(
            group_id=group.group_id,
            disposition=baseline,
            confidence=None,
            summary=None,
            citations=[],
            llm_unavailable=True,
            validation_error=last_error,
            fallback=True,
            fallback_reason=last_error,
            attempts=2,
        ),
        audit,
    )
