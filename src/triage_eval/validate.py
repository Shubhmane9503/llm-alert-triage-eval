from __future__ import annotations

from typing import Any

from pydantic import ValidationError

from .guard import evidence_fields
from .models import (
    AlertGroup,
    Disposition,
    TriageResponse,
)


class TriageValidationError(ValueError):
    """Model output failed deterministic validation."""


def _parse(payload: Any) -> TriageResponse:
    try:
        if isinstance(payload, str):
            return TriageResponse.model_validate_json(
                payload
            )
        return TriageResponse.model_validate(payload)
    except ValidationError as exc:
        raise TriageValidationError(
            str(exc)
        ) from exc


def validate_triage_response(
    payload: Any,
    group: AlertGroup,
) -> TriageResponse:
    response = _parse(payload)
    fields = evidence_fields(group)

    for citation in response.citations:
        value = fields.get(citation.field)
        if value is None:
            raise TriageValidationError(
                "citation field does not exist: "
                f"{citation.field}"
            )
        if citation.quote not in value:
            raise TriageValidationError(
                "citation quote is not an exact "
                f"substring of {citation.field}"
            )

    if (
        response.disposition
        == Disposition.LIKELY_BENIGN
        and not response.citations
    ):
        raise TriageValidationError(
            "likely_benign requires at least "
            "one valid citation"
        )

    return response
