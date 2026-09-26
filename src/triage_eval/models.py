from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


class AlertSource(StrEnum):
    WAZUH = "wazuh"
    SURICATA = "suricata"


class Disposition(StrEnum):
    ESCALATE = "escalate"
    LIKELY_BENIGN = "likely_benign"
    NEEDS_MORE_DATA = "needs_more_data"


class LabelStatus(StrEnum):
    MALICIOUS = "malicious"
    BENIGN = "benign"
    UNCERTAIN = "uncertain"


class NormalizedAlert(BaseModel):
    model_config = ConfigDict(extra="forbid")

    alert_id: str
    scenario: str
    source: AlertSource
    timestamp: datetime
    rule_id: str
    rule_level: int = Field(ge=0)
    rule_description: str
    source_ip: str | None = None
    destination_ip: str | None = None
    source_port: int | None = Field(default=None, ge=0, le=65535)
    destination_port: int | None = Field(default=None, ge=0, le=65535)
    host: str | None = None
    location: str | None = None
    full_log: str | None = None
    url: str | None = None
    user_agent: str | None = None
    raw: dict[str, Any]

    @field_validator("timestamp")
    @classmethod
    def require_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("timestamp must be timezone-aware")
        return value


class AlertGroup(BaseModel):
    model_config = ConfigDict(extra="forbid")

    group_id: str
    scenario: str
    rule_id: str
    source_ip: str | None
    destination_ip: str | None
    window_start: datetime
    window_end: datetime
    member_count: int = Field(ge=1)
    members: list[NormalizedAlert] = Field(min_length=1)
    representative: NormalizedAlert


class AttackWindow(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scenario: str
    attack: str
    start: float
    end: float


class AlertLabel(BaseModel):
    model_config = ConfigDict(extra="forbid")

    alert_id: str
    status: LabelStatus
    attack_phase: str | None = None
    evidence: str | None = None

    @property
    def malicious(self) -> bool | None:
        if self.status == LabelStatus.UNCERTAIN:
            return None
        return self.status == LabelStatus.MALICIOUS


class GroupLabel(BaseModel):
    model_config = ConfigDict(extra="forbid")

    group_id: str
    scenario: str
    status: LabelStatus
    attack_phases: list[str] = Field(default_factory=list)
    mixed_member_labels: bool = False
    evidence: list[str] = Field(default_factory=list)

    @property
    def malicious(self) -> bool | None:
        if self.status == LabelStatus.UNCERTAIN:
            return None
        return self.status == LabelStatus.MALICIOUS


class Citation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    field: str
    quote: str = Field(min_length=1)


class TriageResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    summary: str = Field(min_length=1, max_length=1000)
    disposition: Disposition
    confidence: float = Field(ge=0.0, le=1.0)
    citations: list[Citation]


class DecisionResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    group_id: str
    disposition: Disposition
    confidence: float | None = None
    summary: str | None = None
    citations: list[Citation] = Field(default_factory=list)
    llm_unavailable: bool = False
    validation_error: str | None = None
    fallback: bool = False
    fallback_reason: str | None = None
    attempts: int = Field(ge=0, le=2)


class BaselineParameters(BaseModel):
    model_config = ConfigDict(extra="forbid")

    rule_level_threshold: int = Field(ge=0)
    noise_rule_ids: list[str] = Field(default_factory=list)
    tuned_on_scenarios: list[str] = Field(min_length=1)
    fn_weight: float = Field(gt=0)
    min_noise_support: int = Field(ge=1)
    max_noise_malicious_rate: float = Field(ge=0, le=1)


class MetricView(BaseModel):
    model_config = ConfigDict(extra="forbid")

    n: int = Field(ge=0)
    tp: int = Field(ge=0)
    fp: int = Field(ge=0)
    tn: int = Field(ge=0)
    fn: int = Field(ge=0)
    accuracy: float
    precision: float
    recall: float
    fp_rate: float
    fn_rate: float


class ClassificationMetrics(BaseModel):
    model_config = ConfigDict(extra="forbid")

    abstain_rate: float
    non_abstained: MetricView
    abstain_as_escalate: MetricView


class AuditRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    run_id: str
    group_id: str
    model: str
    started_at: datetime
    latency_ms: float = Field(ge=0)
    input_tokens: int = Field(ge=0)
    output_tokens: int = Field(ge=0)
    disposition: Disposition
    confidence: float | None = None
    validation_ok: bool
    validation_error: str | None = None
    llm_unavailable: bool
    fallback: bool = False
    fallback_reason: str | None = None
    attempt: Literal[1, 2]
