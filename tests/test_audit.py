from __future__ import annotations

from datetime import UTC, datetime

from triage_eval.audit import append_audit_records
from triage_eval.models import AuditRecord, Disposition


def test_audit_appends_jsonl(tmp_path) -> None:
    path = tmp_path / "audit.jsonl"
    record = AuditRecord(
        run_id="r1",
        group_id="g1",
        model="mock",
        started_at=datetime.now(UTC),
        latency_ms=1,
        input_tokens=2,
        output_tokens=3,
        disposition=Disposition.ESCALATE,
        validation_ok=True,
        llm_unavailable=False,
        attempt=1,
    )
    append_audit_records(path, [record, record])
    assert len(
        path.read_text(encoding="utf-8").splitlines()
    ) == 2
