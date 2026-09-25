from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path

from .models import AuditRecord


def append_audit_records(
    path: Path,
    records: Iterable[AuditRecord],
) -> None:
    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )
    with path.open(
        "a",
        encoding="utf-8",
    ) as handle:
        for record in records:
            handle.write(
                record.model_dump_json() + "\n"
            )
