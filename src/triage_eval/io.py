from __future__ import annotations

import json
from collections.abc import Iterable, Iterator, Mapping
from pathlib import Path

from pydantic import BaseModel


def write_jsonl(
    path: Path,
    items: Iterable[BaseModel],
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for item in items:
            handle.write(item.model_dump_json() + "\n")


def read_jsonl[T: BaseModel](
    path: Path,
    model: type[T],
) -> Iterator[T]:
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                yield model.model_validate_json(line)
            except Exception as exc:
                raise ValueError(
                    f"{path}:{line_number}: invalid record"
                ) from exc


def write_json(
    path: Path,
    value: BaseModel | Mapping[str, object],
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = (
        value.model_dump(mode="json")
        if isinstance(value, BaseModel)
        else value
    )
    path.write_text(
        json.dumps(
            payload,
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
