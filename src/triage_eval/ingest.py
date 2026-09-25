from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from .models import AlertSource, NormalizedAlert


class IngestError(ValueError):
    """Raised when an alert cannot be normalized safely."""


def _deep_get(obj: dict[str, Any], dotted: str) -> Any:
    cur: Any = obj
    for part in dotted.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur


def _first(obj: dict[str, Any], *paths: str) -> Any:
    for path in paths:
        value = _deep_get(obj, path)
        if value not in (None, ""):
            return value
    return None


def _parse_timestamp(value: Any) -> datetime:
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(float(value), tz=UTC)
    if not isinstance(value, str) or not value.strip():
        raise IngestError("missing timestamp")
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        try:
            parsed = datetime.fromtimestamp(float(text), tz=UTC)
        except ValueError:
            raise IngestError(f"unsupported timestamp: {value!r}") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed


def _port(value: Any) -> int | None:
    if value in (None, ""):
        return None
    try:
        port = int(value)
    except (TypeError, ValueError):
        return None
    return port if 0 <= port <= 65535 else None


def _string(value: Any) -> str | None:
    if value in (None, ""):
        return None
    return str(value)


def _detect_source(raw: dict[str, Any]) -> AlertSource:
    description = str(_first(raw, "rule.description", "alert.signature") or "")
    decoder = str(_first(raw, "decoder.name", "event.module") or "").lower()
    integration = str(_first(raw, "integration", "data.integration") or "").lower()
    if (
        description.lower().startswith("suricata:")
        or "suricata" in decoder
        or "suricata" in integration
        or isinstance(_deep_get(raw, "data.alert"), dict)
    ):
        return AlertSource.SURICATA
    return AlertSource.WAZUH


def normalize_alert(raw: dict[str, Any], *, scenario: str, line_number: int = 0) -> NormalizedAlert:
    """Normalize one AIT-ADS Wazuh/Suricata JSON object.

    AIT-ADS documentation warns that Wazuh's numeric generation epoch does not
    align with the original scenario. Prefer the ISO timestamp field.
    """

    timestamp_value = _first(raw, "timestamp", "event.created", "@timestamp", "data.timestamp")
    timestamp = _parse_timestamp(timestamp_value)
    source = _detect_source(raw)

    rule_id = _first(raw, "rule.id", "data.alert.signature_id", "alert.signature_id")
    if rule_id is None:
        raise IngestError("missing rule id")
    level_raw = _first(raw, "rule.level", "data.alert.severity", "alert.severity")
    try:
        rule_level = int(level_raw if level_raw is not None else 0)
    except (TypeError, ValueError) as exc:
        raise IngestError(f"invalid rule level: {level_raw!r}") from exc

    description = _first(raw, "rule.description", "data.alert.signature", "alert.signature")
    description = str(description or f"rule {rule_id}")

    source_ip = _string(
        _first(raw, "data.src_ip", "data.srcip", "data.source.ip", "src_ip", "srcip", "source.ip")
    )
    destination_ip = _string(
        _first(
            raw,
            "data.dest_ip",
            "data.dst_ip",
            "data.dstip",
            "data.destination.ip",
            "dest_ip",
            "dst_ip",
            "dstip",
            "destination.ip",
        )
    )
    source_port = _port(_first(raw, "data.src_port", "data.srcport", "src_port", "source.port"))
    destination_port = _port(
        _first(raw, "data.dest_port", "data.dst_port", "data.dstport", "dest_port", "destination.port")
    )
    host = _string(_first(raw, "agent.name", "predecoder.hostname", "host.name", "hostname"))
    location = _string(_first(raw, "location", "data.location"))
    full_log = _string(_first(raw, "full_log", "data.full_log", "message"))
    url = _string(_first(raw, "data.http.url", "data.url", "url.full", "url"))
    user_agent = _string(
        _first(
            raw,
            "data.http.http_user_agent",
            "data.http.user_agent",
            "user_agent",
            "user_agent.original",
        )
    )

    identity = json.dumps(
        {
            "scenario": scenario,
            "line": line_number,
            "timestamp": timestamp.isoformat(),
            "rule_id": str(rule_id),
            "src": source_ip,
            "dst": destination_ip,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    alert_id = hashlib.sha256(identity.encode()).hexdigest()[:20]

    try:
        return NormalizedAlert(
            alert_id=alert_id,
            scenario=scenario,
            source=source,
            timestamp=timestamp,
            rule_id=str(rule_id),
            rule_level=rule_level,
            rule_description=description,
            source_ip=source_ip,
            destination_ip=destination_ip,
            source_port=source_port,
            destination_port=destination_port,
            host=host,
            location=location,
            full_log=full_log,
            url=url,
            user_agent=user_agent,
            raw=raw,
        )
    except ValidationError as exc:
        raise IngestError(str(exc)) from exc


def iter_json_records(path: Path) -> Iterator[tuple[int, dict[str, Any]]]:
    """Read either JSONL or a JSON array without silently dropping malformed rows."""

    with path.open("r", encoding="utf-8") as handle:
        first = ""
        while True:
            char = handle.read(1)
            if not char:
                return
            if not char.isspace():
                first = char
                break
        handle.seek(0)
        if first == "[":
            value = json.load(handle)
            if not isinstance(value, list):
                raise IngestError(f"expected JSON array in {path}")
            for idx, item in enumerate(value, start=1):
                if not isinstance(item, dict):
                    raise IngestError(f"{path}:{idx}: record is not an object")
                yield idx, item
            return

        for idx, line in enumerate(handle, start=1):
            text = line.strip()
            if not text:
                continue
            try:
                item = json.loads(text)
            except json.JSONDecodeError as exc:
                raise IngestError(f"{path}:{idx}: invalid JSON: {exc.msg}") from exc
            if not isinstance(item, dict):
                raise IngestError(f"{path}:{idx}: record is not an object")
            yield idx, item


def load_alert_file(path: Path, *, scenario: str) -> Iterator[NormalizedAlert]:
    for line_number, raw in iter_json_records(path):
        try:
            yield normalize_alert(raw, scenario=scenario, line_number=line_number)
        except IngestError as exc:
            raise IngestError(f"{path}:{line_number}: {exc}") from exc


def load_scenarios(data_dir: Path, scenarios: Iterable[str]) -> Iterator[NormalizedAlert]:
    for scenario in scenarios:
        path = data_dir / f"{scenario}_wazuh.json"
        if not path.exists():
            raise FileNotFoundError(path)
        yield from load_alert_file(path, scenario=scenario)
