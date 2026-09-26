from __future__ import annotations

import hashlib
import ipaddress
import json
from collections import deque
from collections.abc import Iterable, Iterator
from datetime import UTC, datetime, timedelta
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


def _parse_endpoint(
    value: Any,
    explicit_port: Any = None,
) -> tuple[str | None, int | None]:
    port = _port(explicit_port)
    if value in (None, ""):
        return None, port

    text = str(value).strip()
    if not text:
        return None, port

    host = text
    embedded_port: int | None = None

    if text.startswith("["):
        close = text.find("]")
        if close == -1:
            raise IngestError(f"invalid bracketed IP endpoint: {value!r}")
        host = text[1:close]
        suffix = text[close + 1 :]
        if suffix:
            if not suffix.startswith(":"):
                raise IngestError(f"invalid IP endpoint: {value!r}")
            embedded_port = _port(suffix[1:])
            if embedded_port is None:
                raise IngestError(f"invalid endpoint port: {value!r}")
    else:
        try:
            parsed = ipaddress.ip_address(text)
        except ValueError:
            if text.count(":") == 1:
                candidate_host, candidate_port = text.rsplit(":", 1)
                try:
                    parsed = ipaddress.ip_address(candidate_host)
                except ValueError as exc:
                    raise IngestError(f"invalid IP endpoint: {value!r}") from exc
                embedded_port = _port(candidate_port)
                if embedded_port is None:
                    raise IngestError(f"invalid endpoint port: {value!r}") from None
                host = candidate_host
            else:
                raise IngestError(f"invalid IP address: {value!r}") from None
        else:
            host = str(parsed)

    try:
        parsed_host = ipaddress.ip_address(host)
    except ValueError as exc:
        raise IngestError(f"invalid IP address: {value!r}") from exc

    return str(parsed_host), port if port is not None else embedded_port


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


def normalize_alert(
    raw: dict[str, Any],
    *,
    scenario: str,
    line_number: int = 0,
) -> NormalizedAlert:
    """Normalize one AIT-ADS Wazuh/Suricata JSON object."""

    timestamp_value = _first(
        raw,
        "timestamp",
        "event.created",
        "@timestamp",
        "data.timestamp",
    )
    timestamp = _parse_timestamp(timestamp_value)
    source = _detect_source(raw)
    wrapper_rule_id = _string(_first(raw, "rule.id"))

    if source == AlertSource.SURICATA:
        rule_id = _first(
            raw,
            "data.alert.signature_id",
            "alert.signature_id",
            "rule.id",
        )
        level_raw = _first(
            raw,
            "data.alert.severity",
            "alert.severity",
            "rule.level",
        )
        description = _first(
            raw,
            "data.alert.signature",
            "alert.signature",
            "rule.description",
        )
        signature = _string(
            _first(
                raw,
                "data.alert.signature",
                "alert.signature",
            )
        )
    else:
        rule_id = _first(raw, "rule.id")
        level_raw = _first(raw, "rule.level")
        description = _first(raw, "rule.description")
        signature = _string(
            _first(
                raw,
                "data.alert.signature",
                "alert.signature",
            )
        )

    if rule_id is None:
        raise IngestError("missing rule id")
    try:
        rule_level = int(level_raw if level_raw is not None else 0)
    except (TypeError, ValueError) as exc:
        raise IngestError(f"invalid rule level: {level_raw!r}") from exc

    description = str(description or f"rule {rule_id}")

    source_ip, source_port = _parse_endpoint(
        _first(
            raw,
            "data.src_ip",
            "data.srcip",
            "data.source.ip",
            "src_ip",
            "srcip",
            "source.ip",
        ),
        _first(
            raw,
            "data.src_port",
            "data.srcport",
            "src_port",
            "source.port",
        ),
    )
    destination_ip, destination_port = _parse_endpoint(
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
        ),
        _first(
            raw,
            "data.dest_port",
            "data.dst_port",
            "data.dstport",
            "dest_port",
            "destination.port",
        ),
    )

    host = _string(
        _first(
            raw,
            "agent.name",
            "predecoder.hostname",
            "host.name",
            "hostname",
        )
    )
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
            signature=signature,
            wrapper_rule_id=wrapper_rule_id,
            raw=None,
        )
    except ValidationError as exc:
        raise IngestError(str(exc)) from exc


def iter_json_records(path: Path) -> Iterator[tuple[int, dict[str, Any]]]:
    """Stream JSONL one record at a time."""

    with path.open("r", encoding="utf-8") as handle:
        for idx, line in enumerate(handle, start=1):
            text = line.strip()
            if not text:
                continue
            if text.startswith("["):
                raise IngestError(
                    f"{path}:{idx}: JSON arrays are not supported; "
                    "AIT-ADS files must be streamed as JSONL"
                )
            try:
                item = json.loads(text)
            except json.JSONDecodeError as exc:
                raise IngestError(
                    f"{path}:{idx}: invalid JSON: {exc.msg}"
                ) from exc
            if not isinstance(item, dict):
                raise IngestError(f"{path}:{idx}: record is not an object")
            yield idx, item


def _duplicate_ids_pair(
    left: NormalizedAlert,
    right: NormalizedAlert,
) -> bool:
    if "20101" not in {left.wrapper_rule_id, right.wrapper_rule_id}:
        return False
    if left.wrapper_rule_id == right.wrapper_rule_id:
        return False
    if not left.signature or not right.signature:
        return False
    if left.signature != right.signature:
        return False
    if left.source_ip != right.source_ip:
        return False
    if left.destination_ip != right.destination_ip:
        return False
    return abs((left.timestamp - right.timestamp).total_seconds()) <= 1.0


def _prefer_duplicate(
    left: NormalizedAlert,
    right: NormalizedAlert,
) -> NormalizedAlert:
    if left.wrapper_rule_id == "20101" and right.wrapper_rule_id != "20101":
        return right
    return left


def dedupe_ids_event_duplicates(
    alerts: Iterable[NormalizedAlert],
) -> Iterator[NormalizedAlert]:
    """Remove Wazuh rule-20101 copies of the same Suricata signature."""

    buffer: deque[NormalizedAlert] = deque()
    last_timestamp: datetime | None = None
    horizon = timedelta(seconds=1)

    def flush_one() -> NormalizedAlert | None:
        candidate = buffer.popleft()
        matches = [
            other
            for other in buffer
            if _duplicate_ids_pair(candidate, other)
        ]
        if not matches:
            return candidate

        preferred = candidate
        for other in matches:
            preferred = _prefer_duplicate(preferred, other)

        if preferred is candidate:
            for other in matches:
                try:
                    buffer.remove(other)
                except ValueError:
                    pass
            return candidate
        return None

    for alert in alerts:
        if (
            last_timestamp is not None
            and alert.timestamp < last_timestamp
        ):
            raise IngestError(
                "alerts are not timestamp-ordered; streaming dedupe requires "
                "nondecreasing timestamps within each scenario"
            )
        last_timestamp = alert.timestamp
        buffer.append(alert)

        while (
            buffer
            and alert.timestamp - buffer[0].timestamp > horizon
        ):
            item = flush_one()
            if item is not None:
                yield item

    while buffer:
        item = flush_one()
        if item is not None:
            yield item


def load_alert_file(
    path: Path,
    *,
    scenario: str,
) -> Iterator[NormalizedAlert]:
    def normalized() -> Iterator[NormalizedAlert]:
        for line_number, raw in iter_json_records(path):
            try:
                yield normalize_alert(
                    raw,
                    scenario=scenario,
                    line_number=line_number,
                )
            except IngestError as exc:
                raise IngestError(
                    f"{path}:{line_number}: {exc}"
                ) from exc

    yield from dedupe_ids_event_duplicates(normalized())


def load_scenarios(
    data_dir: Path,
    scenarios: Iterable[str],
) -> Iterator[NormalizedAlert]:
    for scenario in scenarios:
        path = data_dir / f"{scenario}_wazuh.json"
        if not path.exists():
            raise FileNotFoundError(path)
        yield from load_alert_file(path, scenario=scenario)
