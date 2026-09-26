from __future__ import annotations

import hashlib
import heapq
from collections.abc import Iterable, Iterator
from datetime import datetime, timedelta

from .models import AlertGroup, NormalizedAlert

GroupKey = tuple[str, str, str | None, str | None]


def _make_group(members: list[NormalizedAlert]) -> AlertGroup:
    first = members[0]
    last = members[-1]
    identity = "|".join(
        [
            first.scenario,
            first.rule_id,
            first.source_ip or "",
            first.destination_ip or "",
            first.timestamp.isoformat(),
        ]
    )
    group_id = hashlib.sha256(identity.encode()).hexdigest()[:20]
    representative = max(
        members,
        key=lambda alert: (
            alert.rule_level,
            -alert.timestamp.timestamp(),
        ),
    )
    return AlertGroup(
        group_id=group_id,
        scenario=first.scenario,
        rule_id=first.rule_id,
        source_ip=first.source_ip,
        destination_ip=first.destination_ip,
        window_start=first.timestamp,
        window_end=last.timestamp,
        member_count=len(members),
        members=members,
        representative=representative,
    )


def _key(alert: NormalizedAlert) -> GroupKey:
    return (
        alert.scenario,
        alert.rule_id,
        alert.source_ip,
        alert.destination_ip,
    )


def iter_group_alerts(
    alerts: Iterable[NormalizedAlert],
    *,
    window_seconds: int = 300,
) -> Iterator[AlertGroup]:
    """Group timestamp-ordered alerts with bounded active state."""

    if window_seconds <= 0:
        raise ValueError("window_seconds must be positive")

    window = timedelta(seconds=window_seconds)
    active: dict[GroupKey, list[NormalizedAlert]] = {}
    expiries: list[tuple[datetime, int, GroupKey]] = []
    sequence = 0
    scenario: str | None = None
    last_timestamp: datetime | None = None

    def flush_all() -> Iterator[AlertGroup]:
        groups = [
            _make_group(members)
            for members in active.values()
        ]
        groups.sort(
            key=lambda item: (
                item.window_start,
                item.group_id,
            )
        )
        active.clear()
        expiries.clear()
        yield from groups

    for alert in alerts:
        if scenario is not None and alert.scenario != scenario:
            yield from flush_all()
            last_timestamp = None
        scenario = alert.scenario

        if (
            last_timestamp is not None
            and alert.timestamp < last_timestamp
        ):
            raise ValueError(
                "alerts must be timestamp-ordered within a scenario"
            )
        last_timestamp = alert.timestamp

        while expiries and expiries[0][0] < alert.timestamp:
            expiry, _, key = heapq.heappop(expiries)
            members = active.get(key)
            if members is None:
                continue
            expected_expiry = members[0].timestamp + window
            if expected_expiry != expiry:
                continue
            yield _make_group(members)
            del active[key]

        key = _key(alert)
        members = active.get(key)
        if members is None:
            active[key] = [alert]
            sequence += 1
            heapq.heappush(
                expiries,
                (
                    alert.timestamp + window,
                    sequence,
                    key,
                ),
            )
        else:
            members.append(alert)

    yield from flush_all()


def group_alerts(
    alerts: Iterable[NormalizedAlert],
    *,
    window_seconds: int = 300,
) -> list[AlertGroup]:
    return list(
        iter_group_alerts(
            alerts,
            window_seconds=window_seconds,
        )
    )
