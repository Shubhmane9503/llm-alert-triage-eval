from __future__ import annotations

import hashlib
from collections import defaultdict
from collections.abc import Iterable
from datetime import timedelta

from .models import AlertGroup, NormalizedAlert


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
        key=lambda alert: (alert.rule_level, -alert.timestamp.timestamp()),
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


def group_alerts(
    alerts: Iterable[NormalizedAlert],
    *,
    window_seconds: int = 300,
) -> list[AlertGroup]:
    if window_seconds <= 0:
        raise ValueError("window_seconds must be positive")

    buckets: dict[
        tuple[str, str, str | None, str | None],
        list[NormalizedAlert],
    ] = defaultdict(list)
    for alert in alerts:
        key = (
            alert.scenario,
            alert.rule_id,
            alert.source_ip,
            alert.destination_ip,
        )
        buckets[key].append(alert)

    groups: list[AlertGroup] = []
    window = timedelta(seconds=window_seconds)
    for bucket in buckets.values():
        ordered = sorted(bucket, key=lambda alert: alert.timestamp)
        current: list[NormalizedAlert] = []
        for alert in ordered:
            if not current or alert.timestamp - current[0].timestamp <= window:
                current.append(alert)
            else:
                groups.append(_make_group(current))
                current = [alert]
        if current:
            groups.append(_make_group(current))

    return sorted(groups, key=lambda group: (group.window_start, group.group_id))
