from __future__ import annotations

import csv
import random
from collections import defaultdict
from collections.abc import Iterable, Mapping
from pathlib import Path

import yaml

from .models import AlertGroup, AlertLabel, AttackWindow, GroupLabel, NormalizedAlert


def load_attack_windows(path: Path) -> list[AttackWindow]:
    windows: list[AttackWindow] = []
    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        required = {"scenario", "attack", "start", "end"}
        if not required.issubset(reader.fieldnames or []):
            raise ValueError(f"{path} must contain columns: {sorted(required)}")
        for row in reader:
            windows.append(
                AttackWindow(
                    scenario=row["scenario"],
                    attack=row["attack"],
                    start=float(row["start"]),
                    end=float(row["end"]),
                )
            )
    return windows


def load_attacker_hosts(path: Path) -> dict[str, set[str]]:
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(raw, dict):
        raise ValueError("attacker host config must be a mapping")
    result: dict[str, set[str]] = {}
    for scenario, values in raw.items():
        if not isinstance(values, list):
            raise ValueError(f"attacker hosts for {scenario} must be a list")
        result[str(scenario)] = {
            str(item).strip() for item in values if str(item).strip()
        }
    return result


def _involves_attacker(
    alert: NormalizedAlert,
    attacker_hosts: set[str],
) -> bool:
    observed = {
        value
        for value in (
            alert.source_ip,
            alert.destination_ip,
            alert.host,
        )
        if value
    }
    return bool(observed & attacker_hosts)


def label_alert(
    alert: NormalizedAlert,
    windows: Iterable[AttackWindow],
    attacker_hosts_by_scenario: Mapping[str, set[str]],
) -> AlertLabel:
    attacker_hosts = attacker_hosts_by_scenario.get(alert.scenario, set())
    if not attacker_hosts:
        raise ValueError(
            f"no attacker hosts configured for scenario {alert.scenario!r}; "
            "refusing to emit all-benign labels"
        )

    if not _involves_attacker(alert, attacker_hosts):
        return AlertLabel(alert_id=alert.alert_id, malicious=False)

    epoch = alert.timestamp.timestamp()
    for window in windows:
        if (
            window.scenario == alert.scenario
            and window.start <= epoch <= window.end
        ):
            return AlertLabel(
                alert_id=alert.alert_id,
                malicious=True,
                attack_phase=window.attack,
            )
    return AlertLabel(alert_id=alert.alert_id, malicious=False)


def label_group(
    group: AlertGroup,
    windows: Iterable[AttackWindow],
    attacker_hosts_by_scenario: Mapping[str, set[str]],
) -> GroupLabel:
    window_list = list(windows)
    labels = [
        label_alert(member, window_list, attacker_hosts_by_scenario)
        for member in group.members
    ]
    malicious_values = {item.malicious for item in labels}
    phases = sorted(
        {item.attack_phase for item in labels if item.attack_phase}
    )
    return GroupLabel(
        group_id=group.group_id,
        scenario=group.scenario,
        malicious=any(item.malicious for item in labels),
        attack_phases=phases,
        mixed_member_labels=len(malicious_values) > 1,
    )


def label_groups(
    groups: Iterable[AlertGroup],
    windows: Iterable[AttackWindow],
    attacker_hosts_by_scenario: Mapping[str, set[str]],
) -> list[GroupLabel]:
    window_list = list(windows)
    return [
        label_group(group, window_list, attacker_hosts_by_scenario)
        for group in groups
    ]


def write_manual_check_sample(
    groups: list[AlertGroup],
    labels: list[GroupLabel],
    path: Path,
    *,
    n: int = 100,
    seed: int = 20260925,
) -> None:
    if len(groups) != len(labels):
        raise ValueError("groups and labels must have the same length")

    by_id = {label.group_id: label for label in labels}
    strata: dict[tuple[str, bool], list[AlertGroup]] = defaultdict(list)
    for group in groups:
        label = by_id[group.group_id]
        strata[(group.scenario, label.malicious)].append(group)

    rng = random.Random(seed)
    selected: list[AlertGroup] = []
    nonempty = [items for items in strata.values() if items]
    if not nonempty:
        raise ValueError("cannot sample from an empty group set")

    per_stratum = max(1, n // len(nonempty))
    for items in nonempty:
        chosen = (
            items
            if len(items) <= per_stratum
            else rng.sample(items, per_stratum)
        )
        selected.extend(chosen)

    selected_ids = {group.group_id for group in selected}
    remaining = [
        group for group in groups if group.group_id not in selected_ids
    ]
    if len(selected) < n and remaining:
        selected.extend(
            rng.sample(remaining, min(n - len(selected), len(remaining)))
        )
    selected = selected[: min(n, len(selected))]

    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        fieldnames = [
            "group_id",
            "scenario",
            "derived_label",
            "attack_phases",
            "timestamp",
            "rule_id",
            "rule_description",
            "source_ip",
            "destination_ip",
            "manual_label",
            "notes",
        ]
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for group in selected:
            label = by_id[group.group_id]
            rep = group.representative
            writer.writerow(
                {
                    "group_id": group.group_id,
                    "scenario": group.scenario,
                    "derived_label": (
                        "malicious" if label.malicious else "benign"
                    ),
                    "attack_phases": ";".join(label.attack_phases),
                    "timestamp": rep.timestamp.isoformat(),
                    "rule_id": rep.rule_id,
                    "rule_description": rep.rule_description,
                    "source_ip": rep.source_ip or "",
                    "destination_ip": rep.destination_ip or "",
                    "manual_label": "",
                    "notes": "",
                }
            )
