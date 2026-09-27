from __future__ import annotations

import csv
import random
from collections import Counter, defaultdict
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

import yaml

from .models import (
    AlertGroup,
    AlertLabel,
    AttackWindow,
    GroupLabel,
    LabelStatus,
    NormalizedAlert,
)


def load_attack_windows(path: Path) -> list[AttackWindow]:
    windows: list[AttackWindow] = []
    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        required = {"scenario", "attack", "start", "end"}
        if not required.issubset(reader.fieldnames or []):
            raise ValueError(
                f"{path} must contain columns: {sorted(required)}"
            )
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


def load_labeling_config(path: Path) -> dict[str, Any]:
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(raw, dict):
        raise ValueError("labeling config must be a mapping")

    scenarios = raw.get("scenarios")
    phase_rules = raw.get("phase_rules")
    if not isinstance(scenarios, dict) or not isinstance(phase_rules, dict):
        raise ValueError(
            "labeling config requires scenarios and phase_rules mappings"
        )

    normalized_scenarios: dict[str, dict[str, set[str]]] = {}
    for scenario, value in scenarios.items():
        if not isinstance(value, dict):
            raise ValueError(f"scenario {scenario} config must be a mapping")
        attacker_ips = value.get("attacker_ips", [])
        if not isinstance(attacker_ips, list) or not attacker_ips:
            raise ValueError(
                f"scenario {scenario} must define attacker_ips"
            )
        normalized_scenarios[str(scenario)] = {
            "attacker_ips": {
                str(item).strip()
                for item in attacker_ips
                if str(item).strip()
            }
        }

    normalized_rules: dict[str, set[str]] = {}
    for phase, value in phase_rules.items():
        if not isinstance(value, dict):
            raise ValueError(f"phase rule {phase} must be a mapping")
        keywords = value.get("keywords", [])
        if not isinstance(keywords, list):
            raise ValueError(
                f"phase rule {phase}.keywords must be a list"
            )
        normalized_rules[str(phase)] = {
            str(item).strip().lower()
            for item in keywords
            if str(item).strip()
        }

    return {
        "scenarios": normalized_scenarios,
        "phase_rules": normalized_rules,
    }


def _attack_window(
    alert: NormalizedAlert,
    windows: Iterable[AttackWindow],
) -> AttackWindow | None:
    epoch = alert.timestamp.timestamp()
    for window in windows:
        if (
            window.scenario == alert.scenario
            and window.start <= epoch <= window.end
        ):
            return window
    return None


def _involves_attacker_ip(
    alert: NormalizedAlert,
    attacker_ips: set[str],
) -> bool:
    observed = {
        value
        for value in (alert.source_ip, alert.destination_ip)
        if value
    }
    return bool(observed & attacker_ips)


def _rule_family_text(alert: NormalizedAlert) -> str:
    values = [
        alert.rule_id,
        alert.rule_description,
        alert.location or "",
        alert.full_log or "",
    ]
    return "\n".join(values).lower()


def _matches_phase_rule(
    alert: NormalizedAlert,
    phase: str,
    phase_rules: Mapping[str, set[str]],
) -> bool:
    keywords = phase_rules.get(phase, set())
    if not keywords:
        return False
    text = _rule_family_text(alert)
    return any(keyword in text for keyword in keywords)


def label_alert(
    alert: NormalizedAlert,
    windows: Iterable[AttackWindow],
    labeling_config: Mapping[str, Any],
) -> AlertLabel:
    scenario_config = labeling_config["scenarios"].get(alert.scenario)
    if not scenario_config:
        raise ValueError(
            f"no labeling config for scenario {alert.scenario!r}"
        )
    attacker_ips = scenario_config["attacker_ips"]
    if not attacker_ips:
        raise ValueError(
            f"no attacker IPs configured for scenario {alert.scenario!r}"
        )

    window = _attack_window(alert, windows)
    if window is None:
        return AlertLabel(
            alert_id=alert.alert_id,
            status=LabelStatus.BENIGN,
            evidence="outside_attack_window",
        )

    if _involves_attacker_ip(alert, attacker_ips):
        return AlertLabel(
            alert_id=alert.alert_id,
            status=LabelStatus.MALICIOUS,
            attack_phase=window.attack,
            evidence="attacker_or_vpn_ip",
        )

    phase_rules = labeling_config["phase_rules"]
    if alert.host and _matches_phase_rule(
        alert,
        window.attack,
        phase_rules,
    ):
        return AlertLabel(
            alert_id=alert.alert_id,
            status=LabelStatus.MALICIOUS,
            attack_phase=window.attack,
            evidence=f"victim_host_rule_family:{window.attack}",
        )

    return AlertLabel(
        alert_id=alert.alert_id,
        status=LabelStatus.UNCERTAIN,
        attack_phase=window.attack,
        evidence="in_window_without_attacker_ip_or_phase_rule",
    )


def label_group(
    group: AlertGroup,
    windows: Iterable[AttackWindow],
    labeling_config: Mapping[str, Any],
) -> GroupLabel:
    window_list = list(windows)
    labels = [
        label_alert(member, window_list, labeling_config)
        for member in group.members
    ]
    statuses = {item.status for item in labels}
    phases = sorted(
        {item.attack_phase for item in labels if item.attack_phase}
    )
    evidence = sorted(
        {item.evidence for item in labels if item.evidence}
    )

    if LabelStatus.MALICIOUS in statuses:
        status = LabelStatus.MALICIOUS
    elif LabelStatus.UNCERTAIN in statuses:
        status = LabelStatus.UNCERTAIN
    else:
        status = LabelStatus.BENIGN

    return GroupLabel(
        group_id=group.group_id,
        scenario=group.scenario,
        status=status,
        attack_phases=phases,
        mixed_member_labels=len(statuses) > 1,
        evidence=evidence,
    )


def label_groups(
    groups: Iterable[AlertGroup],
    windows: Iterable[AttackWindow],
    labeling_config: Mapping[str, Any],
) -> list[GroupLabel]:
    window_list = list(windows)
    return [
        label_group(group, window_list, labeling_config)
        for group in groups
    ]


def summarize_labels(
    labels: Iterable[GroupLabel],
) -> dict[str, dict[str, dict[str, int]]]:
    summary: dict[str, dict[str, Counter[str]]] = defaultdict(
        lambda: defaultdict(Counter)
    )
    for label in labels:
        phases = label.attack_phases or ["outside_attack_window"]
        for phase in phases:
            summary[label.scenario][phase][label.status.value] += 1

    return {
        scenario: {
            phase: dict(counts)
            for phase, counts in sorted(phases.items())
        }
        for scenario, phases in sorted(summary.items())
    }


def _manual_sheet_has_labels(path: Path) -> bool:
    if not path.exists():
        return False
    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        if "manual_label" not in (reader.fieldnames or []):
            return False
        return any(
            str(row.get("manual_label", "")).strip()
            for row in reader
        )


def write_manual_check_sample(
    groups: list[AlertGroup],
    labels: list[GroupLabel],
    path: Path,
    *,
    n: int = 100,
    seed: int = 20260925,
    force: bool = False,
    min_in_window_non_malicious: int = 30,
) -> None:
    if len(groups) != len(labels):
        raise ValueError("groups and labels must have the same length")
    if n < min_in_window_non_malicious:
        raise ValueError(
            "sample size is smaller than the required in-window reserve"
        )
    if _manual_sheet_has_labels(path) and not force:
        raise FileExistsError(
            f"{path} contains manual labels; refusing to overwrite. "
            "Use --force only if discarding human review is intentional."
        )

    by_id = {label.group_id: label for label in labels}
    rng = random.Random(seed)

    in_window_non_malicious = [
        group
        for group in groups
        if by_id[group.group_id].status != LabelStatus.MALICIOUS
        and by_id[group.group_id].attack_phases
    ]
    if len(in_window_non_malicious) < min_in_window_non_malicious:
        raise ValueError(
            "not enough in-window non-malicious/uncertain groups for "
            f"manual review: need {min_in_window_non_malicious}, "
            f"found {len(in_window_non_malicious)}"
        )

    selected = rng.sample(
        in_window_non_malicious,
        min_in_window_non_malicious,
    )
    selected_ids = {group.group_id for group in selected}

    strata: dict[tuple[str, str], list[AlertGroup]] = defaultdict(list)
    for group in groups:
        if group.group_id in selected_ids:
            continue
        label = by_id[group.group_id]
        strata[(group.scenario, label.status.value)].append(group)

    slots = n - len(selected)
    nonempty = [items for items in strata.values() if items]
    if slots and not nonempty:
        raise ValueError("cannot fill manual-check sample")

    if nonempty:
        per_stratum = max(1, slots // len(nonempty))
        for items in nonempty:
            remaining_slots = n - len(selected)
            if remaining_slots <= 0:
                break
            count = min(
                per_stratum,
                len(items),
                remaining_slots,
            )
            selected.extend(rng.sample(items, count))

    selected_ids = {group.group_id for group in selected}
    remaining = [
        group
        for group in groups
        if group.group_id not in selected_ids
    ]
    if len(selected) < n and remaining:
        selected.extend(
            rng.sample(
                remaining,
                min(n - len(selected), len(remaining)),
            )
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
                    "derived_label": label.status.value,
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
