from __future__ import annotations

import csv
from datetime import timedelta

import pytest

from triage_eval.group import group_alerts
from triage_eval.labels import write_manual_check_sample
from triage_eval.models import GroupLabel, LabelStatus


def _group(alert_factory, idx: int):
    alert = alert_factory(
        alert_id=f"a{idx}",
        rule_id=str(1000 + idx),
        timestamp=alert_factory().timestamp + timedelta(seconds=idx),
    )
    return group_alerts([alert])[0]


def test_manual_sheet_with_human_labels_is_not_overwritten(
    alert_factory,
    tmp_path,
) -> None:
    path = tmp_path / "manual_check.csv"
    path.write_text(
        "group_id,derived_label,manual_label\n"
        "g1,benign,malicious\n",
        encoding="utf-8",
    )
    group = _group(alert_factory, 1)
    label = GroupLabel(
        group_id=group.group_id,
        scenario=group.scenario,
        status=LabelStatus.UNCERTAIN,
        attack_phases=["dirb"],
    )
    with pytest.raises(FileExistsError, match="refusing to overwrite"):
        write_manual_check_sample(
            [group],
            [label],
            path,
            n=1,
            min_in_window_non_malicious=1,
        )


def test_force_allows_overwrite(
    alert_factory,
    tmp_path,
) -> None:
    path = tmp_path / "manual_check.csv"
    path.write_text(
        "group_id,derived_label,manual_label\n"
        "g1,benign,malicious\n",
        encoding="utf-8",
    )
    group = _group(alert_factory, 1)
    label = GroupLabel(
        group_id=group.group_id,
        scenario=group.scenario,
        status=LabelStatus.UNCERTAIN,
        attack_phases=["dirb"],
    )
    write_manual_check_sample(
        [group],
        [label],
        path,
        n=1,
        min_in_window_non_malicious=1,
        force=True,
    )
    assert "manual_label" in path.read_text(encoding="utf-8")


def test_sampler_reserves_30_in_window_uncertain(
    alert_factory,
    tmp_path,
) -> None:
    groups = []
    labels = []
    for idx in range(120):
        group = _group(alert_factory, idx)
        groups.append(group)
        in_window_uncertain = idx < 40
        labels.append(
            GroupLabel(
                group_id=group.group_id,
                scenario=group.scenario,
                status=(
                    LabelStatus.UNCERTAIN
                    if in_window_uncertain
                    else LabelStatus.BENIGN
                ),
                attack_phases=["dirb"] if in_window_uncertain else [],
            )
        )

    path = tmp_path / "manual_check.csv"
    write_manual_check_sample(
        groups,
        labels,
        path,
        n=100,
        seed=7,
    )
    with path.open("r", encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))

    assert len(rows) == 100
    overlap = [
        row
        for row in rows
        if row["derived_label"] == "uncertain"
        and row["attack_phases"]
    ]
    assert len(overlap) >= 30
