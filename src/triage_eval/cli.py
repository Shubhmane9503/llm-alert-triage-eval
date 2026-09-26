from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import yaml

from .baseline import tune_baseline
from .data import download_ait_ads
from .group import group_alerts
from .ingest import load_scenarios
from .io import read_jsonl, write_json, write_jsonl
from .labels import (
    label_groups,
    load_attack_windows,
    load_labeling_config,
    write_manual_check_sample,
)
from .models import AlertGroup, GroupLabel


def _config(path: Path) -> dict[str, Any]:
    value = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain a YAML mapping")
    return value


def cmd_data(args: argparse.Namespace) -> None:
    download_ait_ads(args.output)


def cmd_ingest(args: argparse.Namespace) -> None:
    cfg = _config(args.config)
    raw_dir = Path(args.data_dir)
    alerts = list(load_scenarios(raw_dir, cfg["scenarios"]))
    processed = Path(cfg["processed_dir"])
    write_jsonl(processed / "alerts.jsonl", alerts)

    groups = group_alerts(
        alerts,
        window_seconds=int(cfg.get("group_window_seconds", 300)),
    )
    write_jsonl(processed / "groups.jsonl", groups)
    print(json.dumps({"alerts": len(alerts), "groups": len(groups)}))


def cmd_label(args: argparse.Namespace) -> None:
    cfg = _config(args.config)
    processed = Path(cfg["processed_dir"])
    groups = list(
        read_jsonl(processed / "groups.jsonl", AlertGroup)
    )
    windows = load_attack_windows(Path(cfg["labels_csv"]))
    labeling_config = load_labeling_config(
        Path(cfg["attacker_hosts_file"])
    )
    labels = label_groups(groups, windows, labeling_config)
    write_jsonl(processed / "group_labels.jsonl", labels)

    write_manual_check_sample(
        groups,
        labels,
        Path("labels/manual_check.csv"),
        n=100,
        seed=int(cfg.get("random_seed", 20260925)),
    )
    print(
        json.dumps(
            {
                "groups": len(groups),
                "malicious": sum(label.status.value == "malicious" for label in labels),
                "benign": sum(label.status.value == "benign" for label in labels),
                "uncertain": sum(label.status.value == "uncertain" for label in labels),
            }
        )
    )


def cmd_baseline(args: argparse.Namespace) -> None:
    cfg = _config(args.config)
    processed = Path(cfg["processed_dir"])
    groups = list(
        read_jsonl(processed / "groups.jsonl", AlertGroup)
    )
    labels = list(
        read_jsonl(processed / "group_labels.jsonl", GroupLabel)
    )
    baseline_cfg = cfg.get("baseline", {})

    params = tune_baseline(
        groups,
        labels,
        scenarios=list(cfg["scenarios"]),
        threshold_min=int(
            baseline_cfg.get("threshold_min", 1)
        ),
        threshold_max=int(
            baseline_cfg.get("threshold_max", 15)
        ),
        fn_weight=float(baseline_cfg.get("fn_weight", 5.0)),
        min_noise_support=int(
            baseline_cfg.get("min_noise_support", 20)
        ),
        max_noise_malicious_rate=float(
            baseline_cfg.get("max_noise_malicious_rate", 0.0)
        ),
    )
    write_json(Path("results/baseline.json"), params)
    print(params.model_dump_json())


def _not_yet(_: argparse.Namespace) -> None:
    raise SystemExit(
        "This command is implemented in the next project milestone."
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="triage-eval")
    sub = parser.add_subparsers(
        dest="command",
        required=True,
    )

    data_parser = sub.add_parser(
        "data",
        help="download and verify AIT-ADS",
    )
    data_parser.add_argument(
        "--output",
        type=Path,
        default=Path("data"),
    )
    data_parser.set_defaults(func=cmd_data)

    ingest_parser = sub.add_parser(
        "ingest",
        help="normalize and group AIT-ADS alerts",
    )
    ingest_parser.add_argument(
        "--config",
        type=Path,
        default=Path("configs/dev.yaml"),
    )
    ingest_parser.add_argument(
        "--data-dir",
        default="data/raw",
    )
    ingest_parser.set_defaults(func=cmd_ingest)

    label_parser = sub.add_parser(
        "label",
        help="derive group labels and manual-check sample",
    )
    label_parser.add_argument(
        "--config",
        type=Path,
        default=Path("configs/dev.yaml"),
    )
    label_parser.set_defaults(func=cmd_label)

    baseline_parser = sub.add_parser(
        "baseline",
        help="tune rules baseline on dev scenarios",
    )
    baseline_parser.add_argument(
        "--config",
        type=Path,
        default=Path("configs/dev.yaml"),
    )
    baseline_parser.set_defaults(func=cmd_baseline)

    for name in ("run", "inject", "report"):
        command = sub.add_parser(name)
        command.add_argument(
            "--config",
            type=Path,
            default=Path("configs/heldout.yaml"),
        )
        if name == "run":
            command.add_argument(
                "--runs",
                type=int,
                default=3,
            )
        if name == "report":
            command.add_argument(
                "--results",
                type=Path,
                default=Path("results"),
            )
        command.set_defaults(func=_not_yet)

    return parser


def main() -> None:
    args = build_parser().parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
