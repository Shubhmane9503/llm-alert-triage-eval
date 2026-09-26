from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable

from .models import AlertGroup, BaselineParameters, Disposition, GroupLabel


def predict_baseline(
    group: AlertGroup,
    params: BaselineParameters,
) -> Disposition:
    if group.rule_id in set(params.noise_rule_ids):
        return Disposition.LIKELY_BENIGN
    if group.representative.rule_level >= params.rule_level_threshold:
        return Disposition.ESCALATE
    return Disposition.LIKELY_BENIGN


def _rates(
    y_true: list[bool],
    y_pred: list[bool],
) -> tuple[float, float]:
    tp = sum(t and p for t, p in zip(y_true, y_pred, strict=True))
    fn = sum(t and not p for t, p in zip(y_true, y_pred, strict=True))
    fp = sum(
        (not t) and p for t, p in zip(y_true, y_pred, strict=True)
    )
    tn = sum(
        (not t) and (not p) for t, p in zip(y_true, y_pred, strict=True)
    )
    fn_rate = fn / (fn + tp) if fn + tp else 0.0
    fp_rate = fp / (fp + tn) if fp + tn else 0.0
    return fn_rate, fp_rate


def tune_baseline(
    groups: Iterable[AlertGroup],
    labels: Iterable[GroupLabel],
    *,
    scenarios: list[str],
    threshold_min: int = 1,
    threshold_max: int = 15,
    fn_weight: float = 5.0,
    min_noise_support: int = 20,
    max_noise_malicious_rate: float = 0.0,
) -> BaselineParameters:
    group_list = list(groups)
    label_list = list(labels)
    by_label = {item.group_id: item for item in label_list}
    allowed = set(scenarios)

    if not group_list:
        raise ValueError("cannot tune baseline on zero groups")
    if any(group.scenario not in allowed for group in group_list):
        raise ValueError(
            "baseline tuning received a group outside the configured dev scenarios"
        )

    labeled_groups = [
        group
        for group in group_list
        if by_label[group.group_id].malicious is not None
    ]
    if not labeled_groups:
        raise ValueError("cannot tune baseline with only uncertain labels")

    per_rule: dict[str, list[bool]] = defaultdict(list)
    for group in labeled_groups:
        malicious = by_label[group.group_id].malicious
        assert malicious is not None
        per_rule[group.rule_id].append(malicious)

    noise = sorted(
        rule_id
        for rule_id, values in per_rule.items()
        if len(values) >= min_noise_support
        and (sum(values) / len(values)) <= max_noise_malicious_rate
    )

    y_true = [
        bool(by_label[group.group_id].malicious)
        for group in labeled_groups
    ]
    best: tuple[float, float, int] | None = None
    best_threshold = threshold_min

    for threshold in range(threshold_min, threshold_max + 1):
        noise_set = set(noise)
        y_pred = [
            group.rule_id not in noise_set
            and group.representative.rule_level >= threshold
            for group in labeled_groups
        ]
        fn_rate, fp_rate = _rates(y_true, y_pred)
        score = fn_weight * fn_rate + fp_rate
        candidate = (score, fn_rate, threshold)
        if best is None or candidate < best:
            best = candidate
            best_threshold = threshold

    return BaselineParameters(
        rule_level_threshold=best_threshold,
        noise_rule_ids=noise,
        tuned_on_scenarios=scenarios,
        fn_weight=fn_weight,
        min_noise_support=min_noise_support,
        max_noise_malicious_rate=max_noise_malicious_rate,
    )
