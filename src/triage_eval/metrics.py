from __future__ import annotations

from collections.abc import Sequence

from .models import ClassificationMetrics, Disposition, MetricView


def _view(
    y_true: Sequence[bool],
    y_pred: Sequence[bool],
) -> MetricView:
    if len(y_true) != len(y_pred):
        raise ValueError("y_true and y_pred lengths differ")

    tp = sum(t and p for t, p in zip(y_true, y_pred, strict=True))
    fp = sum(
        (not t) and p for t, p in zip(y_true, y_pred, strict=True)
    )
    tn = sum(
        (not t) and (not p)
        for t, p in zip(y_true, y_pred, strict=True)
    )
    fn = sum(t and not p for t, p in zip(y_true, y_pred, strict=True))
    n = len(y_true)

    return MetricView(
        n=n,
        tp=tp,
        fp=fp,
        tn=tn,
        fn=fn,
        accuracy=(tp + tn) / n if n else 0.0,
        precision=tp / (tp + fp) if tp + fp else 0.0,
        recall=tp / (tp + fn) if tp + fn else 0.0,
        fp_rate=fp / (fp + tn) if fp + tn else 0.0,
        fn_rate=fn / (fn + tp) if fn + tp else 0.0,
    )


def compute_metrics(
    y_true: Sequence[bool],
    dispositions: Sequence[Disposition],
) -> ClassificationMetrics:
    if len(y_true) != len(dispositions):
        raise ValueError("y_true and dispositions lengths differ")

    kept_true: list[bool] = []
    kept_pred: list[bool] = []
    all_pred: list[bool] = []
    abstentions = 0

    for truth, disposition in zip(y_true, dispositions, strict=True):
        if disposition == Disposition.NEEDS_MORE_DATA:
            abstentions += 1
            all_pred.append(True)
            continue

        pred = disposition == Disposition.ESCALATE
        kept_true.append(truth)
        kept_pred.append(pred)
        all_pred.append(pred)

    return ClassificationMetrics(
        abstain_rate=abstentions / len(y_true) if y_true else 0.0,
        non_abstained=_view(kept_true, kept_pred),
        abstain_as_escalate=_view(list(y_true), all_pred),
    )
