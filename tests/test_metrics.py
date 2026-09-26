from __future__ import annotations

from triage_eval.metrics import compute_metrics
from triage_eval.models import Disposition


def test_fixed_confusion_matrix() -> None:
    truth = [True, True, False, False]
    pred = [
        Disposition.ESCALATE,
        Disposition.LIKELY_BENIGN,
        Disposition.ESCALATE,
        Disposition.LIKELY_BENIGN,
    ]
    metrics = compute_metrics(truth, pred)
    view = metrics.non_abstained
    assert (view.tp, view.fp, view.tn, view.fn) == (1, 1, 1, 1)
    assert view.accuracy == 0.5
    assert view.precision == 0.5
    assert view.recall == 0.5
    assert view.fp_rate == 0.5
    assert view.fn_rate == 0.5


def test_abstention_has_two_views() -> None:
    truth = [True, False]
    pred = [
        Disposition.NEEDS_MORE_DATA,
        Disposition.LIKELY_BENIGN,
    ]
    metrics = compute_metrics(truth, pred)
    assert metrics.abstain_rate == 0.5
    assert metrics.non_abstained.n == 1
    assert metrics.abstain_as_escalate.n == 2
    assert metrics.abstain_as_escalate.tp == 1
    assert metrics.abstain_as_escalate.tn == 1
