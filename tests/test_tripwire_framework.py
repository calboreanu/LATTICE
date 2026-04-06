"""Tests for lattice.tripwire_framework."""
from __future__ import annotations

import pytest

from lattice.models import (
    TripwireDecision,
    TripwireMetric,
    TripwireOperator,
    TripwirePredicate,
    TripwireWindow,
    TripwireWindowKind,
)
from lattice.tripwire_framework import (
    SensitivityLevel,
    build_metric_threshold,
    calibrate_tripwire_predicate,
    evaluate_tripwire_predicate,
    evaluate_tripwire_predicates,
    get_metric_definition,
    list_standard_metrics,
    validate_tripwire_predicate_spec,
)


def _predicate(
    *,
    metric: TripwireMetric = TripwireMetric.RATE,
    operator: TripwireOperator = TripwireOperator.GT,
    threshold: float = 5.0,
    enabled: bool = True,
    predicate_id: str = "TW-FW-001",
) -> TripwirePredicate:
    return TripwirePredicate(
        predicate_id=predicate_id,
        metric=metric,
        operator=operator,
        threshold=threshold,
        on_trigger=TripwireDecision.ESCALATE,
        window=TripwireWindow(kind=TripwireWindowKind.EVENT_COUNT, size=10),
        enabled=enabled,
    )


def test_standard_metrics_include_all_expected_metrics() -> None:
    metrics = {m.metric for m in list_standard_metrics()}
    assert metrics == {
        TripwireMetric.ARI,
        TripwireMetric.PRDS,
        TripwireMetric.TMD,
        TripwireMetric.RATE,
        TripwireMetric.VOLUME,
        TripwireMetric.DURATION,
        TripwireMetric.ERROR_RATE,
        TripwireMetric.UNAUTHORIZED_TOOL_ATTEMPTS,
    }


def test_metric_definition_has_domain_for_ratio_metric() -> None:
    ari = get_metric_definition(TripwireMetric.ARI)
    assert ari.minimum == 0.0
    assert ari.maximum == 1.0
    assert ari.in_domain(0.2) is True
    assert ari.in_domain(1.2) is False


def test_validate_predicate_accepts_valid_spec() -> None:
    errors = validate_tripwire_predicate_spec(_predicate())
    assert errors == []


def test_validate_predicate_rejects_ratio_threshold_out_of_range() -> None:
    errors = validate_tripwire_predicate_spec(
        _predicate(metric=TripwireMetric.ERROR_RATE, threshold=1.5)
    )
    assert any("ERROR_RATE" in err for err in errors)


def test_validate_predicate_rejects_negative_count_threshold() -> None:
    errors = validate_tripwire_predicate_spec(
        _predicate(metric=TripwireMetric.RATE, threshold=-1.0)
    )
    assert any("must be >=" in err for err in errors)


def test_validate_predicate_skips_disabled_predicate() -> None:
    errors = validate_tripwire_predicate_spec(
        _predicate(metric=TripwireMetric.ERROR_RATE, threshold=9.0, enabled=False)
    )
    assert errors == []


@pytest.mark.parametrize(
    ("operator", "value", "threshold", "expected"),
    [
        (TripwireOperator.GT, 3.0, 2.0, True),
        (TripwireOperator.GT, 2.0, 2.0, False),
        (TripwireOperator.GTE, 2.0, 2.0, True),
        (TripwireOperator.LT, 1.0, 2.0, True),
        (TripwireOperator.LTE, 2.0, 2.0, True),
        (TripwireOperator.EQ, 2.0, 2.0, True),
        (TripwireOperator.NEQ, 3.0, 2.0, True),
    ],
)
def test_evaluate_tripwire_predicate_operator_matrix(
    operator: TripwireOperator,
    value: float,
    threshold: float,
    expected: bool,
) -> None:
    predicate = _predicate(operator=operator, threshold=threshold)
    assert evaluate_tripwire_predicate(predicate, value) is expected


def test_evaluate_tripwire_predicates_handles_disabled_and_missing_metrics() -> None:
    preds = [
        _predicate(predicate_id="TW-A", metric=TripwireMetric.RATE, threshold=2.0),
        _predicate(predicate_id="TW-B", metric=TripwireMetric.ERROR_RATE, enabled=False),
        _predicate(predicate_id="TW-C", metric=TripwireMetric.PRDS, threshold=0.2),
    ]
    outcomes = evaluate_tripwire_predicates(
        preds,
        metric_values={
            TripwireMetric.RATE: 3.0,
            TripwireMetric.ERROR_RATE: 0.9,
            # PRDS intentionally missing
        },
    )
    assert outcomes == {
        "TW-A": True,
        "TW-B": False,
        "TW-C": False,
    }


def test_build_metric_threshold_orders_by_sensitivity() -> None:
    baseline = [1.0, 1.5, 2.0, 2.5, 3.0]
    low = build_metric_threshold(TripwireMetric.RATE, baseline, sensitivity=SensitivityLevel.LOW)
    med = build_metric_threshold(TripwireMetric.RATE, baseline, sensitivity=SensitivityLevel.MEDIUM)
    high = build_metric_threshold(TripwireMetric.RATE, baseline, sensitivity=SensitivityLevel.HIGH)
    assert low.threshold > med.threshold > high.threshold


def test_build_metric_threshold_clamps_ratio_metric_to_one() -> None:
    baseline = [0.9, 0.95, 1.0]
    cal = build_metric_threshold(
        TripwireMetric.ERROR_RATE,
        baseline,
        sensitivity=SensitivityLevel.LOW,
    )
    assert 0.0 <= cal.threshold <= 1.0


def test_build_metric_threshold_rejects_empty_samples() -> None:
    with pytest.raises(ValueError, match="baseline_samples must be non-empty"):
        build_metric_threshold(TripwireMetric.RATE, [])


def test_build_metric_threshold_rejects_out_of_domain_samples() -> None:
    with pytest.raises(ValueError, match="must be in \\[0.0, 1.0\\]"):
        build_metric_threshold(TripwireMetric.ARI, [0.1, 1.2])


def test_calibrate_tripwire_predicate_updates_threshold_and_parameters() -> None:
    predicate = _predicate(metric=TripwireMetric.RATE, threshold=99.0)
    calibrated = calibrate_tripwire_predicate(
        predicate,
        baseline_samples=[2.0, 3.0, 4.0],
        sensitivity=SensitivityLevel.HIGH,
    )

    assert calibrated.threshold != predicate.threshold
    assert "calibration" in calibrated.parameters
    assert calibrated.parameters["calibration"]["sensitivity"] == "HIGH"
