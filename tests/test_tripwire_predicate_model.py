"""Tests for lattice.models.TripwirePredicate."""
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


def _valid_predicate_dict() -> dict:
    return {
        "predicate_id": "TW-300-RATE",
        "metric": "RATE",
        "operator": "GT",
        "threshold": 5.0,
        "on_trigger": "ESCALATE",
        "window": {"kind": "EVENT_COUNT", "size": 10},
        "enabled": True,
        "description": "Escalate when request rate is high.",
        "rationale": "Burst behavior indicates unstable operation.",
        "parameters": {"unit": "requests_per_window"},
    }


def test_tripwire_predicate_round_trip_dict() -> None:
    payload = _valid_predicate_dict()
    predicate = TripwirePredicate.from_dict(payload)

    assert predicate.metric is TripwireMetric.RATE
    assert predicate.operator is TripwireOperator.GT
    assert predicate.on_trigger is TripwireDecision.ESCALATE
    assert predicate.window.kind is TripwireWindowKind.EVENT_COUNT
    assert predicate.to_dict() == payload


def test_tripwire_predicate_rejects_non_finite_threshold() -> None:
    payload = _valid_predicate_dict()
    payload["threshold"] = float("nan")

    with pytest.raises(ValueError, match="threshold must be finite"):
        TripwirePredicate.from_dict(payload)


def test_tripwire_predicate_rejects_non_object_window() -> None:
    payload = _valid_predicate_dict()
    payload["window"] = "10s"

    with pytest.raises(ValueError, match="window is required and must be an object"):
        TripwirePredicate.from_dict(payload)


def test_tripwire_window_rejects_non_positive_size() -> None:
    with pytest.raises(ValueError, match="tripwire window size must be > 0"):
        TripwireWindow(kind=TripwireWindowKind.EVENT_COUNT, size=0)
