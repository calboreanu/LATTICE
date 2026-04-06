"""Tests for lattice.models.ConfidenceScore."""
from __future__ import annotations

import pytest

from lattice.models import ConfidenceScore


def test_confidence_score_defaults_composite_to_average() -> None:
    score = ConfidenceScore(
        objective_clarity=1.0,
        tool_specificity=0.5,
        constraint_completeness=0.5,
        risk_assessment_depth=0.5,
        precedent_availability=0.5,
    )
    assert score.composite == pytest.approx(0.6)


def test_confidence_score_weighted_composite() -> None:
    score = ConfidenceScore(
        objective_clarity=0.8,
        tool_specificity=0.6,
        constraint_completeness=0.7,
        risk_assessment_depth=0.9,
        precedent_availability=0.4,
    )
    composite = score.compute_composite(
        weights={
            "objective_clarity": 2.0,
            "tool_specificity": 1.0,
            "constraint_completeness": 1.0,
            "risk_assessment_depth": 1.0,
            "precedent_availability": 1.0,
        }
    )
    assert 0.0 <= composite <= 1.0
    assert composite == pytest.approx((2 * 0.8 + 0.6 + 0.7 + 0.9 + 0.4) / 6.0)


def test_confidence_score_rejects_out_of_range_values() -> None:
    with pytest.raises(ValueError):
        ConfidenceScore(
            objective_clarity=1.2,
            tool_specificity=0.5,
            constraint_completeness=0.5,
            risk_assessment_depth=0.5,
            precedent_availability=0.5,
        )


def test_confidence_score_round_trip_dict() -> None:
    original = ConfidenceScore(
        objective_clarity=0.9,
        tool_specificity=0.8,
        constraint_completeness=0.7,
        risk_assessment_depth=0.6,
        precedent_availability=0.5,
    )
    payload = original.to_dict()
    loaded = ConfidenceScore.from_dict(payload)
    assert loaded.to_dict() == payload
