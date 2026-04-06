"""Tests for 5-component confidence scoring and tier thresholds."""
from __future__ import annotations

from lattice.policy_engine import evaluate


def _policy() -> dict:
    return {
        "policy_id": "P-CONF-001",
        "version": "1.0",
        "allowed_targets": ["acme.example.com"],
        "permitted_tools": {"DEFAULT": ["echo"]},
        "rules": [],
        "thresholds": {"autonomous": 85, "hitl": 65, "escalate": 45},
    }


def _action_with_confidence(composite: float) -> dict:
    return {
        "target": "acme.example.com",
        "tool": "echo",
        "tool_class": "DEFAULT",
        "scope_tags": [],
        "time_bound": "2099-01-01T00:00:00Z",
        "confidence_scores": {
            "objective_clarity": composite,
            "tool_specificity": composite,
            "constraint_completeness": composite,
            "risk_assessment_depth": composite,
            "precedent_availability": composite,
            "composite": composite,
        },
    }


def test_confidence_tier_allows_high_confidence() -> None:
    vr = evaluate(_action_with_confidence(0.95), _policy())
    assert vr.verdict == "ALLOW"
    assert vr.confidence == 95.0


def test_confidence_tier_escalates_mid_confidence() -> None:
    vr = evaluate(_action_with_confidence(0.60), _policy())
    assert vr.verdict == "ESCALATE"
    assert vr.confidence == 60.0


def test_confidence_tier_blocks_low_confidence() -> None:
    vr = evaluate(_action_with_confidence(0.20), _policy())
    assert vr.verdict == "BLOCK"
    assert vr.confidence == 20.0
    assert "CONFIDENCE_TIER_BLOCK" in vr.reason_codes


def test_confidence_thresholds_support_normalized_scale() -> None:
    policy = _policy()
    policy["thresholds"] = {"autonomous": 0.90, "hitl": 0.70, "escalate": 0.50}
    vr = evaluate(_action_with_confidence(0.75), policy)
    assert vr.verdict == "ESCALATE"


def test_confidence_missing_component_blocks_fail_closed() -> None:
    action = _action_with_confidence(0.90)
    action["confidence_scores"].pop("objective_clarity")
    vr = evaluate(action, _policy())
    assert vr.verdict == "BLOCK"
    assert "CONFIDENCE_COMPONENT_MISSING:objective_clarity" in vr.reason_codes
