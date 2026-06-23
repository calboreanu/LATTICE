"""Tests for native TIME_WINDOW and PREREQUISITE rule types (R7 / D2).

These two rule types close the rule-expressivity gap the reviewer identified:
maintenance/execution-window enforcement and prerequisite-check gating are now
enforceable as native, deterministic policy rules rather than relying on
confidence-mediated heuristics.
"""
from __future__ import annotations

from lattice.policy_engine import evaluate


def _base_action() -> dict:
    return {
        "target": "acme.example.com",
        "tool": "echo",
        "tool_class": "DEFAULT",
        "scope_tags": [],
        "time_bound": "2099-01-01T00:00:00Z",
        "confidence_scores": {
            "objective_clarity": 0.95,
            "tool_specificity": 0.95,
            "constraint_completeness": 0.95,
            "risk_assessment_depth": 0.95,
            "precedent_availability": 0.95,
            "composite": 0.95,
        },
    }


def _base_policy() -> dict:
    return {
        "policy_id": "P-TW-PR",
        "version": "1.0",
        "allowed_targets": ["acme.example.com"],
        "permitted_tools": {"DEFAULT": ["echo"]},
        "rules": [],
        "thresholds": {"autonomous": 85, "hitl": 65, "escalate": 45},
    }


# ---- TIME_WINDOW -----------------------------------------------------------

def _time_window_rule() -> dict:
    return {
        "type": "TIME_WINDOW",
        "effect": "BLOCK",
        "window": {"start": "2099-06-15T00:00:00Z", "end": "2099-06-16T00:00:00Z"},
        "reason_code": "MAINT_WINDOW_VIOLATION",
    }


def test_time_window_allows_inside_window() -> None:
    action = _base_action()
    action["time_bound"] = "2099-06-15T12:00:00Z"
    policy = _base_policy()
    policy["rules"] = [_time_window_rule()]
    assert evaluate(action, policy).verdict == "ALLOW"


def test_time_window_blocks_outside_window() -> None:
    action = _base_action()
    action["time_bound"] = "2099-07-01T12:00:00Z"
    policy = _base_policy()
    policy["rules"] = [_time_window_rule()]
    vr = evaluate(action, policy)
    assert vr.verdict == "BLOCK"
    assert "MAINT_WINDOW_VIOLATION" in vr.reason_codes


def test_time_window_default_reason_code() -> None:
    action = _base_action()
    action["time_bound"] = "2099-07-01T12:00:00Z"
    policy = _base_policy()
    rule = _time_window_rule()
    del rule["reason_code"]
    policy["rules"] = [rule]
    vr = evaluate(action, policy)
    assert vr.verdict == "BLOCK"
    assert "TIME_WINDOW_VIOLATION" in vr.reason_codes


# ---- PREREQUISITE ----------------------------------------------------------

def test_prerequisite_blocks_when_missing() -> None:
    action = _base_action()
    action["prerequisites_satisfied"] = ["work_order_open"]
    policy = _base_policy()
    policy["rules"] = [{
        "type": "PREREQUISITE",
        "effect": "BLOCK",
        "requires": ["upstream_isolation_verified", "work_order_open"],
        "reason_code": "PREREQ_MISSING",
    }]
    vr = evaluate(action, policy)
    assert vr.verdict == "BLOCK"
    assert "PREREQ_MISSING" in vr.reason_codes


def test_prerequisite_allows_when_all_satisfied() -> None:
    action = _base_action()
    action["prerequisites_satisfied"] = ["upstream_isolation_verified", "work_order_open"]
    policy = _base_policy()
    policy["rules"] = [{
        "type": "PREREQUISITE",
        "effect": "BLOCK",
        "requires": ["upstream_isolation_verified", "work_order_open"],
    }]
    assert evaluate(action, policy).verdict == "ALLOW"


def test_prerequisite_escalate_effect() -> None:
    action = _base_action()
    action["prerequisites_satisfied"] = []
    policy = _base_policy()
    policy["rules"] = [{
        "type": "PREREQUISITE",
        "effect": "ESCALATE",
        "requires": ["upstream_isolation_verified"],
    }]
    vr = evaluate(action, policy)
    assert vr.verdict == "ESCALATE"
    assert "PREREQUISITE_NOT_MET" in vr.reason_codes


def test_prerequisite_hard_safety_overrides_high_confidence() -> None:
    # High planner confidence must NOT bypass an unmet hard prerequisite.
    action = _base_action()  # composite 0.95
    action["prerequisites_satisfied"] = []
    policy = _base_policy()
    policy["rules"] = [{
        "type": "PREREQUISITE",
        "effect": "BLOCK",
        "requires": ["upstream_isolation_verified"],
        "reason_code": "PREREQ_MISSING",
    }]
    vr = evaluate(action, policy)
    assert vr.verdict == "BLOCK"
