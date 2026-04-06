"""Comprehensive governance engine matrix tests (KAN-305)."""
from __future__ import annotations

from typing import Any

import pytest

from lattice.execution_gate import enforce
from lattice.policy_engine import evaluate


def _base_policy() -> dict:
    return {
        "policy_id": "POL-305-BASE",
        "version": "1.0",
        "allowed_targets": ["acme.example.com"],
        "permitted_tools": {"DEFAULT": ["echo"]},
        "rules": [],
        "thresholds": {"autonomous": 85, "hitl": 65, "escalate": 45},
    }


def _base_action(confidence: float = 0.95) -> dict:
    return {
        "target": "acme.example.com",
        "tool": "echo",
        "tool_class": "DEFAULT",
        "scope_tags": [],
        "time_bound": "2099-01-01T00:00:00Z",
        "confidence_scores": {
            "objective_clarity": confidence,
            "tool_specificity": confidence,
            "constraint_completeness": confidence,
            "risk_assessment_depth": confidence,
            "precedent_availability": confidence,
            "composite": confidence,
        },
    }


def _decision_tree() -> dict:
    return {
        "start": "exec",
        "nodes": [
            {
                "id": "exec",
                "kind": "EXECUTE_STEP",
                "default": "exec",
                "edges": [{"when": {"signal": "DONE"}, "to": "end"}],
            },
            {"id": "end", "kind": "END", "default": "end"},
        ],
    }


def _tripwire(predicate_id: str = "TW-305-01") -> dict:
    return {
        "predicate_id": predicate_id,
        "metric": "RATE",
        "operator": "GT",
        "threshold": 2.0,
        "on_trigger": "ESCALATE",
        "window": {"kind": "EVENT_COUNT", "size": 5},
    }


@pytest.mark.parametrize(
    ("composite", "expected_verdict"),
    [
        (0.99, "ALLOW"),
        (0.95, "ALLOW"),
        (0.90, "ALLOW"),
        (0.88, "ALLOW"),
        (0.85, "ALLOW"),
        (0.84, "ESCALATE"),
        (0.80, "ESCALATE"),
        (0.75, "ESCALATE"),
        (0.70, "ESCALATE"),
        (0.65, "ESCALATE"),
        (0.60, "ESCALATE"),
        (0.55, "ESCALATE"),
        (0.50, "ESCALATE"),
        (0.45, "ESCALATE"),
        (0.44, "BLOCK"),
        (0.40, "BLOCK"),
        (0.35, "BLOCK"),
        (0.30, "BLOCK"),
        (0.20, "BLOCK"),
        (0.10, "BLOCK"),
        (0.00, "BLOCK"),
    ],
)
def test_confidence_threshold_matrix(composite: float, expected_verdict: str) -> None:
    vr = evaluate(_base_action(confidence=composite), _base_policy())
    assert vr.verdict == expected_verdict


@pytest.mark.parametrize(
    ("rule_type", "triggered", "effect", "penalty", "expected_verdict"),
    [
        ("TARGET_DENYLIST", True, "BLOCK", 0, "BLOCK"),
        ("TOOL_DENYLIST", True, "BLOCK", 0, "BLOCK"),
        ("SCOPE_TAG_DENYLIST", True, "BLOCK", 0, "BLOCK"),
        ("TARGET_ALLOWLIST", True, "BLOCK", 0, "BLOCK"),
        ("TOOL_ALLOWLIST", True, "BLOCK", 0, "BLOCK"),
        ("TARGET_DENYLIST", False, "BLOCK", 0, "ALLOW"),
        ("TOOL_DENYLIST", False, "BLOCK", 0, "ALLOW"),
        ("SCOPE_TAG_DENYLIST", False, "BLOCK", 0, "ALLOW"),
        ("TARGET_ALLOWLIST", False, "BLOCK", 0, "ALLOW"),
        ("TOOL_ALLOWLIST", False, "BLOCK", 0, "ALLOW"),
        ("TARGET_DENYLIST", True, "ESCALATE", 0, "ESCALATE"),
        ("TOOL_DENYLIST", True, "ESCALATE", 0, "ESCALATE"),
        ("SCOPE_TAG_DENYLIST", True, "ESCALATE", 0, "ESCALATE"),
        ("TARGET_ALLOWLIST", True, "ESCALATE", 0, "ESCALATE"),
        ("TOOL_ALLOWLIST", True, "ESCALATE", 0, "ESCALATE"),
        ("TARGET_DENYLIST", True, "SCORE", 10, "ESCALATE"),
        ("TOOL_DENYLIST", True, "SCORE", 10, "ESCALATE"),
        ("SCOPE_TAG_DENYLIST", True, "SCORE", 10, "ESCALATE"),
        ("TARGET_ALLOWLIST", True, "SCORE", 10, "ESCALATE"),
        ("TOOL_ALLOWLIST", True, "SCORE", 10, "ESCALATE"),
        ("TARGET_DENYLIST", True, "SCORE", 70, "BLOCK"),
    ],
)
def test_rule_effect_matrix(
    rule_type: str,
    triggered: bool,
    effect: str,
    penalty: float,
    expected_verdict: str,
) -> None:
    action = _base_action(confidence=0.95)
    policy = _base_policy()

    values: list[str] = []
    if rule_type == "TARGET_DENYLIST":
        values = ["acme.example.com"] if triggered else ["other.example.com"]
    elif rule_type == "TARGET_ALLOWLIST":
        values = ["other.example.com"] if triggered else ["acme.example.com"]
    elif rule_type == "TOOL_DENYLIST":
        values = ["echo"] if triggered else ["nmap"]
    elif rule_type == "TOOL_ALLOWLIST":
        values = ["nmap"] if triggered else ["echo"]
    elif rule_type == "SCOPE_TAG_DENYLIST":
        values = ["SENSITIVE"]
        action["scope_tags"] = ["SENSITIVE"] if triggered else []

    rule = {
        "type": rule_type,
        "effect": effect,
        "values": values,
        "reason_code": f"R_{rule_type}_{effect}",
    }
    if effect == "SCORE":
        rule["penalty"] = penalty

    policy["rules"] = [rule]
    vr = evaluate(action, policy)
    assert vr.verdict == expected_verdict


def test_unsupported_rule_type_is_fail_safe_escalate() -> None:
    action = _base_action(confidence=0.95)
    policy = _base_policy()
    policy["rules"] = [
        {"type": "UNKNOWN_RULE_TYPE", "effect": "BLOCK", "values": ["x"]},
    ]
    vr = evaluate(action, policy)
    assert vr.verdict == "ESCALATE"
    assert "RULE_TYPE_UNSUPPORTED:UNKNOWN_RULE_TYPE" in vr.reason_codes


@pytest.mark.parametrize(
    ("case_id", "expected_decision", "expected_reason_prefix"),
    [
        ("valid", "ALLOW", ""),
        ("tree_missing_start", "BLOCK", "DECISION_TREE_INVALID:"),
        ("tree_unknown_start", "BLOCK", "DECISION_TREE_INVALID:"),
        ("tree_duplicate_signal", "BLOCK", "DECISION_TREE_INVALID:"),
        ("tree_unknown_target", "BLOCK", "DECISION_TREE_INVALID:"),
        ("tripwire_not_list", "BLOCK", "TRIPWIRE_PREDICATES_INVALID:"),
        ("tripwire_non_object", "BLOCK", "TRIPWIRE_PREDICATES_INVALID:"),
        ("tripwire_missing_metric", "BLOCK", "TRIPWIRE_PREDICATES_INVALID:"),
        ("tripwire_duplicate_ids", "BLOCK", "TRIPWIRE_PREDICATES_INVALID:duplicate_id:"),
        ("tripwire_invalid_window", "BLOCK", "TRIPWIRE_PREDICATES_INVALID:"),
    ],
)
def test_execution_gate_validation_matrix(
    case_id: str,
    expected_decision: str,
    expected_reason_prefix: str,
    tmp_path,
) -> None:
    action = _base_action(confidence=0.95)
    policy = _base_policy()
    tree: dict[str, Any] = _decision_tree()
    tripwires: Any = [_tripwire()]

    if case_id == "tree_missing_start":
        tree.pop("start")
    elif case_id == "tree_unknown_start":
        tree["start"] = "missing"
    elif case_id == "tree_duplicate_signal":
        tree["nodes"][0]["edges"] = [
            {"when": {"signal": "DONE"}, "to": "end"},
            {"when": {"signal": "DONE"}, "to": "end"},
        ]
    elif case_id == "tree_unknown_target":
        tree["nodes"][0]["edges"] = [{"when": {"signal": "DONE"}, "to": "missing"}]
    elif case_id == "tripwire_not_list":
        tripwires = "not-a-list"
    elif case_id == "tripwire_non_object":
        tripwires = ["bad"]
    elif case_id == "tripwire_missing_metric":
        bad = _tripwire()
        bad.pop("metric")
        tripwires = [bad]
    elif case_id == "tripwire_duplicate_ids":
        first = _tripwire("TW-DUP")
        second = _tripwire("TW-DUP")
        tripwires = [first, second]
    elif case_id == "tripwire_invalid_window":
        bad = _tripwire()
        bad["window"]["size"] = 0
        tripwires = [bad]

    decision, audit = enforce(
        action,
        policy,
        str(tmp_path / f"{case_id}.audit.jsonl"),
        decision_tree=tree,
        tripwire_predicates=tripwires,
        require_signed_audit=False,
    )
    assert decision == expected_decision
    if expected_reason_prefix:
        assert any(code.startswith(expected_reason_prefix) for code in audit["reason_codes"])
    else:
        assert audit["verdict"] == "ALLOW"
