"""Tests for multi-rule deterministic policy evaluation."""
from __future__ import annotations

from lattice.policy_engine import evaluate


def _base_action_bundle() -> dict:
    return {
        "target": "acme.example.com",
        "tool": "echo",
        "tool_class": "DEFAULT",
        "scope_tags": [],
        "time_bound": "2099-01-01T00:00:00Z",
    }


def _base_policy_bundle() -> dict:
    return {
        "policy_id": "P-MULTI-001",
        "version": "1.0",
        "allowed_targets": ["acme.example.com"],
        "permitted_tools": {"DEFAULT": ["echo"]},
        "rules": [],
        "thresholds": {"autonomous": 85, "hitl": 65, "escalate": 45},
    }


def test_multi_rule_engine_allows_when_no_rule_fires() -> None:
    vr = evaluate(_base_action_bundle(), _base_policy_bundle())
    assert vr.verdict == "ALLOW"
    assert vr.confidence == 100.0
    assert vr.reason_codes == ["POLICY_ALLOW"]


def test_multi_rule_engine_blocks_on_tool_denylist_rule() -> None:
    policy = _base_policy_bundle()
    policy["rules"] = [
        {
            "type": "TOOL_DENYLIST",
            "effect": "BLOCK",
            "values": ["echo"],
            "reason_code": "RULE_BLOCK_ECHO",
        }
    ]

    vr = evaluate(_base_action_bundle(), policy)
    assert vr.verdict == "BLOCK"
    assert "RULE_BLOCK_ECHO" in vr.reason_codes


def test_multi_rule_engine_escalates_on_scope_tag_rule() -> None:
    action = _base_action_bundle()
    action["scope_tags"] = ["SENSITIVE"]
    policy = _base_policy_bundle()
    policy["rules"] = [
        {
            "type": "SCOPE_TAG_DENYLIST",
            "effect": "ESCALATE",
            "values": ["SENSITIVE"],
            "reason_code": "RULE_SCOPE_ESCALATE",
        }
    ]

    vr = evaluate(action, policy)
    assert vr.verdict == "ESCALATE"
    assert "RULE_SCOPE_ESCALATE" in vr.reason_codes


def test_multi_rule_engine_applies_score_penalty_effect() -> None:
    policy = _base_policy_bundle()
    policy["rules"] = [
        {
            "type": "TARGET_ALLOWLIST",
            "effect": "SCORE",
            "values": ["other.example.com"],
            "penalty": 60,
            "reason_code": "RULE_TARGET_PENALTY",
        }
    ]

    vr = evaluate(_base_action_bundle(), policy)
    assert vr.verdict == "BLOCK"
    assert vr.confidence == 40.0
    assert "RULE_TARGET_PENALTY" in vr.reason_codes


def test_multi_rule_engine_unsupported_rule_type_escalates_fail_safe() -> None:
    policy = _base_policy_bundle()
    policy["rules"] = [
        {
            "type": "UNSUPPORTED_RULE",
            "effect": "BLOCK",
            "values": ["x"],
        }
    ]

    vr = evaluate(_base_action_bundle(), policy)
    assert vr.verdict == "ESCALATE"
    assert "RULE_TYPE_UNSUPPORTED:UNSUPPORTED_RULE" in vr.reason_codes
