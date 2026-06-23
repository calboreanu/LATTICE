"""Fail-closed regression tests (surfaced by the adversarial suite).

A structurally malformed policy must not silently skip enforcement and ALLOW.
"""
from __future__ import annotations

from lattice.policy_engine import evaluate


def _ab():
    return {"target": "asset-1", "tool": "adjust", "tool_class": "OTHER", "scope_tags": [],
            "time_bound": "2099-01-01T00:00:00Z", "parameters": {},
            "confidence_scores": {k: 0.95 for k in ("objective_clarity", "tool_specificity",
                "constraint_completeness", "risk_assessment_depth", "precedent_availability", "composite")}}


def _pol(**kw):
    p = {"policy_id": "P", "version": "1.0", "allowed_targets": ["asset-1"],
         "permitted_tools": {"OTHER": ["adjust"], "DEFAULT": ["adjust"]}, "rules": [],
         "thresholds": {"autonomous": 85, "hitl": 65, "escalate": 45}}
    p.update(kw)
    return p


def test_non_list_rules_fail_closed():
    vr = evaluate(_ab(), _pol(rules="not-a-list"))
    assert vr.verdict == "BLOCK"
    assert "POLICY_RULES_INVALID" in vr.reason_codes


def test_dict_rules_fail_closed():
    vr = evaluate(_ab(), _pol(rules={"id": "x"}))
    assert vr.verdict == "BLOCK"
    assert "POLICY_RULES_INVALID" in vr.reason_codes


def test_valid_empty_rules_still_allow():
    # Regression guard: a *valid* empty list must remain unaffected.
    assert evaluate(_ab(), _pol(rules=[])).verdict == "ALLOW"
