"""Tests for the governance-derived confidence cap (R6 / D1): c_eff = min(c_p, c_cap).

The cap is a deterministic ceiling computed from governance-observable action
attributes (irreversibility, tool privilege, novelty, cross-cell scope, contingency
artifacts), all parameterized by the policy bundle. Because it derives from
governance state rather than the planner's self-report, an overconfident or
adversarial planner cannot lift it by inflating its score. When the cap binds, a
``CONFIDENCE_CAP_APPLIED`` reason is recorded, which also removes the action from
autonomous ALLOW (autonomous ALLOW requires an empty reason set) -> human review.
"""
from __future__ import annotations

from lattice.policy_engine import evaluate

CAPS = {
    "irreversibility": {"reversible": 1.0, "partial": 0.85, "irreversible": 0.70},
    "privilege": {"RECON": 1.0, "SCAN": 0.90, "EXPLOIT": 0.70},
    "novelty_cap": 0.80,
    "novelty_precedent_threshold": 0.5,
    "cross_cell_cap": 0.85,
    "contingency_cap": 0.75,
}


def _action(**kw) -> dict:
    a = {
        "target": "acme.example.com",
        "tool": "echo",
        "tool_class": "DEFAULT",
        "scope_tags": [],
        "time_bound": "2099-01-01T00:00:00Z",
        "confidence_scores": {k: 0.95 for k in (
            "objective_clarity", "tool_specificity", "constraint_completeness",
            "risk_assessment_depth", "precedent_availability", "composite")},
    }
    a.update(kw)
    return a


def _policy(caps=CAPS, permitted=None) -> dict:
    p = {
        "policy_id": "P-CAP",
        "version": "1.0",
        "allowed_targets": ["acme.example.com"],
        "permitted_tools": permitted or {"DEFAULT": ["echo"]},
        "rules": [],
        "thresholds": {"autonomous": 85, "hitl": 65, "escalate": 45},
    }
    if caps:
        p["confidence_caps"] = caps
    return p


# Contingency present by default isolates the feature under test.
_OK = {"rollback_plan": True, "impact_assessment": True}


def test_no_caps_block_is_backward_compatible():
    assert evaluate(_action(**_OK), _policy(caps=None)).verdict == "ALLOW"


def test_reversible_with_contingency_unaffected():
    assert evaluate(_action(**_OK), _policy()).verdict == "ALLOW"


def test_irreversible_caps_to_human_review():
    vr = evaluate(_action(irreversibility_class="irreversible", **_OK), _policy())
    assert vr.verdict == "ESCALATE"
    assert "CONFIDENCE_CAP_APPLIED:irreversibility" in vr.reason_codes


def test_privilege_cap():
    a = _action(tool="x", tool_class="EXPLOIT", **_OK)
    vr = evaluate(a, _policy(permitted={"EXPLOIT": ["x"], "DEFAULT": ["x"]}))
    assert vr.verdict == "ESCALATE"
    assert "CONFIDENCE_CAP_APPLIED:privilege" in vr.reason_codes


def test_cross_cell_cap():
    vr = evaluate(_action(cross_cell_scope=True, **_OK), _policy())
    assert vr.verdict == "ESCALATE"
    assert "CONFIDENCE_CAP_APPLIED:cross_cell" in vr.reason_codes


def test_contingency_missing_caps():
    vr = evaluate(_action(), _policy())  # no rollback/impact
    assert vr.verdict == "ESCALATE"
    assert "CONFIDENCE_CAP_APPLIED:contingency" in vr.reason_codes


def test_contingency_present_allows():
    assert evaluate(_action(**_OK), _policy()).verdict == "ALLOW"


def test_most_conservative_feature_binds():
    a = _action(irreversibility_class="irreversible", cross_cell_scope=True, **_OK)
    vr = evaluate(a, _policy())
    # irreversibility (0.70) is lower than cross_cell (0.85) -> it binds
    assert "CONFIDENCE_CAP_APPLIED:irreversibility" in vr.reason_codes


def test_cap_never_raises_autonomy():
    # An overconfident planner on an irreversible action cannot get autonomous ALLOW.
    vr = evaluate(_action(irreversibility_class="irreversible", **_OK), _policy())
    assert vr.verdict != "ALLOW"
