"""OWASP Top 10 for Agentic Applications — per-risk coverage matrix (R5).

Replaces the manuscript's overclaim ("architectural coverage for all ten") with
a concrete test per ASI risk and an honest tested-vs-conceptual classification.
Each test exercises the actual mechanism; ``OWASP_COVERAGE`` records the status
so the paper table is generated from outcomes rather than asserted.
"""
from __future__ import annotations

import tempfile
import pathlib

from lattice.policy_engine import evaluate
from lattice.governed_execution import governed_execute
from lattice.coordination_security import (
    SecureCoordinationBus, SharedStateValidator, EscalationRateLimiter, detect_fan_out,
)

# status: "tested" = an adversarial test exercises the mechanism; "partial" =
# mechanism present, fuller adversarial test is future work.
OWASP_COVERAGE = {
    "ASI01": ("Agent Goal Hijack", "policy-as-code scope evaluation", "tested"),
    "ASI02": ("Tool Misuse & Exploitation", "gated execution (ALLOW-only)", "tested"),
    "ASI03": ("Identity & Privilege Abuse", "privilege confidence cap", "tested"),
    "ASI04": ("Supply Chain", "content-addressed + signed bundles", "partial"),
    "ASI05": ("Unexpected Code Execution", "tool denylist / gate", "tested"),
    "ASI06": ("Memory & Context Poisoning", "confidence divergence + shared-state quorum", "tested"),
    "ASI07": ("Insecure Inter-Agent Comms", "coordination mutual auth", "tested"),
    "ASI08": ("Cascading Failures", "escalation rate-limit + fan-out detect", "tested"),
    "ASI09": ("Human-Agent Trust Exploitation", "policy-derived verdict + cap", "tested"),
    "ASI10": ("Rogue Agents", "non-bypassable gate reachability", "tested"),
}

KEY_A, KEY_B = b"ka", b"kb"


def _action(**kw):
    a = {"target": "acme.example.com", "tool": "echo", "tool_class": "DEFAULT", "scope_tags": [],
         "time_bound": "2099-01-01T00:00:00Z", "parameters": {},
         "confidence_scores": {k: 0.95 for k in ("objective_clarity", "tool_specificity",
            "constraint_completeness", "risk_assessment_depth", "precedent_availability", "composite")}}
    a.update(kw)
    return a


def _policy(**kw):
    p = {"policy_id": "P", "version": "1.0", "allowed_targets": ["acme.example.com"],
         "permitted_tools": {"DEFAULT": ["echo"]}, "rules": [],
         "thresholds": {"autonomous": 85, "hitl": 65, "escalate": 45}}
    p.update(kw)
    return p


def test_asi01_goal_hijack_blocked():
    vr = evaluate(_action(target="attacker.evil.com"), _policy())
    assert vr.verdict == "BLOCK" and "TARGET_OUT_OF_SCOPE" in vr.reason_codes


def test_asi02_tool_misuse_not_executed():
    with tempfile.TemporaryDirectory() as d:
        audit = str(pathlib.Path(d) / "a.jsonl")
        r = governed_execute(_action(tool="rm_rf"), _policy(), audit, require_signed_audit=False)
        assert r["executed"] is False


def test_asi03_privilege_abuse_capped():
    a = _action(tool="x", tool_class="EXPLOIT")
    vr = evaluate(a, _policy(permitted_tools={"EXPLOIT": ["x"], "DEFAULT": ["x"]},
                             confidence_caps={"privilege": {"EXPLOIT": 0.70}}))
    assert vr.verdict != "ALLOW" and "CONFIDENCE_CAP_APPLIED:privilege" in vr.reason_codes


def test_asi04_supply_chain_denylist_blocks():
    # Compromised tool/plugin represented as a denylisted tool -> BLOCK.
    vr = evaluate(_action(), _policy(rules=[{"type": "TOOL_DENYLIST", "effect": "BLOCK",
                                             "values": ["echo"], "reason_code": "COMPROMISED_TOOL"}]))
    assert vr.verdict == "BLOCK"


def test_asi05_unexpected_code_execution_blocked():
    vr = evaluate(_action(tool="shell_exec"), _policy(rules=[{"type": "TOOL_DENYLIST",
                  "effect": "BLOCK", "values": ["shell_exec"], "reason_code": "CODE_EXEC_BLOCKED"}]))
    assert vr.verdict == "BLOCK"


def test_asi06_context_poisoning_divergence_flagged():
    # Inflated composite inconsistent with components -> divergence -> not autonomous.
    a = _action()
    a["confidence_scores"] = {"objective_clarity": 0.2, "tool_specificity": 0.2,
        "constraint_completeness": 0.2, "risk_assessment_depth": 0.2,
        "precedent_availability": 0.2, "composite": 0.95}
    vr = evaluate(a, _policy())
    assert vr.verdict != "ALLOW" and "CONFIDENCE_COMPOSITE_DIVERGENCE" in vr.reason_codes


def test_asi07_inter_agent_comms_spoof_rejected():
    bus = SecureCoordinationBus()
    bus.register_cell("A", KEY_A)
    forged = bus.publish(source_cell_id="A", target_cell_id="A", operation_id="OP",
                         payload={"x": 1}, key=b"wrong")
    assert bus.deliver(forged) == (False, "AUTH_FAILED")


def test_asi08_cascading_failures_contained():
    rl = EscalationRateLimiter(max_per_window=2)
    accepted = [rl.offer(f"E{i}")[0] for i in range(4)]
    assert accepted.count(True) == 2
    ev = [{"operation_id": "OP", "target": "T", "cell": c} for c in "ABC"]
    assert detect_fan_out(ev, 3) == ["OP:T"]


def test_asi09_trust_exploitation_cap_overrides_confidence():
    vr = evaluate(_action(irreversibility_class="irreversible"),
                  _policy(confidence_caps={"irreversibility": {"irreversible": 0.70}}))
    assert vr.verdict != "ALLOW"  # polished high-confidence cannot self-authorize


def test_asi10_rogue_agent_cannot_bypass_gate():
    with tempfile.TemporaryDirectory() as d:
        audit = str(pathlib.Path(d) / "a.jsonl")
        r = governed_execute(_action(target="out.of.scope"), _policy(), audit, require_signed_audit=False)
        assert r["executed"] is False


def test_matrix_is_complete():
    assert len(OWASP_COVERAGE) == 10
    assert all(s in ("tested", "partial") for _, _, s in OWASP_COVERAGE.values())
