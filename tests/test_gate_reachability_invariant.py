"""Gate-reachability invariant (R3): tools are reachable ONLY past an ALLOW verdict.

Two complementary checks:
  1. Dynamic: instrument the tool-execution primitive and assert it fires iff the
     governance gate returned ALLOW, across ALLOW / BLOCK / ESCALATE.
  2. Static: scan the lattice core and assert the only *call site* of
     ``sandbox_execute`` is the sanctioned ``governed_execution`` module — i.e.
     no code path reaches tools without traversing the gate.

This converts the paper's "non-bypassable by construction" from an assertion
into a checked structural property of the reference implementation.
"""
from __future__ import annotations

import pathlib
import tempfile

import lattice.governed_execution as ge
from lattice.governed_execution import governed_execute


def _action(**kw) -> dict:
    a = {
        "target": "acme.example.com",
        "tool": "echo",
        "tool_class": "DEFAULT",
        "scope_tags": [],
        "time_bound": "2099-01-01T00:00:00Z",
        "parameters": {},
        "confidence_scores": {k: 0.95 for k in (
            "objective_clarity", "tool_specificity", "constraint_completeness",
            "risk_assessment_depth", "precedent_availability", "composite")},
    }
    a.update(kw)
    return a


def _policy(**kw) -> dict:
    p = {
        "policy_id": "P-REACH",
        "version": "1.0",
        "allowed_targets": ["acme.example.com"],
        "permitted_tools": {"DEFAULT": ["echo"]},
        "rules": [],
        "thresholds": {"autonomous": 85, "hitl": 65, "escalate": 45},
    }
    p.update(kw)
    return p


def test_tool_executes_only_on_allow(monkeypatch):
    calls = {"n": 0}
    real = ge.sandbox_execute

    def _counting(action_bundle):
        calls["n"] += 1
        return real(action_bundle)

    monkeypatch.setattr(ge, "sandbox_execute", _counting)

    with tempfile.TemporaryDirectory() as d:
        audit = str(pathlib.Path(d) / "audit.jsonl")

        # ALLOW -> executes
        r = governed_execute(_action(), _policy(), audit, require_signed_audit=False)
        assert r["verdict"] == "ALLOW" and r["executed"] is True

        # BLOCK (out-of-scope target) -> no execution
        r = governed_execute(_action(target="evil.example.com"), _policy(), audit, require_signed_audit=False)
        assert r["executed"] is False and r["result"] is None

        # Non-ALLOW (irreversible action capped to human review) -> no execution.
        # The gate is binary: enforce() returns ALLOW or BLOCK; an ESCALATE
        # evaluation is treated as non-ALLOW and never reaches the tool.
        r = governed_execute(
            _action(irreversibility_class="irreversible"),
            _policy(confidence_caps={"irreversibility": {"irreversible": 0.70}}),
            audit, require_signed_audit=False,
        )
        assert r["verdict"] != "ALLOW" and r["executed"] is False

    # Exactly one tool execution occurred, for the single ALLOW.
    assert calls["n"] == 1


def test_no_other_call_site_for_sandbox_execute():
    core = pathlib.Path(ge.__file__).parent
    offenders = []
    for path in core.glob("*.py"):
        if path.name in ("sandbox_stub.py", "governed_execution.py"):
            continue  # definition + sanctioned caller
        text = path.read_text(encoding="utf-8")
        if "sandbox_execute(" in text:
            offenders.append(path.name)
    assert offenders == [], f"tool execution reachable outside the gate in: {offenders}"
