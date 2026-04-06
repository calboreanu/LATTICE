"""Tests for KAN-294 planning agent scaffolding."""
from __future__ import annotations

import pytest

from aegis.llm import LLMAdapter, LLMResponse, ResponseParseError
from lattice.planning_agent import PlanningAgent


class QueueAdapter(LLMAdapter):
    def __init__(self, outputs):
        self.outputs = list(outputs)

    def generate(self, prompt: str, schema: dict) -> LLMResponse:
        if not self.outputs:
            raise RuntimeError("no queued outputs")
        output = self.outputs.pop(0)
        return LLMResponse(output=output, tokens_used=11, latency_ms=4.2, raw_response={"provider": "queue"})

    def generate_with_trace(self, prompt: str, schema: dict):
        response = self.generate(prompt, schema)
        return response, {"source": "queue"}


def _proposal(bundle_id: str) -> dict:
    return {
        "action_bundle": {"bundle_id": bundle_id, "target": "example.local", "tool": "echo"},
        "confidence_scores": {
            "objective_clarity": 0.9,
            "tool_specificity": 0.9,
            "constraint_completeness": 0.9,
            "risk_assessment_depth": 0.8,
            "precedent_availability": 0.7,
            "composite": 0.84,
        },
        "rationale": "baseline plan",
    }


def test_propose_bundle_parses_schema_valid_output() -> None:
    agent = PlanningAgent(adapter=QueueAdapter([_proposal("B-1")]))
    proposal = agent.propose_bundle({"mandate_id": "M-1"})

    assert proposal.action_bundle["bundle_id"] == "B-1"
    assert proposal.confidence_scores["composite"] == 0.84
    assert proposal.metadata["tokens_used"] == 11


def test_replan_bundle_rejects_invalid_schema_output() -> None:
    bad_output = {"action_bundle": {"bundle_id": "B-2"}, "rationale": "missing scores"}
    agent = PlanningAgent(adapter=QueueAdapter([bad_output]))

    with pytest.raises(ResponseParseError, match="schema validation failed"):
        agent.replan_bundle(
            original_bundle={"bundle_id": "B-1"},
            governance_verdict="BLOCK",
            rejection_reason="scope_violation",
        )


def test_plan_until_non_blocking_replans_after_block() -> None:
    adapter = QueueAdapter([_proposal("B-1"), _proposal("B-2")])
    agent = PlanningAgent(adapter=adapter)

    evaluations = {"count": 0}

    def evaluate(bundle: dict):
        evaluations["count"] += 1
        if evaluations["count"] == 1:
            return "BLOCK", "policy_violation"
        return "ALLOW", "ok"

    final, history = agent.plan_until_non_blocking({"mandate_id": "M-1"}, evaluate=evaluate)

    assert evaluations["count"] == 2
    assert len(history) == 2
    assert history[0].verdict == "BLOCK"
    assert history[1].verdict == "ALLOW"
    assert final.action_bundle["bundle_id"] == "B-2"
