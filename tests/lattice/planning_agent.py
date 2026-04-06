from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

from aegis.llm import LLMAdapter, ResponseParseError, ResponseParser


@dataclass(frozen=True)
class PlanningAgentConfig:
    max_replan_iterations: int = 3
    include_policy_hints: bool = True


@dataclass(frozen=True)
class ProposedActionBundle:
    action_bundle: Dict[str, Any]
    confidence_scores: Dict[str, Any]
    rationale: str
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "action_bundle": dict(self.action_bundle),
            "confidence_scores": dict(self.confidence_scores),
            "rationale": self.rationale,
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True)
class PlanningIteration:
    iteration: int
    verdict: str
    reason: str
    proposal: ProposedActionBundle


_BUNDLE_OUTPUT_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "required": ["action_bundle", "confidence_scores", "rationale"],
    "properties": {
        "action_bundle": {"type": "object"},
        "confidence_scores": {
            "type": "object",
            "required": [
                "objective_clarity",
                "tool_specificity",
                "constraint_completeness",
                "risk_assessment_depth",
                "precedent_availability",
                "composite",
            ],
            "properties": {
                "objective_clarity": {"type": "number", "minimum": 0.0, "maximum": 1.0},
                "tool_specificity": {"type": "number", "minimum": 0.0, "maximum": 1.0},
                "constraint_completeness": {"type": "number", "minimum": 0.0, "maximum": 1.0},
                "risk_assessment_depth": {"type": "number", "minimum": 0.0, "maximum": 1.0},
                "precedent_availability": {"type": "number", "minimum": 0.0, "maximum": 1.0},
                "composite": {"type": "number", "minimum": 0.0, "maximum": 1.0},
            },
        },
        "rationale": {"type": "string"},
    },
}


class PlanningAgent:
    """LLM-driven Planning Agent with deterministic schema validation wrappers."""

    def __init__(
        self,
        adapter: LLMAdapter,
        *,
        parser: Optional[ResponseParser] = None,
        config: Optional[PlanningAgentConfig] = None,
    ) -> None:
        self.adapter = adapter
        self.parser = parser or ResponseParser()
        self.config = config or PlanningAgentConfig()

    def propose_bundle(
        self,
        mandate_as_code: Dict[str, Any],
        *,
        policy_hints: Optional[Dict[str, Any]] = None,
    ) -> ProposedActionBundle:
        prompt = self._build_proposal_prompt(mandate_as_code, policy_hints=policy_hints)
        raw = self.adapter.generate(prompt, _BUNDLE_OUTPUT_SCHEMA)
        return self._parse_proposal(raw.output, raw_metadata={"tokens_used": raw.tokens_used, "latency_ms": raw.latency_ms})

    def replan_bundle(
        self,
        *,
        original_bundle: Dict[str, Any],
        governance_verdict: str,
        rejection_reason: str,
    ) -> ProposedActionBundle:
        prompt = self._build_replan_prompt(
            original_bundle=original_bundle,
            governance_verdict=governance_verdict,
            rejection_reason=rejection_reason,
        )
        raw = self.adapter.generate(prompt, _BUNDLE_OUTPUT_SCHEMA)
        return self._parse_proposal(raw.output, raw_metadata={"tokens_used": raw.tokens_used, "latency_ms": raw.latency_ms})

    def plan_until_non_blocking(
        self,
        mandate_as_code: Dict[str, Any],
        *,
        evaluate: Callable[[Dict[str, Any]], Tuple[str, str]],
        policy_hints: Optional[Dict[str, Any]] = None,
    ) -> Tuple[ProposedActionBundle, List[PlanningIteration]]:
        proposal = self.propose_bundle(mandate_as_code, policy_hints=policy_hints)
        history: List[PlanningIteration] = []

        for iteration in range(self.config.max_replan_iterations + 1):
            verdict, reason = evaluate(proposal.action_bundle)
            history.append(
                PlanningIteration(
                    iteration=iteration,
                    verdict=str(verdict),
                    reason=str(reason),
                    proposal=proposal,
                )
            )
            if verdict != "BLOCK":
                return proposal, history
            if iteration >= self.config.max_replan_iterations:
                break
            proposal = self.replan_bundle(
                original_bundle=proposal.action_bundle,
                governance_verdict=verdict,
                rejection_reason=reason,
            )

        return proposal, history

    def _parse_proposal(self, output: Any, *, raw_metadata: Optional[Dict[str, Any]] = None) -> ProposedActionBundle:
        parsed = self.parser.parse_output(output, _BUNDLE_OUTPUT_SCHEMA)
        if not parsed.ok or parsed.parsed is None:
            raise ResponseParseError(parsed.error or "planning output parse failure")

        payload = parsed.parsed
        metadata = dict(raw_metadata or {})
        return ProposedActionBundle(
            action_bundle=dict(payload.get("action_bundle") or {}),
            confidence_scores=dict(payload.get("confidence_scores") or {}),
            rationale=str(payload.get("rationale", "")),
            metadata=metadata,
        )

    def _build_proposal_prompt(self, mandate_as_code: Dict[str, Any], *, policy_hints: Optional[Dict[str, Any]]) -> str:
        payload: Dict[str, Any] = {
            "task": "Propose a LATTICE action bundle from mandate-as-code.",
            "mandate_as_code": mandate_as_code,
            "output_schema": _BUNDLE_OUTPUT_SCHEMA,
            "rules": [
                "Do not emit policy verdicts (ALLOW/BLOCK/ESCALATE).",
                "Respect mandate constraints and scope boundaries.",
                "Emit calibrated confidence scores in [0.0, 1.0].",
            ],
        }
        if self.config.include_policy_hints and policy_hints is not None:
            payload["policy_hints"] = policy_hints
        return json.dumps(payload, ensure_ascii=False, sort_keys=True)

    @staticmethod
    def _build_replan_prompt(
        *,
        original_bundle: Dict[str, Any],
        governance_verdict: str,
        rejection_reason: str,
    ) -> str:
        payload: Dict[str, Any] = {
            "task": "Replan an action bundle after governance rejection.",
            "original_bundle": original_bundle,
            "governance_verdict": governance_verdict,
            "rejection_reason": rejection_reason,
            "output_schema": _BUNDLE_OUTPUT_SCHEMA,
            "rules": [
                "Address the rejection reason directly.",
                "Do not inflate confidence to bypass governance.",
                "If constraints are irreconcilable, return conservative bundle intent.",
            ],
        }
        return json.dumps(payload, ensure_ascii=False, sort_keys=True)


__all__ = [
    "PlanningAgentConfig",
    "ProposedActionBundle",
    "PlanningIteration",
    "PlanningAgent",
]
