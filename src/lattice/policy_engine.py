from __future__ import annotations
from dataclasses import dataclass
from typing import Any, Dict, List, Set
from datetime import datetime, timezone

_CONFIDENCE_COMPONENTS = (
    "objective_clarity",
    "tool_specificity",
    "constraint_completeness",
    "risk_assessment_depth",
    "precedent_availability",
)


@dataclass(frozen=True)
class VerdictResult:
    verdict: str  # ALLOW | BLOCK | ESCALATE
    confidence: float  # 0..100
    reason_codes: List[str]


@dataclass(frozen=True)
class RuleOutcome:
    verdict: str  # NONE | ESCALATE | BLOCK
    score_delta: float
    reason_code: str


@dataclass(frozen=True)
class ConfidenceOutcome:
    score: float  # 0..100
    reason_codes: List[str]


def _is_time_valid(time_bound: str) -> bool:
    try:
        # Accept 'Z' suffix as UTC
        tb = time_bound.replace("Z", "+00:00")
        bound = datetime.fromisoformat(tb)
        now = datetime.now(timezone.utc)
        return now <= bound.astimezone(timezone.utc)
    except Exception:
        return False


def _to_str_set(values: Any) -> Set[str]:
    if not isinstance(values, list):
        return set()
    return {str(v) for v in values}


def _normalize_threshold(value: Any, default_percent: float) -> float:
    try:
        v = float(value)
    except Exception:
        return default_percent
    if 0.0 <= v <= 1.0:
        return v * 100.0
    return v


def _compute_confidence_outcome(action_bundle: Dict[str, Any], policy: Dict[str, Any]) -> ConfidenceOutcome:
    raw = action_bundle.get("confidence_scores")
    if raw is None:
        return ConfidenceOutcome(100.0, [])
    if not isinstance(raw, dict):
        return ConfidenceOutcome(0.0, ["CONFIDENCE_FORMAT_INVALID"])

    reasons: List[str] = []
    components: Dict[str, float] = {}
    for key in _CONFIDENCE_COMPONENTS:
        if key not in raw:
            reasons.append(f"CONFIDENCE_COMPONENT_MISSING:{key}")
            continue
        try:
            value = float(raw[key])
        except Exception:
            reasons.append(f"CONFIDENCE_COMPONENT_INVALID:{key}")
            continue
        if not (0.0 <= value <= 1.0):
            reasons.append(f"CONFIDENCE_COMPONENT_OUT_OF_RANGE:{key}")
            continue
        components[key] = value

    if len(components) != len(_CONFIDENCE_COMPONENTS):
        return ConfidenceOutcome(0.0, reasons or ["CONFIDENCE_COMPONENTS_INVALID"])

    raw_weights = policy.get("confidence_weights", {})
    weights: Dict[str, float] = {}
    for key in _CONFIDENCE_COMPONENTS:
        try:
            weight = float(raw_weights.get(key, 1.0)) if isinstance(raw_weights, dict) else 1.0
        except Exception:
            weight = 1.0
        if weight < 0:
            reasons.append(f"CONFIDENCE_WEIGHT_INVALID:{key}")
            weight = 0.0
        weights[key] = weight

    total_weight = sum(weights.values())
    if total_weight <= 0:
        reasons.append("CONFIDENCE_WEIGHTS_INVALID")
        weights = {k: 1.0 for k in _CONFIDENCE_COMPONENTS}
        total_weight = float(len(_CONFIDENCE_COMPONENTS))

    computed_composite = sum(components[key] * weights[key] for key in _CONFIDENCE_COMPONENTS) / total_weight

    declared_composite = raw.get("composite")
    if declared_composite is None:
        composite = computed_composite
    else:
        try:
            composite = float(declared_composite)
        except Exception:
            reasons.append("CONFIDENCE_COMPOSITE_INVALID")
            composite = computed_composite
        if not (0.0 <= composite <= 1.0):
            reasons.append("CONFIDENCE_COMPOSITE_OUT_OF_RANGE")
            composite = computed_composite

    if abs(computed_composite - composite) > 0.15:
        reasons.append("CONFIDENCE_COMPOSITE_DIVERGENCE")

    return ConfidenceOutcome(composite * 100.0, reasons)


def _confidence_tier(score: float, thresholds: Dict[str, float]) -> str:
    if score >= thresholds["autonomous"]:
        return "AUTONOMOUS"
    if score >= thresholds["hitl"]:
        return "HITL"
    if score >= thresholds["escalate"]:
        return "ESCALATE"
    return "BLOCK"


def _evaluate_rule(
    rule: Dict[str, Any],
    *,
    target: str,
    tool: str,
    scope_tags: Set[str],
) -> RuleOutcome:
    rule_type = str(rule.get("type", "")).upper()
    effect = str(rule.get("effect", "BLOCK")).upper()
    values = _to_str_set(rule.get("values", []))
    reason_code = str(rule.get("reason_code", f"RULE_{rule_type}_TRIGGERED"))

    if not rule_type:
        return RuleOutcome("ESCALATE", 0.0, "RULE_TYPE_MISSING")

    triggered = False
    if rule_type == "TARGET_DENYLIST":
        triggered = target in values
    elif rule_type == "TOOL_DENYLIST":
        triggered = tool in values
    elif rule_type == "SCOPE_TAG_DENYLIST":
        triggered = bool(scope_tags.intersection(values))
    elif rule_type == "TARGET_ALLOWLIST":
        triggered = target not in values
    elif rule_type == "TOOL_ALLOWLIST":
        triggered = tool not in values
    else:
        return RuleOutcome("ESCALATE", 0.0, f"RULE_TYPE_UNSUPPORTED:{rule_type}")

    if not triggered:
        return RuleOutcome("NONE", 0.0, "")

    if effect == "BLOCK":
        return RuleOutcome("BLOCK", 0.0, reason_code)
    if effect == "ESCALATE":
        return RuleOutcome("ESCALATE", 0.0, reason_code)
    if effect == "SCORE":
        penalty = abs(float(rule.get("penalty", 25.0)))
        return RuleOutcome("NONE", -penalty, reason_code)
    return RuleOutcome("ESCALATE", 0.0, "RULE_EFFECT_UNSUPPORTED")


def evaluate(action_bundle: Dict[str, Any], policy: Dict[str, Any]) -> VerdictResult:
    """
    Deterministic multi-rule evaluation of an Action Bundle under a Policy Bundle.

    Rule support:
    - TARGET_DENYLIST / TARGET_ALLOWLIST
    - TOOL_DENYLIST / TOOL_ALLOWLIST
    - SCOPE_TAG_DENYLIST
    Effects:
    - BLOCK | ESCALATE | SCORE
    """
    reasons: List[str] = []
    target = action_bundle.get("target", "")
    tool = action_bundle.get("tool", "")
    tool_class = action_bundle.get("tool_class", "DEFAULT")
    scope_tags = set(action_bundle.get("scope_tags", []))
    time_bound = action_bundle.get("time_bound", "")

    allowed_targets = set(policy.get("allowed_targets", []))
    permitted_tools = policy.get("permitted_tools", {})
    allowed_tools = set(permitted_tools.get(tool_class, [])) | set(permitted_tools.get("DEFAULT", []))

    # Scoring heuristic (bounded). This is a *toy* confidence model.
    score = 100.0

    if target not in allowed_targets:
        reasons.append("TARGET_OUT_OF_SCOPE")
        score -= 60.0

    if tool not in allowed_tools:
        reasons.append("TOOL_NOT_PERMITTED")
        score -= 60.0

    if "OUT_OF_SCOPE" in scope_tags:
        reasons.append("SCOPE_TAG_OUT_OF_SCOPE")
        score -= 40.0

    if not _is_time_valid(time_bound):
        reasons.append("TIME_BOUND_INVALID_OR_EXPIRED")
        score -= 80.0

    confidence = _compute_confidence_outcome(action_bundle, policy)
    score = min(score, confidence.score)
    reasons.extend(confidence.reason_codes)

    block_reasons: List[str] = []
    escalate_reasons: List[str] = []
    rule_score_delta = 0.0
    rules = policy.get("rules", [])
    if isinstance(rules, list):
        for raw_rule in rules:
            if not isinstance(raw_rule, dict):
                escalate_reasons.append("RULE_NOT_OBJECT")
                continue
            outcome = _evaluate_rule(
                raw_rule,
                target=str(target),
                tool=str(tool),
                scope_tags={str(t) for t in scope_tags},
            )
            if outcome.verdict == "BLOCK":
                block_reasons.append(outcome.reason_code)
            elif outcome.verdict == "ESCALATE":
                escalate_reasons.append(outcome.reason_code)
            if outcome.score_delta:
                rule_score_delta += outcome.score_delta
                if outcome.reason_code:
                    reasons.append(outcome.reason_code)

    score += rule_score_delta
    score = max(0.0, min(100.0, score))

    raw_thr = policy.get("thresholds", {"autonomous": 85, "hitl": 65, "escalate": 45})
    thresholds = {
        "autonomous": _normalize_threshold(raw_thr.get("autonomous", 85), 85.0),
        "hitl": _normalize_threshold(raw_thr.get("hitl", 65), 65.0),
        "escalate": _normalize_threshold(raw_thr.get("escalate", 45), 45.0),
    }

    if block_reasons:
        return VerdictResult("BLOCK", score, reasons + block_reasons)
    if escalate_reasons:
        return VerdictResult("ESCALATE", score, reasons + escalate_reasons)

    if score >= thresholds["autonomous"] and not reasons:
        return VerdictResult("ALLOW", score, ["POLICY_ALLOW"])
    if score >= thresholds["hitl"] and ("TARGET_OUT_OF_SCOPE" not in reasons):
        # Example: still allowed but requires human-in-the-loop
        return VerdictResult("ESCALATE", score, reasons or ["CONFIDENCE_TIER_HITL"])
    if score >= thresholds["escalate"]:
        return VerdictResult("ESCALATE", score, reasons or ["CONFIDENCE_TIER_ESCALATE"])

    # Explicit confidence-tier annotation on fail-closed outcomes.
    tier = _confidence_tier(score, thresholds)
    if tier == "BLOCK" and "CONFIDENCE_TIER_BLOCK" not in reasons:
        reasons = reasons + ["CONFIDENCE_TIER_BLOCK"]
    return VerdictResult("BLOCK", score, reasons or ["POLICY_BLOCK"])
