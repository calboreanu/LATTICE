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


def _parse_iso(value: str) -> datetime:
    # Accept 'Z' suffix as UTC; return a tz-aware UTC datetime.
    tb = str(value).replace("Z", "+00:00")
    return datetime.fromisoformat(tb).astimezone(timezone.utc)


def _is_time_valid(time_bound: str) -> bool:
    try:
        return datetime.now(timezone.utc) <= _parse_iso(time_bound)
    except Exception:
        return False


def _within_time_window(time_value: str, window: Dict[str, Any]) -> bool:
    """True if time_value falls within [start, end] inclusive; an absent bound is open-ended."""
    if not isinstance(window, dict):
        return False
    try:
        t = _parse_iso(time_value)
    except Exception:
        return False
    start = window.get("start")
    end = window.get("end")
    try:
        if start and t < _parse_iso(start):
            return False
        if end and t > _parse_iso(end):
            return False
    except Exception:
        return False
    return True


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


_DEFAULT_IRREVERSIBILITY_CAPS = {"reversible": 1.0, "partial": 0.85, "irreversible": 0.70}


def _clamp01(x: float) -> float:
    return 0.0 if x < 0.0 else 1.0 if x > 1.0 else x


def _compute_confidence_cap(action_bundle: Dict[str, Any], policy: Dict[str, Any]):
    """Deterministic, governance-derived ceiling on effective confidence (R6).

    Returns ``(cap_fraction in [0,1], binding_feature | None)``. The cap is the
    most conservative ceiling across governance-observable features; every value
    comes from the policy bundle's ``confidence_caps`` block, so the cap is
    auditable and tunable rather than a hidden heuristic. Absent config => no
    constraint (backward compatible). Because the cap is derived from
    governance-observable attributes -- not the planner's self-report -- a
    miscalibrated or adversarial planner cannot lift it by inflating its score.
    """
    caps = policy.get("confidence_caps")
    if not isinstance(caps, dict) or not caps:
        return 1.0, None

    ceilings: Dict[str, float] = {}

    irr_map = caps.get("irreversibility", _DEFAULT_IRREVERSIBILITY_CAPS)
    if isinstance(irr_map, dict):
        cls = str(action_bundle.get("irreversibility_class", "reversible")).lower()
        ceilings["irreversibility"] = _clamp01(float(irr_map.get(cls, 1.0)))

    priv_map = caps.get("privilege")
    if isinstance(priv_map, dict):
        tc = str(action_bundle.get("tool_class", "OTHER"))
        if tc in priv_map:
            ceilings["privilege"] = _clamp01(float(priv_map[tc]))

    if "novelty_cap" in caps:
        scores = action_bundle.get("confidence_scores", {})
        precedent = scores.get("precedent_availability") if isinstance(scores, dict) else None
        thresh = float(caps.get("novelty_precedent_threshold", 0.5))
        try:
            if precedent is not None and float(precedent) < thresh:
                ceilings["novelty"] = _clamp01(float(caps["novelty_cap"]))
        except Exception:
            pass

    if "cross_cell_cap" in caps and action_bundle.get("cross_cell_scope"):
        ceilings["cross_cell"] = _clamp01(float(caps["cross_cell_cap"]))

    if "contingency_cap" in caps:
        has_contingency = bool(action_bundle.get("rollback_plan")) and bool(action_bundle.get("impact_assessment"))
        if not has_contingency:
            ceilings["contingency"] = _clamp01(float(caps["contingency_cap"]))

    if not ceilings:
        return 1.0, None
    binding = min(ceilings, key=ceilings.get)
    return ceilings[binding], binding


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
    action_bundle: Dict[str, Any],
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
    elif rule_type == "TIME_WINDOW":
        # Hard maintenance/execution-window enforcement: triggers when the action's
        # time_bound falls OUTSIDE the permitted window. Default effect BLOCK.
        triggered = not _within_time_window(str(action_bundle.get("time_bound", "")), rule.get("window", {}))
        if reason_code == f"RULE_{rule_type}_TRIGGERED":
            reason_code = "TIME_WINDOW_VIOLATION"
    elif rule_type == "PREREQUISITE":
        # Hard prerequisite gating (e.g., verify upstream isolation before downstream
        # switching): triggers when any required prerequisite is not satisfied.
        required = _to_str_set(rule.get("requires", rule.get("values", [])))
        satisfied = _to_str_set(action_bundle.get("prerequisites_satisfied", []))
        triggered = bool(required - satisfied)
        if reason_code == f"RULE_{rule_type}_TRIGGERED":
            reason_code = "PREREQUISITE_NOT_MET"
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
    - TIME_WINDOW (maintenance/execution-window enforcement)
    - PREREQUISITE (hard prerequisite gating)
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
    cap_fraction, cap_feature = _compute_confidence_cap(action_bundle, policy)
    effective_confidence = min(confidence.score, cap_fraction * 100.0)
    if effective_confidence < confidence.score:
        # Governance-derived cap binds: c_eff = min(c_p, c_cap). Recording a reason
        # also removes the action from autonomous ALLOW (which requires an empty
        # reason set), routing it to human review.
        reasons.append(f"CONFIDENCE_CAP_APPLIED:{cap_feature}")
    score = min(score, effective_confidence)
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
                action_bundle=action_bundle,
            )
            if outcome.verdict == "BLOCK":
                block_reasons.append(outcome.reason_code)
            elif outcome.verdict == "ESCALATE":
                escalate_reasons.append(outcome.reason_code)
            if outcome.score_delta:
                rule_score_delta += outcome.score_delta
                if outcome.reason_code:
                    reasons.append(outcome.reason_code)
    else:
        # Fail closed: a malformed (non-list) rules container is a structurally
        # invalid policy; do not silently skip enforcement.
        block_reasons.append("POLICY_RULES_INVALID")

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
