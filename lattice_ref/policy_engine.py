from __future__ import annotations
from dataclasses import dataclass
from typing import Any, Dict, List, Tuple
from datetime import datetime, timezone

@dataclass(frozen=True)
class VerdictResult:
    verdict: str              # ALLOW | BLOCK | ESCALATE
    confidence: float         # 0..100
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

def evaluate(action_bundle: Dict[str, Any], policy: Dict[str, Any]) -> VerdictResult:
    """Deterministic evaluation of an Action Bundle under a Policy Bundle."""
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

    score = max(0.0, min(100.0, score))

    thr = policy.get("thresholds", {"autonomous": 85, "hitl": 65, "escalate": 45})
    if score >= float(thr.get("autonomous", 85)) and not reasons:
        return VerdictResult("ALLOW", score, ["POLICY_ALLOW"])
    if score >= float(thr.get("hitl", 65)) and ("TARGET_OUT_OF_SCOPE" not in reasons):
        # Example: still allowed but requires human-in-the-loop
        return VerdictResult("ESCALATE", score, reasons or ["HITL_REQUIRED"])
    return VerdictResult("BLOCK", score, reasons or ["POLICY_BLOCK"])
