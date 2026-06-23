"""Policy-bundle linter (R8 + "policy-as-code != valid policy").

Policy-as-code makes enforcement auditable and repeatable, but it does not
guarantee the policy itself is correct, complete, or appropriately scoped. This
linter attacks that "policy-authoring opacity": it flags over-broad scope,
wildcard grants, permissive thresholds, and missing safeguards before a bundle
is deployed. ``policy_is_safe`` is false if any HIGH-severity finding is present.
"""
from __future__ import annotations

from typing import Any, Dict, List

WILDCARDS = {"*", "0.0.0.0/0", "::/0", "any", "all", "0.0.0.0"}


def _is_wild(value: Any) -> bool:
    s = str(value).strip().lower()
    return s in WILDCARDS or "*" in s


def lint_policy(policy: Dict[str, Any]) -> List[Dict[str, str]]:
    findings: List[Dict[str, str]] = []

    def add(sev: str, code: str, msg: str) -> None:
        findings.append({"severity": sev, "code": code, "message": msg})

    targets = policy.get("allowed_targets")
    if targets is None:
        add("HIGH", "NO_ALLOWLIST", "no allowed_targets defined (default-permit risk)")
    elif isinstance(targets, list):
        if not targets:
            add("HIGH", "EMPTY_ALLOWLIST", "allowed_targets is empty")
        for t in targets:
            if _is_wild(t):
                add("HIGH", "WILDCARD_TARGET", f"allowed_targets contains wildcard '{t}'")

    permitted = policy.get("permitted_tools", {})
    if isinstance(permitted, dict):
        for cls, tools in permitted.items():
            if any(_is_wild(x) for x in (tools or [])):
                add("HIGH", "WILDCARD_TOOL", f"permitted_tools['{cls}'] contains a wildcard tool grant")

    thresholds = policy.get("thresholds")
    if not isinstance(thresholds, dict):
        add("MED", "NO_THRESHOLDS", "no thresholds defined; engine defaults assumed")
    else:
        au = thresholds.get("autonomous")
        if isinstance(au, (int, float)):
            permissive = au <= 0.5 if au <= 1 else au <= 50
            if permissive:
                add("MED", "LOW_AUTONOMOUS_THRESHOLD", f"autonomous threshold {au} is permissive")

    if not policy.get("rules"):
        add("LOW", "NO_RULES", "policy defines no explicit rules")
    if "confidence_caps" not in policy:
        add("LOW", "NO_CONFIDENCE_CAPS", "no confidence_caps; high-consequence actions are not ceiling-capped")

    return findings


def policy_is_safe(policy: Dict[str, Any]) -> bool:
    return not any(f["severity"] == "HIGH" for f in lint_policy(policy))
