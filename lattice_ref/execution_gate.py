from __future__ import annotations
from typing import Any, Dict, Tuple
from .canonicalize import canonicalize
from .hashing import sha256_hex
from .policy_engine import evaluate, VerdictResult
from .audit_log import append_audit_record

def enforce(action_bundle: Dict[str, Any], policy: Dict[str, Any], audit_path: str) -> Tuple[str, Dict[str, Any]]:
    """Algorithm 1: Immutable Bundle Enforcement (TOCTOU Prevention)"""
    # 1-2. canonicalize + hash
    ab_canon = canonicalize(action_bundle)
    h = sha256_hex(ab_canon)

    # 3. evaluate (deterministic)
    vr: VerdictResult = evaluate(action_bundle, policy)

    # 4. record (pre-commit)
    audit_record = append_audit_record(audit_path, {
        "action_hash": h,
        "policy_id": policy.get("policy_id", "UNKNOWN"),
        "policy_version": policy.get("version", "UNKNOWN"),
        "verdict": vr.verdict,
        "confidence": vr.confidence,
        "reason_codes": list(vr.reason_codes),
    })

    # 5. allow only if ALLOW
    if vr.verdict != "ALLOW":
        return "BLOCK", audit_record

    # 6. gate check (rehash)
    if sha256_hex(canonicalize(action_bundle)) != h:
        # TOCTOU / mutation detected
        # record a second audit note (optional) by reusing append with reason code
        append_audit_record(audit_path, {
            "action_hash": h,
            "policy_id": policy.get("policy_id", "UNKNOWN"),
            "policy_version": policy.get("version", "UNKNOWN"),
            "verdict": "BLOCK",
            "confidence": 0.0,
            "reason_codes": ["TOCTOU_DETECTED"],
        })
        return "BLOCK", audit_record

    return "ALLOW", audit_record
