from __future__ import annotations
import copy
from typing import Any, Dict, List, Optional, Tuple
try:
    from mandate.hashing import sha256_hex, canonical_json
except ImportError:
    from lattice._vendor.hashing import sha256_hex, canonical_json
from .policy_engine import evaluate, VerdictResult
from .audit_log import AuditSigner, append_audit_record
from .decision_tree_engine import (
    validate_decision_tree_payload,
    verify_safe_state_reachability,
)
from .models import DecisionTree, TripwirePredicate


def canonicalize(obj: Dict[str, Any]) -> str:
    """Produce deterministic canonical JSON for hashing (delegates to mandate.hashing)."""
    return canonical_json(obj)


def _governed_unit(
    action_bundle: Dict[str, Any],
    decision_tree: Dict[str, Any] | None,
    tripwire_predicates: List[Dict[str, Any]] | None,
) -> Dict[str, Any]:
    unit: Dict[str, Any] = {"action_bundle": action_bundle}
    if decision_tree is not None:
        unit["decision_tree"] = decision_tree
    if tripwire_predicates is not None:
        unit["tripwire_predicates"] = tripwire_predicates
    return unit


def _validate_governed_unit(
    decision_tree: Dict[str, Any] | None,
    tripwire_predicates: List[Dict[str, Any]] | None,
) -> List[str]:
    errors: List[str] = []
    if decision_tree is not None:
        result = validate_decision_tree_payload(decision_tree)
        if not result.ok:
            errors.extend([f"DECISION_TREE_INVALID:{err}" for err in result.errors])
        else:
            tree = DecisionTree.from_dict(decision_tree)
            reachability = verify_safe_state_reachability(tree)
            if not reachability.ok:
                errors.extend([f"DECISION_TREE_INVALID:{err}" for err in reachability.errors])

    if tripwire_predicates is not None:
        if not isinstance(tripwire_predicates, list):
            errors.append("TRIPWIRE_PREDICATES_INVALID:not_a_list")
        else:
            seen_ids: set[str] = set()
            for idx, predicate in enumerate(tripwire_predicates):
                if not isinstance(predicate, dict):
                    errors.append(f"TRIPWIRE_PREDICATES_INVALID:index_{idx}_not_object")
                    continue
                try:
                    parsed = TripwirePredicate.from_dict(predicate)
                except Exception as exc:
                    errors.append(f"TRIPWIRE_PREDICATES_INVALID:index_{idx}:{exc}")
                    continue
                if parsed.predicate_id in seen_ids:
                    errors.append(f"TRIPWIRE_PREDICATES_INVALID:duplicate_id:{parsed.predicate_id}")
                seen_ids.add(parsed.predicate_id)
    return errors


def enforce(
    action_bundle: Dict[str, Any],
    policy: Dict[str, Any],
    audit_path: str,
    *,
    decision_tree: Dict[str, Any] | None = None,
    tripwire_predicates: List[Dict[str, Any]] | None = None,
    audit_signer: Optional[AuditSigner] = None,
    require_signed_audit: bool = True,
) -> Tuple[str, Dict[str, Any]]:
    """Algorithm 1: Immutable Bundle Enforcement (TOCTOU Prevention) over the governed unit.

    KAN-792: Deep-copies all mutable inputs at the function boundary to
    eliminate the race window between hash computation, policy evaluation,
    and the post-evaluation re-hash check.  The gate now operates entirely
    on frozen snapshots; external mutations to the caller's dicts cannot
    affect the governance decision.
    """
    # --- KAN-792: Freeze mutable inputs at the gate boundary ----------------
    action_bundle = copy.deepcopy(action_bundle)
    policy = copy.deepcopy(policy)
    decision_tree = copy.deepcopy(decision_tree) if decision_tree is not None else None
    tripwire_predicates = copy.deepcopy(tripwire_predicates) if tripwire_predicates is not None else None

    # 1. snapshot hash
    governed_unit = _governed_unit(action_bundle, decision_tree, tripwire_predicates)
    unit_hash = sha256_hex(canonicalize(governed_unit))
    action_hash = sha256_hex(canonicalize(action_bundle))

    if require_signed_audit and audit_signer is None:
        raise ValueError(
            "audit signer is required when require_signed_audit=True but no signer was provided"
        )

    # 2. structural validation
    structural_errors = _validate_governed_unit(decision_tree, tripwire_predicates)
    if structural_errors:
        audit_record = append_audit_record(
            audit_path,
            {
                "event_type": "GOVERNANCE_VERDICT",
                "actor_id": "lattice.execution_gate",
                "unit_hash": unit_hash,
                "action_hash": action_hash,
                "policy_id": policy.get("policy_id", "UNKNOWN"),
                "policy_version": policy.get("version", "UNKNOWN"),
                "verdict": "BLOCK",
                "confidence": 0.0,
                "reason_codes": structural_errors,
            },
            signer=audit_signer,
            require_signature=require_signed_audit,
        )
        return "BLOCK", audit_record

    # 3. evaluate (deterministic, operates on frozen copy)
    vr: VerdictResult = evaluate(action_bundle, policy)

    # 4. record (pre-commit)
    audit_record = append_audit_record(
        audit_path,
        {
            "event_type": "GOVERNANCE_VERDICT",
            "actor_id": "lattice.execution_gate",
            "unit_hash": unit_hash,
            "action_hash": action_hash,
            "policy_id": policy.get("policy_id", "UNKNOWN"),
            "policy_version": policy.get("version", "UNKNOWN"),
            "verdict": vr.verdict,
            "confidence": vr.confidence,
            "reason_codes": list(vr.reason_codes),
        },
        signer=audit_signer,
        require_signature=require_signed_audit,
    )

    # 5. allow only if ALLOW
    if vr.verdict != "ALLOW":
        return "BLOCK", audit_record

    # 6. gate check (rehash — defense in depth; with frozen copies this
    #    should always pass, but we keep it as a tamper-evident seal)
    if sha256_hex(canonicalize(_governed_unit(action_bundle, decision_tree, tripwire_predicates))) != unit_hash:
        # TOCTOU / mutation detected
        append_audit_record(
            audit_path,
            {
                "event_type": "TOCTOU_DETECTED",
                "actor_id": "lattice.execution_gate",
                "unit_hash": unit_hash,
                "action_hash": action_hash,
                "policy_id": policy.get("policy_id", "UNKNOWN"),
                "policy_version": policy.get("version", "UNKNOWN"),
                "verdict": "BLOCK",
                "confidence": 0.0,
                "reason_codes": ["TOCTOU_DETECTED"],
            },
            signer=audit_signer,
            require_signature=require_signed_audit,
        )
        return "BLOCK", audit_record

    return "ALLOW", audit_record
