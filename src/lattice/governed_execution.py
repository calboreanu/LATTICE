"""Sole sanctioned path from objective to tool execution (R3).

Structural non-bypassability *within the trusted core*: tool execution
(``sandbox_stub.sandbox_execute``) is invoked **only** from
``governed_execute`` below, and only after the governance gate
(``execution_gate.enforce``) returns ``ALLOW``. Any alternative path to tools
would have to import and call ``sandbox_execute`` directly; the reachability
invariant test (``tests/test_gate_reachability_invariant.py``) asserts no such
call site exists anywhere else in the ``lattice`` core, turning
"non-bypassable by construction" into a checked invariant rather than a claim.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from .execution_gate import enforce
from .audit_log import AuditSigner
from .sandbox_stub import sandbox_execute


def governed_execute(
    action_bundle: Dict[str, Any],
    policy: Dict[str, Any],
    audit_path: str,
    *,
    decision_tree: Optional[Dict[str, Any]] = None,
    tripwire_predicates: Optional[List[Dict[str, Any]]] = None,
    audit_signer: Optional[AuditSigner] = None,
    require_signed_audit: bool = True,
) -> Dict[str, Any]:
    """Run the governance gate, then execute the tool **iff** the verdict is ALLOW.

    Returns a record with ``executed`` (bool), the ``verdict``, the sandboxed
    ``result`` (or ``None`` if blocked/escalated), and the gate ``audit_record``.
    """
    verdict, audit_record = enforce(
        action_bundle,
        policy,
        audit_path,
        decision_tree=decision_tree,
        tripwire_predicates=tripwire_predicates,
        audit_signer=audit_signer,
        require_signed_audit=require_signed_audit,
    )
    if verdict != "ALLOW":
        return {"executed": False, "verdict": verdict, "result": None, "audit_record": audit_record}

    # The ONLY call to sandbox_execute in the trusted core — past the gate, on ALLOW.
    result = sandbox_execute(action_bundle)
    return {"executed": True, "verdict": verdict, "result": result, "audit_record": audit_record}
