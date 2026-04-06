"""
LATTICE — Authorization layer for the MANDATE→LATTICE→TRACE governance stack.

Provides deterministic policy evaluation, TOCTOU-resistant enforcement,
and append-only audit logging for action bundles.

Usage:
    from lattice.execution_gate import enforce
    from lattice.policy_engine import evaluate, VerdictResult
    from lattice.audit_log import append_audit_record
    from lattice.bundle_signing import sign_signed_bundle, verify_signed_bundle
    from lattice.sandbox_stub import sandbox_execute
"""

__all__ = [
    "execution_gate",
    "policy_engine",
    "audit_log",
    "bundle_signing",
    "crypto",
    "sandbox_stub",
    "models",
    "decision_tree_engine",
    "tripwire_framework",
    "tripwire_trace_contract",
    "multi_cell",
    "planning_agent",
    "training_data",
]
