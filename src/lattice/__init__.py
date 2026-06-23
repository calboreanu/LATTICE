"""
LATTICE — Authorization layer for the MANDATE→LATTICE→TRACE governance stack.

Provides deterministic policy evaluation, TOCTOU-resistant enforcement,
and append-only audit logging for action bundles.

Usage:
    from lattice.execution_gate import enforce
    from lattice.governed_execution import governed_execute   # sole gated execution path
    from lattice.policy_engine import evaluate, VerdictResult # 7 native rule types + confidence cap
    from lattice.audit_log import append_audit_record
    from lattice.bundle_signing import sign_signed_bundle, verify_signed_bundle
    from lattice.sandbox_stub import sandbox_execute
    from lattice.coordination_security import SecureCoordinationBus
    from lattice.authorization import issue_authorization, authorization_valid
    from lattice.policy_linter import lint_policy
    from lattice.key_management import KeyRing
"""

__all__ = [
    "execution_gate",
    "governed_execution",
    "policy_engine",
    "audit_log",
    "bundle_signing",
    "crypto",
    "key_management",
    "authorization",
    "policy_linter",
    "sandbox_stub",
    "models",
    "decision_tree_engine",
    "tripwire_framework",
    "tripwire_trace_contract",
    "multi_cell",
    "coordination_security",
]
