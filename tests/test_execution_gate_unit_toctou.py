"""Tests for execution-gate TOCTOU enforcement over bundle+tree+tripwires."""
from __future__ import annotations

import json

import lattice.execution_gate as gate
from lattice.audit_log import AuditSigner, load_audit_chain, verify_audit_chain
from lattice.crypto import generate_ecdsa_p256_keypair, save_private_key_pem, save_public_key_pem
from lattice.policy_engine import VerdictResult


def _action_bundle() -> dict:
    return {
        "target": "acme.example.com",
        "tool": "echo",
        "tool_class": "DEFAULT",
        "scope_tags": [],
        "time_bound": "2099-01-01T00:00:00Z",
    }


def _policy_bundle() -> dict:
    return {
        "policy_id": "POL-304-001",
        "version": "1.0",
        "allowed_targets": ["acme.example.com"],
        "permitted_tools": {"DEFAULT": ["echo"]},
        "rules": [],
        "thresholds": {"autonomous": 85, "hitl": 65, "escalate": 45},
    }


def _decision_tree() -> dict:
    return {
        "start": "exec",
        "nodes": [
            {
                "id": "exec",
                "kind": "EXECUTE_STEP",
                "default": "exec",
                "edges": [{"when": {"signal": "DONE"}, "to": "end"}],
            },
            {"id": "end", "kind": "END", "default": "end"},
        ],
    }


def _tripwires() -> list[dict]:
    return [
        {
            "predicate_id": "TW-304-01",
            "metric": "RATE",
            "operator": "GT",
            "threshold": 3.0,
            "on_trigger": "ESCALATE",
            "window": {"kind": "EVENT_COUNT", "size": 10},
        }
    ]


def test_enforce_allows_valid_governed_unit(tmp_path) -> None:
    audit_path = tmp_path / "audit.jsonl"
    decision, audit = gate.enforce(
        _action_bundle(),
        _policy_bundle(),
        str(audit_path),
        decision_tree=_decision_tree(),
        tripwire_predicates=_tripwires(),
        require_signed_audit=False,
    )

    assert decision == "ALLOW"
    assert audit["verdict"] == "ALLOW"
    assert "unit_hash" in audit
    assert "action_hash" in audit


def test_enforce_blocks_invalid_decision_tree(tmp_path) -> None:
    audit_path = tmp_path / "audit.jsonl"
    bad_tree = _decision_tree()
    bad_tree["start"] = "missing-node"

    decision, audit = gate.enforce(
        _action_bundle(),
        _policy_bundle(),
        str(audit_path),
        decision_tree=bad_tree,
        tripwire_predicates=_tripwires(),
        require_signed_audit=False,
    )

    assert decision == "BLOCK"
    assert audit["verdict"] == "BLOCK"
    assert any(code.startswith("DECISION_TREE_INVALID:") for code in audit["reason_codes"])


def test_enforce_blocks_duplicate_tripwire_predicate_ids(tmp_path) -> None:
    audit_path = tmp_path / "audit.jsonl"
    dup = _tripwires()[0]
    decision, audit = gate.enforce(
        _action_bundle(),
        _policy_bundle(),
        str(audit_path),
        decision_tree=_decision_tree(),
        tripwire_predicates=[dup, dict(dup)],
        require_signed_audit=False,
    )

    assert decision == "BLOCK"
    assert audit["verdict"] == "BLOCK"
    assert "TRIPWIRE_PREDICATES_INVALID:duplicate_id:TW-304-01" in audit["reason_codes"]


def test_enforce_immune_to_external_mutation_during_evaluate(tmp_path, monkeypatch) -> None:
    """KAN-792: External mutation of caller's tree during evaluate() no longer
    affects the gate's decision because enforce() deep-copies all inputs.

    Previously this test expected BLOCK+TOCTOU_DETECTED.  With the deep-copy
    fix, the gate operates on a frozen snapshot and correctly returns ALLOW.
    """
    audit_path = tmp_path / "audit.jsonl"
    tree = _decision_tree()

    def _mutating_evaluate(action_bundle, policy):
        # Mutate the *caller's* tree reference — should NOT affect the gate's copy
        tree["nodes"][0]["default"] = "end"
        return VerdictResult("ALLOW", 100.0, ["POLICY_ALLOW"])

    monkeypatch.setattr(gate, "evaluate", _mutating_evaluate)

    decision, audit = gate.enforce(
        _action_bundle(),
        _policy_bundle(),
        str(audit_path),
        decision_tree=tree,
        tripwire_predicates=_tripwires(),
        require_signed_audit=False,
    )

    # Gate should ALLOW because its internal frozen copy was never mutated
    assert decision == "ALLOW"
    assert audit["verdict"] == "ALLOW"

    # Verify the caller's tree WAS mutated (proving isolation, not ignorance)
    assert tree["nodes"][0]["default"] == "end"


def test_enforce_deep_copy_isolates_action_bundle(tmp_path, monkeypatch) -> None:
    """KAN-792: Verify that mutating the caller's action_bundle after enforce()
    begins does not affect the governance decision or audit hash."""
    audit_path = tmp_path / "audit.jsonl"
    bundle = _action_bundle()
    original_target = bundle["target"]

    def _mutating_evaluate(action_bundle, policy):
        # Mutate the caller's bundle (outer scope)
        bundle["target"] = "evil.example.com"
        bundle["tool"] = "rm_rf"
        return VerdictResult("ALLOW", 100.0, ["POLICY_ALLOW"])

    monkeypatch.setattr(gate, "evaluate", _mutating_evaluate)

    decision, audit = gate.enforce(
        bundle,
        _policy_bundle(),
        str(audit_path),
        decision_tree=_decision_tree(),
        tripwire_predicates=_tripwires(),
        require_signed_audit=False,
    )

    # Gate allowed based on the original (frozen) bundle, not the mutated one
    assert decision == "ALLOW"
    # Caller's bundle was mutated, proving the gate used a separate copy
    assert bundle["target"] == "evil.example.com"
    assert bundle["tool"] == "rm_rf"


def test_enforce_deep_copy_isolates_policy(tmp_path, monkeypatch) -> None:
    """KAN-792: Policy mutations during evaluate() don't affect the gate."""
    audit_path = tmp_path / "audit.jsonl"
    policy = _policy_bundle()

    def _mutating_evaluate(action_bundle, pol):
        # Mutate the caller's policy
        policy["allowed_targets"] = ["*.evil.com"]
        return VerdictResult("ALLOW", 100.0, ["POLICY_ALLOW"])

    monkeypatch.setattr(gate, "evaluate", _mutating_evaluate)

    decision, audit = gate.enforce(
        _action_bundle(),
        policy,
        str(audit_path),
        decision_tree=_decision_tree(),
        tripwire_predicates=_tripwires(),
        require_signed_audit=False,
    )

    assert decision == "ALLOW"
    # Original policy was mutated by the adversary, but gate was unaffected
    assert policy["allowed_targets"] == ["*.evil.com"]
    assert audit["policy_id"] == "POL-304-001"


def test_enforce_can_emit_signed_audit_chain(tmp_path) -> None:
    private_key, public_key = generate_ecdsa_p256_keypair()
    private_path = tmp_path / "audit_private.pem"
    public_path = tmp_path / "audit_public.pem"
    save_private_key_pem(private_key, private_path)
    save_public_key_pem(public_key, public_path)

    signer = AuditSigner(key_id="audit_k1", private_key_path=private_path)
    audit_path = tmp_path / "audit.jsonl"
    decision, _ = gate.enforce(
        _action_bundle(),
        _policy_bundle(),
        str(audit_path),
        decision_tree=_decision_tree(),
        tripwire_predicates=_tripwires(),
        audit_signer=signer,
    )

    chain = load_audit_chain(audit_path)
    ok, errors = verify_audit_chain(chain, public_keys_by_id={"audit_k1": public_path})
    assert decision == "ALLOW"
    assert ok is True
    assert errors == []


def test_enforce_raises_when_signed_audit_required_but_signer_missing(tmp_path) -> None:
    """KAN-2134: When require_signed_audit=True and no audit_signer is provided,
    enforce() must raise ValueError instead of falling back to unsigned stub."""
    import pytest
    audit_path = tmp_path / "audit.jsonl"
    with pytest.raises(ValueError, match="audit signer is required when require_signed_audit=True"):
        gate.enforce(
            _action_bundle(),
            _policy_bundle(),
            str(audit_path),
            decision_tree=_decision_tree(),
            tripwire_predicates=_tripwires(),
        )
