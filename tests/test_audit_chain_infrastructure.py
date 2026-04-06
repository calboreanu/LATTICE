"""Tests for D5 audit chain creation, sealing, and verification."""
from __future__ import annotations

import copy

import pytest

from lattice.audit_log import AuditSigner, append_audit_record, load_audit_chain, seal_audit_chain, verify_audit_chain
from lattice.crypto import generate_ecdsa_p256_keypair, save_private_key_pem, save_public_key_pem


def _keypair_paths(tmp_path):
    tmp_path.mkdir(parents=True, exist_ok=True)
    private_key, public_key = generate_ecdsa_p256_keypair()
    private_path = tmp_path / "audit_private.pem"
    public_path = tmp_path / "audit_public.pem"
    save_private_key_pem(private_key, private_path)
    save_public_key_pem(public_key, public_path)
    return private_path, public_path


def _base_record() -> dict:
    return {
        "event_type": "GOVERNANCE_VERDICT",
        "actor_id": "lattice.execution_gate",
        "unit_hash": "a" * 64,
        "action_hash": "b" * 64,
        "policy_id": "POL-293",
        "policy_version": "1.0.0",
        "verdict": "ALLOW",
        "confidence": 99.0,
        "reason_codes": ["POLICY_ALLOW"],
    }


def test_audit_chain_signed_round_trip_and_verify(tmp_path) -> None:
    private_path, public_path = _keypair_paths(tmp_path)
    signer = AuditSigner(key_id="audit_k1", private_key_path=private_path)
    audit_path = tmp_path / "audit.jsonl"

    append_audit_record(str(audit_path), _base_record(), signer=signer)
    append_audit_record(
        str(audit_path),
        {
            **_base_record(),
            "event_type": "TOCTOU_CHECK",
            "verdict": "BLOCK",
            "reason_codes": ["TOCTOU_DETECTED"],
        },
        signer=signer,
    )
    seal_audit_chain(str(audit_path), reason="OPERATION_COMPLETE", signer=signer)

    chain = load_audit_chain(audit_path)
    ok, errors = verify_audit_chain(chain, public_keys_by_id={"audit_k1": public_path})
    assert ok is True
    assert errors == []
    assert chain[-1]["event_type"] == "CHAIN_SEALED"
    assert chain[-1]["payload"]["seal"]["total_record_count"] == len(chain)


def test_verify_audit_chain_detects_tamper(tmp_path) -> None:
    private_path, public_path = _keypair_paths(tmp_path)
    signer = AuditSigner(key_id="audit_k1", private_key_path=private_path)
    audit_path = tmp_path / "audit.jsonl"

    append_audit_record(str(audit_path), _base_record(), signer=signer)
    append_audit_record(str(audit_path), {**_base_record(), "sequence_hint": 2}, signer=signer)
    chain = load_audit_chain(audit_path)

    tampered = copy.deepcopy(chain)
    tampered[1]["confidence"] = 12.34
    ok, errors = verify_audit_chain(tampered, public_keys_by_id={"audit_k1": public_path})
    assert ok is False
    assert "hash mismatch" in errors[0]


def test_verify_audit_chain_rejects_wrong_signature_key(tmp_path) -> None:
    private_path, _ = _keypair_paths(tmp_path)
    _, wrong_public_path = _keypair_paths(tmp_path / "wrong")
    signer = AuditSigner(key_id="audit_k1", private_key_path=private_path)
    audit_path = tmp_path / "audit.jsonl"

    append_audit_record(str(audit_path), _base_record(), signer=signer)
    chain = load_audit_chain(audit_path)

    ok, errors = verify_audit_chain(chain, public_keys_by_id={"audit_k1": wrong_public_path})
    assert ok is False
    assert "signature invalid" in errors[0]


def test_chain_becomes_immutable_after_seal(tmp_path) -> None:
    private_path, _ = _keypair_paths(tmp_path)
    signer = AuditSigner(key_id="audit_k1", private_key_path=private_path)
    audit_path = tmp_path / "audit.jsonl"

    append_audit_record(str(audit_path), _base_record(), signer=signer)
    seal_audit_chain(str(audit_path), reason="KILL_SWITCH", signer=signer)

    with pytest.raises(ValueError, match="immutable"):
        append_audit_record(str(audit_path), _base_record(), signer=signer)


def test_require_signature_rejects_unsigned_records(tmp_path) -> None:
    audit_path = tmp_path / "audit.jsonl"
    with pytest.raises(ValueError, match="signer is required"):
        append_audit_record(
            str(audit_path),
            _base_record(),
            require_signature=True,
        )
