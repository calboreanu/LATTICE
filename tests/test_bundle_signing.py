"""Tests for LATTICE signed bundle hashing and signature verification."""
from __future__ import annotations

from lattice.bundle_signing import BundleSignatureValidation, sign_signed_bundle, verify_signed_bundle
from lattice.crypto import generate_ecdsa_p256_keypair, save_private_key_pem, save_public_key_pem


def _unsigned_bundle() -> dict:
    return {
        "bundle_id": "B-293-001",
        "bundle_version": "1.0.0",
        "safe_state_id": "HALT",
        "authorized_tools": ["echo"],
        "tool_hashes": {"echo": "a" * 64},
        "constraints": {},
        "coa": {
            "default_coa_id": "COA-A",
            "coas": [{"coa_id": "COA-A", "steps": [{"tool_id": "echo", "params": {"msg": "hi"}}]}],
        },
        "decision_tree": {
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
        },
        "signature": {"alg": "ECDSA_P256_SHA256", "pubkey_id": "gov_k1", "sig_b64": ""},
    }


def test_sign_and_verify_signed_bundle_round_trip(tmp_path) -> None:
    private_key, public_key = generate_ecdsa_p256_keypair()
    private_key_path = tmp_path / "gov_private.pem"
    public_key_path = tmp_path / "gov_public.pem"
    save_private_key_pem(private_key, private_key_path)
    save_public_key_pem(public_key, public_key_path)

    signed = sign_signed_bundle(_unsigned_bundle(), private_key_path=private_key_path, pubkey_id="gov_k1")
    result: BundleSignatureValidation = verify_signed_bundle(signed, public_key_path=public_key_path)

    assert result.ok is True
    assert result.reason == ""
    assert signed["bundle_hash"]
    assert signed["signature"]["sig_b64"]


def test_verify_signed_bundle_rejects_tampered_body(tmp_path) -> None:
    private_key, public_key = generate_ecdsa_p256_keypair()
    private_key_path = tmp_path / "gov_private.pem"
    public_key_path = tmp_path / "gov_public.pem"
    save_private_key_pem(private_key, private_key_path)
    save_public_key_pem(public_key, public_key_path)

    signed = sign_signed_bundle(_unsigned_bundle(), private_key_path=private_key_path, pubkey_id="gov_k1")
    signed["constraints"]["allowed_targets"] = ["example.local"]

    result = verify_signed_bundle(signed, public_key_path=public_key_path)
    assert result.ok is False
    assert result.reason == "bundle_hash mismatch"


def test_verify_signed_bundle_rejects_wrong_public_key(tmp_path) -> None:
    private_a, _ = generate_ecdsa_p256_keypair()
    private_b, public_b = generate_ecdsa_p256_keypair()
    private_key_path = tmp_path / "gov_private.pem"
    wrong_public_path = tmp_path / "wrong_public.pem"
    save_private_key_pem(private_a, private_key_path)
    save_public_key_pem(public_b, wrong_public_path)
    # Save unrelated private key to avoid lint complaints about unused generation path.
    save_private_key_pem(private_b, tmp_path / "other_private.pem")

    signed = sign_signed_bundle(_unsigned_bundle(), private_key_path=private_key_path, pubkey_id="gov_k1")
    result = verify_signed_bundle(signed, public_key_path=wrong_public_path)

    assert result.ok is False
    assert result.reason == "invalid signature over bundle_hash"
