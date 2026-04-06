"""KAN-798: Expanded bundle signing tests for lattice.bundle_signing.

Covers previously untested functions and edge cases:
- bundle_signing_body: direct tests for field stripping
- compute_signed_bundle_hash: determinism, canonical JSON dependency
- verify_signed_bundle: missing signature, missing sig_b64, wrong algorithm,
  missing bundle_hash, null signature, empty signature object
"""
from __future__ import annotations

from copy import deepcopy

from lattice.bundle_signing import (
    BundleSignatureValidation,
    bundle_signing_body,
    compute_signed_bundle_hash,
    sign_signed_bundle,
    verify_signed_bundle,
)
from lattice.crypto import (
    generate_ecdsa_p256_keypair,
    save_private_key_pem,
    save_public_key_pem,
)


def _unsigned_bundle() -> dict:
    return {
        "bundle_id": "B-798-001",
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
    }


def _signed_bundle(tmp_path, monkeypatch=None) -> tuple[dict, str, str]:
    """Helper: returns (signed_bundle, priv_path, pub_path)."""
    private_key, public_key = generate_ecdsa_p256_keypair()
    priv_path = tmp_path / "priv.pem"
    pub_path = tmp_path / "pub.pem"
    save_private_key_pem(private_key, priv_path)
    save_public_key_pem(public_key, pub_path)

    signed = sign_signed_bundle(
        _unsigned_bundle(),
        private_key_path=priv_path,
        pubkey_id="test_k1",
    )
    return signed, str(priv_path), str(pub_path)


# ---------------------------------------------------------------------------
# bundle_signing_body tests
# ---------------------------------------------------------------------------


class TestBundleSigningBody:
    """Direct tests for bundle_signing_body."""

    def test_removes_signature_field(self):
        bundle = _unsigned_bundle()
        bundle["signature"] = {"alg": "ECDSA_P256_SHA256", "sig_b64": "abc"}
        body = bundle_signing_body(bundle)
        assert "signature" not in body

    def test_removes_bundle_hash_field(self):
        bundle = _unsigned_bundle()
        bundle["bundle_hash"] = "deadbeef" * 8
        body = bundle_signing_body(bundle)
        assert "bundle_hash" not in body

    def test_preserves_other_fields(self):
        bundle = _unsigned_bundle()
        body = bundle_signing_body(bundle)
        assert body["bundle_id"] == "B-798-001"
        assert body["authorized_tools"] == ["echo"]
        assert "coa" in body

    def test_does_not_mutate_original(self):
        bundle = _unsigned_bundle()
        bundle["signature"] = {"alg": "test"}
        original_keys = set(bundle.keys())
        _ = bundle_signing_body(bundle)
        assert set(bundle.keys()) == original_keys
        assert "signature" in bundle

    def test_idempotent_when_no_signature_or_hash(self):
        bundle = _unsigned_bundle()
        body = bundle_signing_body(bundle)
        # Should be equivalent since no signature/hash to strip
        assert body == bundle


# ---------------------------------------------------------------------------
# compute_signed_bundle_hash tests
# ---------------------------------------------------------------------------


class TestComputeSignedBundleHash:
    """Direct tests for compute_signed_bundle_hash."""

    def test_deterministic_output(self):
        bundle = _unsigned_bundle()
        h1 = compute_signed_bundle_hash(bundle)
        h2 = compute_signed_bundle_hash(bundle)
        assert h1 == h2

    def test_output_is_64_hex_chars(self):
        bundle = _unsigned_bundle()
        h = compute_signed_bundle_hash(bundle)
        assert len(h) == 64
        assert all(c in "0123456789abcdef" for c in h)

    def test_different_bundles_different_hashes(self):
        b1 = _unsigned_bundle()
        b2 = _unsigned_bundle()
        b2["bundle_id"] = "B-798-002"
        assert compute_signed_bundle_hash(b1) != compute_signed_bundle_hash(b2)

    def test_ignores_signature_field_in_hash(self):
        bundle = _unsigned_bundle()
        h_without = compute_signed_bundle_hash(bundle)

        bundle["signature"] = {"alg": "test", "sig_b64": "fake"}
        h_with = compute_signed_bundle_hash(bundle)
        assert h_without == h_with

    def test_ignores_bundle_hash_field(self):
        bundle = _unsigned_bundle()
        h_without = compute_signed_bundle_hash(bundle)

        bundle["bundle_hash"] = "ff" * 32
        h_with = compute_signed_bundle_hash(bundle)
        assert h_without == h_with


# ---------------------------------------------------------------------------
# verify_signed_bundle edge cases
# ---------------------------------------------------------------------------


class TestVerifySignedBundleEdgeCases:
    """Edge cases for verify_signed_bundle error paths."""

    def test_missing_signature_object(self, tmp_path, monkeypatch):
        monkeypatch.delenv("AEGIS_PRIVATE_KEY_PASSPHRASE", raising=False)
        monkeypatch.delenv("AEGIS_LATTICE_PRIVATE_KEY_PASSPHRASE", raising=False)
        monkeypatch.delenv("AEGIS_CRYPTO_STRICT", raising=False)

        _, public_key = generate_ecdsa_p256_keypair()
        pub_path = tmp_path / "pub.pem"
        save_public_key_pem(public_key, pub_path)

        bundle = _unsigned_bundle()
        # No signature field at all
        result = verify_signed_bundle(bundle, public_key_path=pub_path)
        assert result.ok is False
        assert "missing signature object" in result.reason

    def test_null_signature_object(self, tmp_path, monkeypatch):
        monkeypatch.delenv("AEGIS_PRIVATE_KEY_PASSPHRASE", raising=False)
        monkeypatch.delenv("AEGIS_LATTICE_PRIVATE_KEY_PASSPHRASE", raising=False)
        monkeypatch.delenv("AEGIS_CRYPTO_STRICT", raising=False)

        _, public_key = generate_ecdsa_p256_keypair()
        pub_path = tmp_path / "pub.pem"
        save_public_key_pem(public_key, pub_path)

        bundle = _unsigned_bundle()
        bundle["signature"] = None
        result = verify_signed_bundle(bundle, public_key_path=pub_path)
        assert result.ok is False
        assert "missing signature object" in result.reason

    def test_string_signature_object(self, tmp_path, monkeypatch):
        monkeypatch.delenv("AEGIS_PRIVATE_KEY_PASSPHRASE", raising=False)
        monkeypatch.delenv("AEGIS_LATTICE_PRIVATE_KEY_PASSPHRASE", raising=False)
        monkeypatch.delenv("AEGIS_CRYPTO_STRICT", raising=False)

        _, public_key = generate_ecdsa_p256_keypair()
        pub_path = tmp_path / "pub.pem"
        save_public_key_pem(public_key, pub_path)

        bundle = _unsigned_bundle()
        bundle["signature"] = "not-a-dict"
        result = verify_signed_bundle(bundle, public_key_path=pub_path)
        assert result.ok is False
        assert "missing signature object" in result.reason

    def test_wrong_algorithm(self, tmp_path, monkeypatch):
        monkeypatch.delenv("AEGIS_PRIVATE_KEY_PASSPHRASE", raising=False)
        monkeypatch.delenv("AEGIS_LATTICE_PRIVATE_KEY_PASSPHRASE", raising=False)
        monkeypatch.delenv("AEGIS_CRYPTO_STRICT", raising=False)

        private_key, public_key = generate_ecdsa_p256_keypair()
        priv_path = tmp_path / "priv.pem"
        pub_path = tmp_path / "pub.pem"
        save_private_key_pem(private_key, priv_path)
        save_public_key_pem(public_key, pub_path)

        signed = sign_signed_bundle(
            _unsigned_bundle(), private_key_path=priv_path, pubkey_id="k1"
        )
        # Tamper with algorithm
        signed["signature"]["alg"] = "RSA_SHA512"
        result = verify_signed_bundle(signed, public_key_path=pub_path)
        assert result.ok is False
        assert "unsupported signature algorithm" in result.reason

    def test_missing_sig_b64(self, tmp_path, monkeypatch):
        monkeypatch.delenv("AEGIS_PRIVATE_KEY_PASSPHRASE", raising=False)
        monkeypatch.delenv("AEGIS_LATTICE_PRIVATE_KEY_PASSPHRASE", raising=False)
        monkeypatch.delenv("AEGIS_CRYPTO_STRICT", raising=False)

        private_key, public_key = generate_ecdsa_p256_keypair()
        priv_path = tmp_path / "priv.pem"
        pub_path = tmp_path / "pub.pem"
        save_private_key_pem(private_key, priv_path)
        save_public_key_pem(public_key, pub_path)

        signed = sign_signed_bundle(
            _unsigned_bundle(), private_key_path=priv_path, pubkey_id="k1"
        )
        del signed["signature"]["sig_b64"]
        result = verify_signed_bundle(signed, public_key_path=pub_path)
        assert result.ok is False
        assert "missing signature.sig_b64" in result.reason

    def test_empty_sig_b64(self, tmp_path, monkeypatch):
        monkeypatch.delenv("AEGIS_PRIVATE_KEY_PASSPHRASE", raising=False)
        monkeypatch.delenv("AEGIS_LATTICE_PRIVATE_KEY_PASSPHRASE", raising=False)
        monkeypatch.delenv("AEGIS_CRYPTO_STRICT", raising=False)

        private_key, public_key = generate_ecdsa_p256_keypair()
        priv_path = tmp_path / "priv.pem"
        pub_path = tmp_path / "pub.pem"
        save_private_key_pem(private_key, priv_path)
        save_public_key_pem(public_key, pub_path)

        signed = sign_signed_bundle(
            _unsigned_bundle(), private_key_path=priv_path, pubkey_id="k1"
        )
        signed["signature"]["sig_b64"] = ""
        result = verify_signed_bundle(signed, public_key_path=pub_path)
        assert result.ok is False
        assert "missing signature.sig_b64" in result.reason

    def test_tampered_bundle_hash(self, tmp_path, monkeypatch):
        monkeypatch.delenv("AEGIS_PRIVATE_KEY_PASSPHRASE", raising=False)
        monkeypatch.delenv("AEGIS_LATTICE_PRIVATE_KEY_PASSPHRASE", raising=False)
        monkeypatch.delenv("AEGIS_CRYPTO_STRICT", raising=False)

        private_key, public_key = generate_ecdsa_p256_keypair()
        priv_path = tmp_path / "priv.pem"
        pub_path = tmp_path / "pub.pem"
        save_private_key_pem(private_key, priv_path)
        save_public_key_pem(public_key, pub_path)

        signed = sign_signed_bundle(
            _unsigned_bundle(), private_key_path=priv_path, pubkey_id="k1"
        )
        signed["bundle_hash"] = "ff" * 32
        result = verify_signed_bundle(signed, public_key_path=pub_path)
        assert result.ok is False
        assert "bundle_hash mismatch" in result.reason


# ---------------------------------------------------------------------------
# BundleSignatureValidation dataclass
# ---------------------------------------------------------------------------


class TestBundleSignatureValidation:
    """Test the BundleSignatureValidation frozen dataclass."""

    def test_ok_true_default_reason(self):
        v = BundleSignatureValidation(ok=True)
        assert v.ok is True
        assert v.reason == ""

    def test_ok_false_with_reason(self):
        v = BundleSignatureValidation(ok=False, reason="test failure")
        assert v.ok is False
        assert v.reason == "test failure"

    def test_frozen(self):
        v = BundleSignatureValidation(ok=True)
        with __import__("pytest").raises(AttributeError):
            v.ok = False  # type: ignore[misc]
