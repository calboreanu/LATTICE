"""KAN-798: Expanded cryptographic primitive tests for lattice.crypto.

Covers previously untested functions and edge cases:
- sha256_hex: deterministic output, empty input, known vectors
- b64e / b64d: round-trip, empty input, invalid base64
- load_public_key_pem: round-trip, corrupted PEM
- load_private_key_pem: corrupted PEM, non-existent path
- verify_ecdsa_p256: invalid signature returns False, wrong message
- generate_ecdsa_p256_keypair: key curve verification, uniqueness
- Cross-module interoperability: lattice key verified by trace_runtime
"""
from __future__ import annotations

import hashlib
import os

import pytest


def _has_trace_runtime() -> bool:
    try:
        import trace_runtime  # noqa: F401
        return True
    except ImportError:
        return False


from lattice.crypto import (
    b64d,
    b64e,
    generate_ecdsa_p256_keypair,
    load_private_key_pem,
    load_public_key_pem,
    save_private_key_pem,
    save_public_key_pem,
    sha256_hex,
    sign_ecdsa_p256,
    verify_ecdsa_p256,
)


def _clear_passphrase_env(monkeypatch):
    monkeypatch.delenv("AEGIS_PRIVATE_KEY_PASSPHRASE", raising=False)
    monkeypatch.delenv("AEGIS_LATTICE_PRIVATE_KEY_PASSPHRASE", raising=False)
    monkeypatch.delenv("AEGIS_CRYPTO_STRICT", raising=False)


# ---------------------------------------------------------------------------
# sha256_hex tests
# ---------------------------------------------------------------------------


class TestSha256Hex:
    """Direct unit tests for sha256_hex."""

    def test_empty_input(self):
        expected = hashlib.sha256(b"").hexdigest()
        assert sha256_hex(b"") == expected

    def test_known_vector(self):
        # SHA-256("abc") = ba7816bf...
        expected = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        assert sha256_hex(b"abc") == expected

    def test_deterministic(self):
        data = b"MANDATE integrity check"
        assert sha256_hex(data) == sha256_hex(data)

    def test_output_format(self):
        result = sha256_hex(b"test")
        assert len(result) == 64
        assert all(c in "0123456789abcdef" for c in result)

    def test_different_inputs_different_outputs(self):
        assert sha256_hex(b"a") != sha256_hex(b"b")


# ---------------------------------------------------------------------------
# b64e / b64d tests
# ---------------------------------------------------------------------------


class TestBase64:
    """Direct unit tests for b64e and b64d."""

    def test_round_trip(self):
        data = b"ECDSA signature payload"
        assert b64d(b64e(data)) == data

    def test_empty_input(self):
        assert b64e(b"") == ""
        assert b64d("") == b""

    def test_known_encoding(self):
        # base64("hello") = "aGVsbG8="
        assert b64e(b"hello") == "aGVsbG8="

    def test_known_decoding(self):
        assert b64d("aGVsbG8=") == b"hello"

    def test_binary_data_round_trip(self):
        data = bytes(range(256))
        assert b64d(b64e(data)) == data

    def test_invalid_base64_raises(self):
        with pytest.raises(Exception):
            b64d("!!!not-valid-base64!!!")


# ---------------------------------------------------------------------------
# Public key I/O tests
# ---------------------------------------------------------------------------


class TestPublicKeyIO:
    """Test load_public_key_pem and save_public_key_pem."""

    def test_save_load_round_trip(self, tmp_path, monkeypatch):
        _clear_passphrase_env(monkeypatch)
        _, public_key = generate_ecdsa_p256_keypair()
        pub_path = tmp_path / "test_pub.pem"
        save_public_key_pem(public_key, pub_path)

        loaded = load_public_key_pem(pub_path)
        # Verify the loaded key has the same encoding
        from cryptography.hazmat.primitives.serialization import (
            Encoding,
            PublicFormat,
        )

        original_bytes = public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
        loaded_bytes = loaded.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
        assert original_bytes == loaded_bytes

    def test_corrupted_public_pem_raises(self, tmp_path):
        pub_path = tmp_path / "corrupted.pem"
        pub_path.write_bytes(b"NOT A PEM FILE")
        with pytest.raises(Exception):
            load_public_key_pem(pub_path)

    def test_nonexistent_public_key_file_raises(self, tmp_path):
        pub_path = tmp_path / "nonexistent.pem"
        with pytest.raises(FileNotFoundError):
            load_public_key_pem(pub_path)

    def test_public_key_used_for_verification(self, tmp_path, monkeypatch):
        """Saved public key can verify signatures from corresponding private key."""
        _clear_passphrase_env(monkeypatch)
        private_key, public_key = generate_ecdsa_p256_keypair()
        pub_path = tmp_path / "verify_pub.pem"
        save_public_key_pem(public_key, pub_path)

        loaded_pub = load_public_key_pem(pub_path)
        msg = b"signed document payload"
        sig = sign_ecdsa_p256(private_key, msg)
        assert verify_ecdsa_p256(loaded_pub, msg, sig) is True


# ---------------------------------------------------------------------------
# Private key corruption tests
# ---------------------------------------------------------------------------


class TestPrivateKeyCorruption:
    """Test error handling for corrupted / invalid private key files."""

    def test_corrupted_private_pem_raises(self, tmp_path, monkeypatch):
        _clear_passphrase_env(monkeypatch)
        priv_path = tmp_path / "corrupted_priv.pem"
        priv_path.write_bytes(b"GARBAGE DATA NOT A PEM KEY")
        with pytest.raises(Exception):
            load_private_key_pem(priv_path)

    def test_nonexistent_private_key_file_raises(self, tmp_path, monkeypatch):
        _clear_passphrase_env(monkeypatch)
        priv_path = tmp_path / "nonexistent_priv.pem"
        with pytest.raises(FileNotFoundError):
            load_private_key_pem(priv_path)

    def test_truncated_pem_raises(self, tmp_path, monkeypatch):
        """A truncated PEM file should not be loadable."""
        _clear_passphrase_env(monkeypatch)
        private_key, _ = generate_ecdsa_p256_keypair()
        priv_path = tmp_path / "good.pem"
        save_private_key_pem(private_key, priv_path)

        # Truncate to half
        data = priv_path.read_bytes()
        truncated_path = tmp_path / "truncated.pem"
        truncated_path.write_bytes(data[: len(data) // 2])

        with pytest.raises(Exception):
            load_private_key_pem(truncated_path)


# ---------------------------------------------------------------------------
# Signature verification edge cases
# ---------------------------------------------------------------------------


class TestSignatureVerification:
    """Test verify_ecdsa_p256 edge cases."""

    def test_invalid_signature_returns_false(self):
        private_key, public_key = generate_ecdsa_p256_keypair()
        msg = b"authentic message"
        # Use garbage bytes as signature
        assert verify_ecdsa_p256(public_key, msg, b"\x00" * 64) is False

    def test_wrong_message_returns_false(self):
        private_key, public_key = generate_ecdsa_p256_keypair()
        sig = sign_ecdsa_p256(private_key, b"original message")
        assert verify_ecdsa_p256(public_key, b"tampered message", sig) is False

    def test_wrong_key_returns_false(self):
        priv_a, _ = generate_ecdsa_p256_keypair()
        _, pub_b = generate_ecdsa_p256_keypair()
        sig = sign_ecdsa_p256(priv_a, b"msg")
        assert verify_ecdsa_p256(pub_b, b"msg", sig) is False

    def test_empty_message_signature(self):
        """Signing and verifying an empty message should work."""
        private_key, public_key = generate_ecdsa_p256_keypair()
        sig = sign_ecdsa_p256(private_key, b"")
        assert verify_ecdsa_p256(public_key, b"", sig) is True

    def test_large_message_signature(self):
        """Signing a large message should work (SHA-256 handles any input length)."""
        private_key, public_key = generate_ecdsa_p256_keypair()
        large_msg = os.urandom(1024 * 1024)  # 1 MiB
        sig = sign_ecdsa_p256(private_key, large_msg)
        assert verify_ecdsa_p256(public_key, large_msg, sig) is True


# ---------------------------------------------------------------------------
# Key generation tests
# ---------------------------------------------------------------------------


class TestKeyGeneration:
    """Test generate_ecdsa_p256_keypair properties."""

    def test_key_curve_is_p256(self):
        from cryptography.hazmat.primitives.asymmetric.ec import SECP256R1

        private_key, public_key = generate_ecdsa_p256_keypair()
        assert isinstance(private_key.curve, SECP256R1)
        assert isinstance(public_key.curve, SECP256R1)

    def test_public_key_matches_private(self):
        from cryptography.hazmat.primitives.serialization import (
            Encoding,
            PublicFormat,
        )

        private_key, public_key = generate_ecdsa_p256_keypair()
        derived = private_key.public_key()
        assert public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo) == \
               derived.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)

    def test_successive_keys_are_different(self):
        from cryptography.hazmat.primitives.serialization import (
            Encoding,
            NoEncryption,
            PrivateFormat,
        )

        priv1, _ = generate_ecdsa_p256_keypair()
        priv2, _ = generate_ecdsa_p256_keypair()
        b1 = priv1.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
        b2 = priv2.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
        assert b1 != b2


# ---------------------------------------------------------------------------
# Cross-module interoperability
# ---------------------------------------------------------------------------


@pytest.mark.skipif(
    not _has_trace_runtime(),
    reason="trace_runtime not available in standalone LATTICE repo",
)
class TestCrossModuleInterop:
    """Verify keys generated by lattice module can be verified by trace_runtime."""

    def test_lattice_sign_trace_verify(self):
        from trace_runtime.crypto import verify_ecdsa_p256 as trace_verify

        private_key, public_key = generate_ecdsa_p256_keypair()
        msg = b"cross-module integrity check"
        sig = sign_ecdsa_p256(private_key, msg)
        assert trace_verify(public_key, msg, sig) is True

    def test_trace_sign_lattice_verify(self):
        from trace_runtime.crypto import (
            generate_ecdsa_p256_keypair as trace_keygen,
            sign_ecdsa_p256 as trace_sign,
        )

        priv, pub = trace_keygen()
        msg = b"trace-originated signature"
        sig = trace_sign(priv, msg)
        assert verify_ecdsa_p256(pub, msg, sig) is True
