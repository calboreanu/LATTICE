"""KAN-790: Tests for hardened cryptographic key passphrase handling.

Covers:
- Unified env var resolution (AEGIS_PRIVATE_KEY_PASSPHRASE primary)
- Legacy env var fallback (AEGIS_LATTICE_PRIVATE_KEY_PASSPHRASE)
- Strict mode enforcement (AEGIS_CRYPTO_STRICT)
- Minimum passphrase length validation
- Deprecation warnings for legacy env vars
- Round-trip key save/load with and without passphrase
"""
from __future__ import annotations

import os
import warnings

import pytest

from lattice.crypto import (
    CryptoConfigError,
    _resolve_passphrase,
    generate_ecdsa_p256_keypair,
    load_private_key_pem,
    save_private_key_pem,
    save_public_key_pem,
)


# ---------------------------------------------------------------------------
# Helper to clear all passphrase env vars
# ---------------------------------------------------------------------------
def _clear_passphrase_env(monkeypatch):
    monkeypatch.delenv("AEGIS_PRIVATE_KEY_PASSPHRASE", raising=False)
    monkeypatch.delenv("AEGIS_LATTICE_PRIVATE_KEY_PASSPHRASE", raising=False)
    monkeypatch.delenv("AEGIS_CRYPTO_STRICT", raising=False)


# ---------------------------------------------------------------------------
# _resolve_passphrase tests
# ---------------------------------------------------------------------------


class TestResolvePassphraseLattice:
    """Tests for _resolve_passphrase in lattice context."""

    def test_returns_none_when_no_env_vars_set(self, monkeypatch):
        _clear_passphrase_env(monkeypatch)
        result = _resolve_passphrase(context="lattice")
        assert result is None

    def test_returns_bytes_from_primary_env_var(self, monkeypatch):
        _clear_passphrase_env(monkeypatch)
        monkeypatch.setenv("AEGIS_PRIVATE_KEY_PASSPHRASE", "my-secure-passphrase-123")
        result = _resolve_passphrase(context="lattice")
        assert result == b"my-secure-passphrase-123"

    def test_returns_bytes_from_legacy_env_var(self, monkeypatch):
        _clear_passphrase_env(monkeypatch)
        monkeypatch.setenv("AEGIS_LATTICE_PRIVATE_KEY_PASSPHRASE", "legacy-pass-1234567890")
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            result = _resolve_passphrase(context="lattice")
        assert result == b"legacy-pass-1234567890"
        # Should emit deprecation warning
        assert any(issubclass(x.category, DeprecationWarning) for x in w)
        assert any("AEGIS_LATTICE_PRIVATE_KEY_PASSPHRASE" in str(x.message) for x in w)

    def test_primary_takes_precedence_over_legacy(self, monkeypatch):
        _clear_passphrase_env(monkeypatch)
        monkeypatch.setenv("AEGIS_PRIVATE_KEY_PASSPHRASE", "primary-passphrase-1234")
        monkeypatch.setenv("AEGIS_LATTICE_PRIVATE_KEY_PASSPHRASE", "legacy-should-not-use!")
        result = _resolve_passphrase(context="lattice")
        assert result == b"primary-passphrase-1234"


class TestStrictModeLattice:
    """Tests for strict mode enforcement."""

    def test_strict_mode_requires_passphrase(self, monkeypatch):
        _clear_passphrase_env(monkeypatch)
        monkeypatch.setenv("AEGIS_CRYPTO_STRICT", "1")
        with pytest.raises(CryptoConfigError, match="not set"):
            _resolve_passphrase(context="lattice")

    def test_strict_mode_accepts_true(self, monkeypatch):
        _clear_passphrase_env(monkeypatch)
        monkeypatch.setenv("AEGIS_CRYPTO_STRICT", "true")
        with pytest.raises(CryptoConfigError, match="not set"):
            _resolve_passphrase(context="lattice")

    def test_strict_mode_accepts_yes(self, monkeypatch):
        _clear_passphrase_env(monkeypatch)
        monkeypatch.setenv("AEGIS_CRYPTO_STRICT", "yes")
        with pytest.raises(CryptoConfigError, match="not set"):
            _resolve_passphrase(context="lattice")

    def test_strict_mode_enforces_min_length(self, monkeypatch):
        _clear_passphrase_env(monkeypatch)
        monkeypatch.setenv("AEGIS_CRYPTO_STRICT", "1")
        monkeypatch.setenv("AEGIS_PRIVATE_KEY_PASSPHRASE", "short")
        with pytest.raises(CryptoConfigError, match="too short"):
            _resolve_passphrase(context="lattice")

    def test_strict_mode_accepts_valid_passphrase(self, monkeypatch):
        _clear_passphrase_env(monkeypatch)
        monkeypatch.setenv("AEGIS_CRYPTO_STRICT", "1")
        monkeypatch.setenv("AEGIS_PRIVATE_KEY_PASSPHRASE", "a" * 20)
        result = _resolve_passphrase(context="lattice")
        assert result == b"a" * 20

    def test_strict_mode_boundary_19_chars_rejected(self, monkeypatch):
        _clear_passphrase_env(monkeypatch)
        monkeypatch.setenv("AEGIS_CRYPTO_STRICT", "1")
        monkeypatch.setenv("AEGIS_PRIVATE_KEY_PASSPHRASE", "a" * 19)
        with pytest.raises(CryptoConfigError, match="too short"):
            _resolve_passphrase(context="lattice")

    def test_strict_mode_boundary_20_chars_accepted(self, monkeypatch):
        _clear_passphrase_env(monkeypatch)
        monkeypatch.setenv("AEGIS_CRYPTO_STRICT", "1")
        monkeypatch.setenv("AEGIS_PRIVATE_KEY_PASSPHRASE", "a" * 20)
        result = _resolve_passphrase(context="lattice")
        assert result is not None

    def test_non_strict_mode_allows_short_passphrase(self, monkeypatch):
        _clear_passphrase_env(monkeypatch)
        monkeypatch.setenv("AEGIS_PRIVATE_KEY_PASSPHRASE", "short")
        result = _resolve_passphrase(context="lattice")
        assert result == b"short"


# ---------------------------------------------------------------------------
# Key round-trip tests
# ---------------------------------------------------------------------------


class TestKeyRoundTrip:
    """Test key save/load with passphrase handling."""

    def test_save_load_without_passphrase(self, tmp_path, monkeypatch):
        _clear_passphrase_env(monkeypatch)
        private_key, public_key = generate_ecdsa_p256_keypair()
        priv_path = tmp_path / "test_priv.pem"
        pub_path = tmp_path / "test_pub.pem"

        save_private_key_pem(private_key, priv_path)
        save_public_key_pem(public_key, pub_path)

        loaded = load_private_key_pem(priv_path)
        # Verify loaded key can sign and original public key can verify
        from lattice.crypto import sign_ecdsa_p256, verify_ecdsa_p256
        msg = b"test message"
        sig = sign_ecdsa_p256(loaded, msg)
        assert verify_ecdsa_p256(public_key, msg, sig)

    def test_save_load_with_passphrase(self, tmp_path, monkeypatch):
        _clear_passphrase_env(monkeypatch)
        monkeypatch.setenv("AEGIS_PRIVATE_KEY_PASSPHRASE", "test-passphrase-for-pem")

        private_key, public_key = generate_ecdsa_p256_keypair()
        priv_path = tmp_path / "test_priv_enc.pem"
        pub_path = tmp_path / "test_pub.pem"

        save_private_key_pem(private_key, priv_path)
        save_public_key_pem(public_key, pub_path)

        loaded = load_private_key_pem(priv_path)
        from lattice.crypto import sign_ecdsa_p256, verify_ecdsa_p256
        msg = b"encrypted key test"
        sig = sign_ecdsa_p256(loaded, msg)
        assert verify_ecdsa_p256(public_key, msg, sig)

    def test_encrypted_pem_fails_without_passphrase(self, tmp_path, monkeypatch):
        _clear_passphrase_env(monkeypatch)
        monkeypatch.setenv("AEGIS_PRIVATE_KEY_PASSPHRASE", "test-passphrase-for-pem")
        private_key, _ = generate_ecdsa_p256_keypair()
        priv_path = tmp_path / "test_enc.pem"
        save_private_key_pem(private_key, priv_path)

        # Now clear the passphrase and attempt to load — should fail
        monkeypatch.delenv("AEGIS_PRIVATE_KEY_PASSPHRASE")
        with pytest.raises(Exception):
            load_private_key_pem(priv_path)

    def test_private_key_file_permissions(self, tmp_path, monkeypatch):
        _clear_passphrase_env(monkeypatch)
        private_key, _ = generate_ecdsa_p256_keypair()
        priv_path = tmp_path / "test_perms.pem"
        save_private_key_pem(private_key, priv_path)

        mode = priv_path.stat().st_mode & 0o777
        assert mode == 0o600, f"Expected 0o600, got 0o{mode:o}"
