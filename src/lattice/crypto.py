"""
LATTICE cryptographic utilities.

Provides ECDSA-P256 key management, signing, and verification for
bundle integrity, audit log signatures, and capability tokens.

KAN-790: Hardened passphrase handling
-------------------------------------
- Unified env var: AEGIS_PRIVATE_KEY_PASSPHRASE (primary)
- Legacy fallback: AEGIS_LATTICE_PRIVATE_KEY_PASSPHRASE
- Production mode: set AEGIS_CRYPTO_STRICT=1 to require passphrase
- Minimum passphrase length: 20 characters in strict mode
"""
from __future__ import annotations

import base64
import hashlib
import logging
import os
import warnings
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# KAN-790: Passphrase configuration
# ---------------------------------------------------------------------------
_PASSPHRASE_ENV_PRIMARY = "AEGIS_PRIVATE_KEY_PASSPHRASE"
_PASSPHRASE_ENV_LEGACY_LATTICE = "AEGIS_LATTICE_PRIVATE_KEY_PASSPHRASE"
_STRICT_MODE_ENV = "AEGIS_CRYPTO_STRICT"
_MIN_PASSPHRASE_LENGTH = 20


class CryptoConfigError(RuntimeError):
    """Raised when cryptographic configuration is invalid in strict mode."""
    pass


def _resolve_passphrase(*, context: str = "lattice") -> bytes | None:
    """
    Resolve the private key passphrase from environment variables.

    Priority:
        1. AEGIS_PRIVATE_KEY_PASSPHRASE  (unified)
        2. AEGIS_LATTICE_PRIVATE_KEY_PASSPHRASE  (legacy)

    In strict mode (AEGIS_CRYPTO_STRICT=1):
        - Passphrase is mandatory; raises CryptoConfigError if absent
        - Minimum length of 20 characters enforced

    Returns:
        Encoded passphrase bytes, or None if not set (non-strict only)
    """
    passphrase = (
        os.getenv(_PASSPHRASE_ENV_PRIMARY)
        or os.getenv(_PASSPHRASE_ENV_LEGACY_LATTICE)
    )

    strict = os.getenv(_STRICT_MODE_ENV, "").strip() in ("1", "true", "yes")

    if passphrase and os.getenv(_PASSPHRASE_ENV_LEGACY_LATTICE) and not os.getenv(_PASSPHRASE_ENV_PRIMARY):
        warnings.warn(
            f"Using deprecated env var {_PASSPHRASE_ENV_LEGACY_LATTICE}. "
            f"Please migrate to {_PASSPHRASE_ENV_PRIMARY}.",
            DeprecationWarning,
            stacklevel=3,
        )

    if strict:
        if not passphrase:
            raise CryptoConfigError(
                f"AEGIS_CRYPTO_STRICT is enabled but {_PASSPHRASE_ENV_PRIMARY} is not set. "
                f"Private keys must be passphrase-protected in production."
            )
        if len(passphrase) < _MIN_PASSPHRASE_LENGTH:
            raise CryptoConfigError(
                f"Passphrase is too short ({len(passphrase)} chars). "
                f"Minimum length in strict mode is {_MIN_PASSPHRASE_LENGTH} characters."
            )

    if not passphrase:
        logger.warning(
            "crypto.key_load: No passphrase set — private key will be loaded/saved "
            "without encryption. Set %s for production use.",
            _PASSPHRASE_ENV_PRIMARY,
        )
        return None

    logger.info("crypto.key_load: Passphrase resolved for context=%s", context)
    return passphrase.encode("utf-8")


# ---------------------------------------------------------------------------
# Hashing utilities
# ---------------------------------------------------------------------------

def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64d(data: str) -> bytes:
    return base64.b64decode(data.encode("ascii"))


# ---------------------------------------------------------------------------
# Key generation
# ---------------------------------------------------------------------------

def generate_ecdsa_p256_keypair() -> tuple[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey]:
    private_key = ec.generate_private_key(ec.SECP256R1())
    return private_key, private_key.public_key()


# ---------------------------------------------------------------------------
# Key I/O
# ---------------------------------------------------------------------------

def load_private_key_pem(path: Path) -> ec.EllipticCurvePrivateKey:
    pwd = _resolve_passphrase(context="lattice-load")
    return serialization.load_pem_private_key(path.read_bytes(), password=pwd)


def load_public_key_pem(path: Path) -> ec.EllipticCurvePublicKey:
    return serialization.load_pem_public_key(path.read_bytes())


def save_private_key_pem(key: ec.EllipticCurvePrivateKey, path: Path) -> None:
    pwd = _resolve_passphrase(context="lattice-save")
    encryption = (
        serialization.BestAvailableEncryption(pwd)
        if pwd
        else serialization.NoEncryption()
    )
    path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption,
        )
    )
    try:
        os.chmod(path, 0o600)
    except OSError:
        # Best effort only; some filesystems may not support POSIX modes.
        pass


def save_public_key_pem(key: ec.EllipticCurvePublicKey, path: Path) -> None:
    path.write_bytes(
        key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )


# ---------------------------------------------------------------------------
# Signing & verification
# ---------------------------------------------------------------------------

def sign_ecdsa_p256(private_key: ec.EllipticCurvePrivateKey, message: bytes) -> bytes:
    return private_key.sign(message, ec.ECDSA(hashes.SHA256()))


def verify_ecdsa_p256(public_key: ec.EllipticCurvePublicKey, message: bytes, signature: bytes) -> bool:
    try:
        public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False
