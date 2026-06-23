"""Versioned signing keys with rotation + revocation (R8 minor comment).

Answers the reviewer's request to "specify whether ECDSA signing keys, audit
anchors, and policy bundles are rotated, versioned, and revocable." A ``KeyRing``
holds versioned keys, supports rotation (activate a new version while old
versions can still *verify* historical records) and revocation (a revoked
version verifies nothing). Demonstrated with HMAC here for a dependency-light
reference; the AEGIS build wires the same lifecycle to ECDSA P-256.
"""
from __future__ import annotations

import hashlib
import hmac
from typing import Dict, Optional, Tuple


class KeyRing:
    def __init__(self) -> None:
        self._keys: Dict[int, bytes] = {}
        self._revoked: set[int] = set()
        self._active: Optional[int] = None

    def add_key(self, version: int, key: bytes, *, activate: bool = True) -> None:
        if version in self._keys:
            raise ValueError(f"key version {version} already exists")
        self._keys[version] = key
        if activate:
            self._active = version

    def rotate(self, version: int, key: bytes) -> None:
        """Introduce and activate a new key version (old versions still verify)."""
        self.add_key(version, key, activate=True)

    def revoke(self, version: int) -> None:
        self._revoked.add(version)
        if self._active == version:
            live = [v for v in sorted(self._keys) if v not in self._revoked]
            self._active = live[-1] if live else None

    def active_version(self) -> Optional[int]:
        return self._active

    def sign(self, message: bytes) -> Tuple[int, str]:
        if self._active is None:
            raise ValueError("no active signing key")
        sig = hmac.new(self._keys[self._active], message, hashlib.sha256).hexdigest()
        return self._active, sig

    def verify(self, message: bytes, version: int, signature: str) -> Tuple[bool, str]:
        if version not in self._keys:
            return False, "UNKNOWN_KEY_VERSION"
        if version in self._revoked:
            return False, "KEY_REVOKED"
        expected = hmac.new(self._keys[version], message, hashlib.sha256).hexdigest()
        ok = hmac.compare_digest(signature, expected)
        return (ok, "OK" if ok else "BAD_SIGNATURE")
