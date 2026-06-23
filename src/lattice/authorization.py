"""Authorization provenance + revocation (R8).

Answers the reviewer's dual-use questions concretely: *how authorization is
established, documented, and revoked*. An ``AuthorizationRecord`` binds a
principal (who authorized), an operation, an explicit scope, issuance time, and
an optional expiry, signed so it is tamper-evident. A ``RevocationRegistry``
records revocations. ``authorization_valid`` checks signature, revocation, and
expiry — so an autonomous deployment can prove an action was, and still is,
authorized.
"""
from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional, Tuple


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _canon(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


@dataclass(frozen=True)
class AuthorizationRecord:
    authorization_id: str
    principal: str
    operation_id: str
    scope: Dict[str, Any]
    issued_at: str
    expires_at: Optional[str]
    signature: str

    def core(self) -> Dict[str, Any]:
        return {
            "authorization_id": self.authorization_id,
            "principal": self.principal,
            "operation_id": self.operation_id,
            "scope": self.scope,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
        }


def issue_authorization(*, authorization_id: str, principal: str, operation_id: str,
                        scope: Dict[str, Any], key: bytes,
                        ttl_seconds: Optional[int] = None,
                        now: Optional[datetime] = None) -> AuthorizationRecord:
    now = now or _now()
    expires = (now + timedelta(seconds=ttl_seconds)).isoformat() if ttl_seconds else None
    core = {
        "authorization_id": authorization_id,
        "principal": principal,
        "operation_id": operation_id,
        "scope": scope,
        "issued_at": now.isoformat(),
        "expires_at": expires,
    }
    sig = hmac.new(key, _canon(core), hashlib.sha256).hexdigest()
    return AuthorizationRecord(signature=sig, **core)


class RevocationRegistry:
    def __init__(self) -> None:
        self._revoked: Dict[str, Dict[str, str]] = {}

    def revoke(self, authorization_id: str, *, reason: str, by: str, now: Optional[datetime] = None) -> None:
        self._revoked[authorization_id] = {"reason": reason, "by": by, "at": (now or _now()).isoformat()}

    def is_revoked(self, authorization_id: str) -> bool:
        return authorization_id in self._revoked

    def record(self, authorization_id: str) -> Optional[Dict[str, str]]:
        return self._revoked.get(authorization_id)


def authorization_valid(auth: AuthorizationRecord, key: bytes, registry: RevocationRegistry,
                        *, now: Optional[datetime] = None) -> Tuple[bool, str]:
    now = now or _now()
    expected = hmac.new(key, _canon(auth.core()), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(auth.signature, expected):
        return False, "AUTH_SIGNATURE_INVALID"
    if registry.is_revoked(auth.authorization_id):
        return False, "AUTH_REVOKED"
    if auth.expires_at and now > datetime.fromisoformat(auth.expires_at):
        return False, "AUTH_EXPIRED"
    return True, "AUTH_VALID"
