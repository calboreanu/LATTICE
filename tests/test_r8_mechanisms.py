"""R8 dual-use mechanisms: authorization provenance/revocation, policy linter,
key rotation/revocation."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from lattice.authorization import issue_authorization, authorization_valid, RevocationRegistry
from lattice.policy_linter import lint_policy, policy_is_safe
from lattice.key_management import KeyRing

KEY = b"signing-key"
T0 = datetime(2026, 6, 1, tzinfo=timezone.utc)


def _auth(**kw):
    base = dict(authorization_id="AUTH-1", principal="cdr.smith", operation_id="OP-1",
                scope={"targets": ["acme.example.com"]}, key=KEY, now=T0)
    base.update(kw)
    return issue_authorization(**base)


# --- authorization ---------------------------------------------------------

def test_authorization_valid():
    reg = RevocationRegistry()
    assert authorization_valid(_auth(), KEY, reg, now=T0) == (True, "AUTH_VALID")


def test_authorization_revoked():
    reg = RevocationRegistry()
    a = _auth()
    reg.revoke(a.authorization_id, reason="scope change", by="cdr.smith")
    assert authorization_valid(a, KEY, reg, now=T0) == (False, "AUTH_REVOKED")
    assert reg.record(a.authorization_id)["by"] == "cdr.smith"


def test_authorization_expired():
    reg = RevocationRegistry()
    a = _auth(ttl_seconds=3600)
    assert authorization_valid(a, KEY, reg, now=T0)[0] is True
    assert authorization_valid(a, KEY, reg, now=T0 + timedelta(hours=2)) == (False, "AUTH_EXPIRED")


def test_authorization_bad_signature():
    reg = RevocationRegistry()
    assert authorization_valid(_auth(), b"wrong-key", reg, now=T0) == (False, "AUTH_SIGNATURE_INVALID")


# --- policy linter ---------------------------------------------------------

def test_linter_flags_wildcard_target():
    findings = lint_policy({"allowed_targets": ["*"], "permitted_tools": {"DEFAULT": ["echo"]},
                            "thresholds": {"autonomous": 85}, "rules": [{"type": "X"}],
                            "confidence_caps": {}})
    assert any(f["code"] == "WILDCARD_TARGET" and f["severity"] == "HIGH" for f in findings)
    assert policy_is_safe({"allowed_targets": ["*"]}) is False


def test_linter_flags_empty_allowlist():
    findings = lint_policy({"allowed_targets": []})
    assert any(f["code"] == "EMPTY_ALLOWLIST" for f in findings)


def test_linter_passes_tight_policy():
    tight = {"allowed_targets": ["acme.example.com"], "permitted_tools": {"DEFAULT": ["echo"]},
             "thresholds": {"autonomous": 85, "hitl": 65, "escalate": 45},
             "rules": [{"type": "TARGET_ALLOWLIST", "effect": "ESCALATE", "values": ["acme.example.com"]}],
             "confidence_caps": {"irreversibility": {"irreversible": 0.7}}}
    assert policy_is_safe(tight) is True


def test_linter_flags_low_threshold():
    findings = lint_policy({"allowed_targets": ["x"], "thresholds": {"autonomous": 30}})
    assert any(f["code"] == "LOW_AUTONOMOUS_THRESHOLD" for f in findings)


# --- key management --------------------------------------------------------

def test_key_sign_and_verify():
    kr = KeyRing()
    kr.add_key(1, b"k1")
    ver, sig = kr.sign(b"msg")
    assert ver == 1 and kr.verify(b"msg", ver, sig) == (True, "OK")


def test_key_rotation_keeps_historical_verification():
    kr = KeyRing()
    kr.add_key(1, b"k1")
    v1, sig1 = kr.sign(b"old")
    kr.rotate(2, b"k2")
    assert kr.active_version() == 2
    # Historical signature under v1 still verifies after rotation.
    assert kr.verify(b"old", v1, sig1) == (True, "OK")


def test_key_revocation_rejects():
    kr = KeyRing()
    kr.add_key(1, b"k1")
    v1, sig1 = kr.sign(b"x")
    kr.revoke(1)
    assert kr.verify(b"x", v1, sig1) == (False, "KEY_REVOKED")
    assert kr.active_version() is None
