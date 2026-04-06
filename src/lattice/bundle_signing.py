from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict

try:
    from mandate.hashing import canonical_json
except ImportError:
    from lattice._vendor.hashing import canonical_json

from .crypto import b64d, b64e, load_private_key_pem, load_public_key_pem, sha256_hex, sign_ecdsa_p256, verify_ecdsa_p256


_SIGNATURE_ALG = "ECDSA_P256_SHA256"


def bundle_signing_body(bundle: Dict[str, Any]) -> Dict[str, Any]:
    """Return the canonical hash-covered body for a signed approved bundle."""
    body = deepcopy(bundle)
    body.pop("signature", None)
    body.pop("bundle_hash", None)
    return body


def compute_signed_bundle_hash(bundle: Dict[str, Any]) -> str:
    body = bundle_signing_body(bundle)
    return sha256_hex(canonical_json(body).encode("utf-8"))


def sign_signed_bundle(bundle: Dict[str, Any], private_key_path: Path, pubkey_id: str) -> Dict[str, Any]:
    """Sign a SignedApprovedBundle payload and return a fully signed copy."""
    signed = deepcopy(bundle)
    bundle_hash = compute_signed_bundle_hash(signed)
    signed["bundle_hash"] = bundle_hash

    private_key = load_private_key_pem(private_key_path)
    signature = sign_ecdsa_p256(private_key, bytes.fromhex(bundle_hash))
    signed["signature"] = {
        "alg": _SIGNATURE_ALG,
        "pubkey_id": str(pubkey_id),
        "sig_b64": b64e(signature),
    }
    return signed


@dataclass(frozen=True)
class BundleSignatureValidation:
    ok: bool
    reason: str = ""


def verify_signed_bundle(bundle: Dict[str, Any], public_key_path: Path) -> BundleSignatureValidation:
    signature = bundle.get("signature")
    if not isinstance(signature, dict):
        return BundleSignatureValidation(False, "missing signature object")
    if signature.get("alg") != _SIGNATURE_ALG:
        return BundleSignatureValidation(False, f"unsupported signature algorithm: {signature.get('alg')}")

    expected_hash = compute_signed_bundle_hash(bundle)
    actual_hash = str(bundle.get("bundle_hash", ""))
    if actual_hash != expected_hash:
        return BundleSignatureValidation(False, "bundle_hash mismatch")

    sig_b64 = signature.get("sig_b64")
    if not isinstance(sig_b64, str) or not sig_b64:
        return BundleSignatureValidation(False, "missing signature.sig_b64")

    public_key = load_public_key_pem(public_key_path)
    if not verify_ecdsa_p256(public_key, bytes.fromhex(actual_hash), b64d(sig_b64)):
        return BundleSignatureValidation(False, "invalid signature over bundle_hash")

    return BundleSignatureValidation(True, "")
