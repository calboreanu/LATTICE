from __future__ import annotations

import json
import os
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:
    from mandate.hashing import canonical_json
except ImportError:
    from lattice._vendor.hashing import canonical_json

from .crypto import b64d, b64e, load_private_key_pem, load_public_key_pem, sha256_hex, sign_ecdsa_p256, verify_ecdsa_p256


GENESIS_HASH_HEX = "00" * 32
SIGNATURE_ALG = "ECDSA_P256_SHA256"


@dataclass(frozen=True)
class AuditSigner:
    key_id: str
    private_key_path: Path

    def sign_hash(self, record_hash_hex: str) -> str:
        private_key = load_private_key_pem(self.private_key_path)
        signature = sign_ecdsa_p256(private_key, bytes.fromhex(record_hash_hex))
        return b64e(signature)


def _uuid7() -> str:
    """Generate a UUIDv7-compatible identifier for audit records."""
    now_ms = int(time.time() * 1000) & ((1 << 48) - 1)
    rand_a = int.from_bytes(os.urandom(2), "big") & 0x0FFF
    rand_b = int.from_bytes(os.urandom(8), "big") & ((1 << 62) - 1)

    value = 0
    value |= now_ms << 80
    value |= 0x7 << 76
    value |= rand_a << 64
    value |= 0b10 << 62
    value |= rand_b
    return str(uuid.UUID(int=value))


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _isoformat_z(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _parse_iso8601(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _record_without_integrity(record: Dict[str, Any]) -> Dict[str, Any]:
    material = dict(record)
    material.pop("record_hash", None)
    material.pop("signature", None)
    return material


def _load_existing_tail(audit_path: str) -> tuple[Optional[Dict[str, Any]], int]:
    if not os.path.exists(audit_path):
        return None, 0

    with open(audit_path, "r", encoding="utf-8") as handle:
        lines = [line for line in handle.read().splitlines() if line.strip()]
    if not lines:
        return None, 0

    for idx in range(len(lines) - 1, -1, -1):
        try:
            parsed = json.loads(lines[idx])
            return parsed, len(lines)
        except json.JSONDecodeError:
            continue

    return None, len(lines)


def _default_payload(record: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "unit_hash": record.get("unit_hash"),
        "action_hash": record.get("action_hash"),
        "policy_id": record.get("policy_id"),
        "policy_version": record.get("policy_version"),
        "verdict": record.get("verdict"),
        "confidence": record.get("confidence"),
        "reason_codes": list(record.get("reason_codes", [])),
    }


def _signature_stub() -> Dict[str, Any]:
    return {"type": "stub", "note": "Unsigned local audit record."}


def append_audit_record(
    audit_path: str,
    record: Dict[str, Any],
    *,
    signer: Optional[AuditSigner] = None,
    require_signature: bool = False,
) -> Dict[str, Any]:
    """Append a hash-linked audit record with optional ECDSA signature."""
    os.makedirs(os.path.dirname(audit_path), exist_ok=True)

    last_record, line_count = _load_existing_tail(audit_path)
    if last_record and str(last_record.get("event_type", "")) == "CHAIN_SEALED":
        raise ValueError("audit chain is sealed and immutable")

    prev_hash = GENESIS_HASH_HEX
    prev_timestamp: Optional[datetime] = None
    prev_sequence = 0

    if last_record:
        prev_hash = str(last_record.get("record_hash", GENESIS_HASH_HEX))
        prev_sequence = int(last_record.get("sequence_number", line_count))
        last_ts = last_record.get("timestamp")
        if isinstance(last_ts, str):
            try:
                prev_timestamp = _parse_iso8601(last_ts)
            except Exception:
                prev_timestamp = None

    timestamp = _now_utc()
    if prev_timestamp is not None and timestamp <= prev_timestamp:
        timestamp = prev_timestamp + timedelta(microseconds=1)

    out = dict(record)
    out.setdefault("record_id", _uuid7())
    out.setdefault("timestamp", _isoformat_z(timestamp))
    out.setdefault("event_type", "GOVERNANCE_VERDICT")
    out.setdefault("actor_id", "lattice.execution_gate")
    out.setdefault("sequence_number", prev_sequence + 1)
    out.setdefault("prev_hash", prev_hash)
    out.setdefault("prev_record_hash", prev_hash)  # Backward-compatible alias

    payload = out.get("payload")
    if not isinstance(payload, dict):
        payload = _default_payload(out)
        out["payload"] = payload
    out["payload_hash"] = sha256_hex(canonical_json(payload).encode("utf-8"))

    record_hash = sha256_hex(canonical_json(_record_without_integrity(out)).encode("utf-8"))
    out["record_hash"] = record_hash
    if signer is None:
        if require_signature:
            raise ValueError("audit signer is required when require_signature=True")
        out["signature"] = _signature_stub()
    else:
        out["signature"] = {
            "alg": SIGNATURE_ALG,
            "key_id": signer.key_id,
            "sig_b64": signer.sign_hash(record_hash),
        }

    with open(audit_path, "a", encoding="utf-8") as handle:
        handle.write(json.dumps(out, ensure_ascii=False) + "\n")
    return out


def load_audit_chain(audit_path: str | Path) -> List[Dict[str, Any]]:
    path = Path(audit_path)
    if not path.exists():
        return []
    out: List[Dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        out.append(json.loads(line))
    return out


def seal_audit_chain(
    audit_path: str,
    *,
    reason: str,
    signer: Optional[AuditSigner] = None,
    actor_id: str = "lattice.system",
) -> Dict[str, Any]:
    chain = load_audit_chain(audit_path)
    chain_hash = sha256_hex("".join(str(rec.get("record_hash", "")) for rec in chain).encode("utf-8"))
    payload = {
        "seal": {
            "reason": str(reason),
            "total_record_count": len(chain) + 1,
            "chain_hash": chain_hash,
            "seal_timestamp": _isoformat_z(_now_utc()),
        }
    }
    return append_audit_record(
        audit_path,
        {
            "event_type": "CHAIN_SEALED",
            "actor_id": actor_id,
            "payload": payload,
            "reason_codes": [f"CHAIN_SEALED:{reason}"],
        },
        signer=signer,
    )


def verify_audit_chain(
    chain: List[Dict[str, Any]],
    *,
    public_keys_by_id: Optional[Dict[str, Path]] = None,
) -> Tuple[bool, List[str]]:
    if not chain:
        return False, ["empty chain"]

    keys = {}
    if public_keys_by_id:
        keys = {key_id: load_public_key_pem(path) for key_id, path in public_keys_by_id.items()}

    previous_hash = GENESIS_HASH_HEX
    previous_sequence = 0
    previous_timestamp: Optional[datetime] = None

    for idx, record in enumerate(chain):
        sequence = int(record.get("sequence_number", -1))
        if sequence != previous_sequence + 1:
            return False, [f"sequence gap at record index {idx}"]

        prev_hash = str(record.get("prev_hash", record.get("prev_record_hash", "")))
        if idx == 0 and prev_hash != GENESIS_HASH_HEX:
            return False, ["genesis record has non-zero prev_hash"]
        if idx > 0 and prev_hash != previous_hash:
            return False, [f"chain break at record index {idx}"]

        timestamp_raw = record.get("timestamp")
        if not isinstance(timestamp_raw, str):
            return False, [f"timestamp missing at record index {idx}"]
        try:
            parsed_timestamp = _parse_iso8601(timestamp_raw)
        except Exception:
            return False, [f"invalid timestamp at record index {idx}"]
        if previous_timestamp is not None and parsed_timestamp < previous_timestamp:
            return False, [f"temporal ordering violation at record index {idx}"]

        recomputed_hash = sha256_hex(canonical_json(_record_without_integrity(record)).encode("utf-8"))
        if recomputed_hash != record.get("record_hash"):
            return False, [f"hash mismatch at record index {idx}"]

        signature = record.get("signature")
        if public_keys_by_id is not None:
            if not isinstance(signature, dict):
                return False, [f"signature missing at record index {idx}"]
            if signature.get("alg") != SIGNATURE_ALG:
                return False, [f"unsupported signature algorithm at record index {idx}"]
            key_id = str(signature.get("key_id", ""))
            pub = keys.get(key_id)
            if pub is None:
                return False, [f"missing public key for key_id '{key_id}' at record index {idx}"]
            sig_b64 = signature.get("sig_b64")
            if not isinstance(sig_b64, str) or not sig_b64:
                return False, [f"missing signature payload at record index {idx}"]
            if not verify_ecdsa_p256(pub, bytes.fromhex(recomputed_hash), b64d(sig_b64)):
                return False, [f"signature invalid at record index {idx}"]

        previous_hash = recomputed_hash
        previous_sequence = sequence
        previous_timestamp = parsed_timestamp

    last_record = chain[-1]
    if str(last_record.get("event_type", "")) == "CHAIN_SEALED":
        seal = (last_record.get("payload") or {}).get("seal") or {}
        if not isinstance(seal, dict):
            return False, ["seal payload missing"]
        total_count = seal.get("total_record_count")
        if total_count is not None and total_count != len(chain):
            return False, ["seal count mismatch"]

    return True, []
