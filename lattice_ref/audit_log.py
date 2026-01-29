from __future__ import annotations
import json
import os
from datetime import datetime, timezone
from typing import Any, Dict, Optional
from .hashing import sha256_hex

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

def append_audit_record(audit_path: str, record: Dict[str, Any]) -> Dict[str, Any]:
    """Append-only JSONL audit log with hash-linking (toy, no real signature)."""
    os.makedirs(os.path.dirname(audit_path), exist_ok=True)

    prev_hash: Optional[str] = None
    if os.path.exists(audit_path):
        with open(audit_path, "rb") as f:
            lines = f.read().splitlines()
            if lines:
                try:
                    last = json.loads(lines[-1].decode("utf-8"))
                    prev_hash = last.get("record_hash")
                except Exception:
                    prev_hash = None

    record = dict(record)
    record["timestamp"] = record.get("timestamp") or _now_iso()
    record["prev_record_hash"] = prev_hash

    canon = json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    record_hash = sha256_hex(canon)
    record["record_hash"] = record_hash
    record["signature"] = {"type": "stub", "note": "Replace with real signing in production."}

    with open(audit_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")

    return record
