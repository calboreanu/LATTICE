"""Coordination-plane security for Team/Squadron deployments (R4).

The per-cell execution gate remains non-bypassable, but a compromised
Coordination Agent can still induce *correlated* harm across cells. This module
adds the coordination-layer controls named in the threat model and validates
them against the four system-level attacks:

  * message spoofing / replay  -> mutual authentication (HMAC) + replay cache +
                                  monotonic per-source sequencing
  * shared-state poisoning     -> quorum corroboration before a critical shared-
                                  state value is accepted
  * escalation flooding/suppr. -> dedup + rate limiting of escalations
  * fan-out amplification      -> detection of one event -> many same-target
                                  actions, flagged for per-cell re-authorization

Design invariant: **no coordination message is an authorization token.** A cell
never executes a tool on another cell's say-so; verdict/authorization payloads
are rejected outright (``reject_verdict_forwarding``). Authorization always
returns to each cell's local governance gate.
"""
from __future__ import annotations

import hashlib
import hmac
import json
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

# Payload keys that would imply one cell authorizing another's action.
CRITICAL_PAYLOAD_KEYS = {"verdict", "authorization", "authorization_token", "allow", "approval", "approved"}


def _canon(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _mac(key: bytes, core: Dict[str, Any]) -> str:
    return hmac.new(key, _canon(core), hashlib.sha256).hexdigest()


@dataclass(frozen=True)
class AuthenticatedMessage:
    message_id: str
    sequence_number: int
    timestamp: str
    source_cell_id: str
    target_cell_id: str
    operation_id: str
    payload: Dict[str, Any]
    mac: str

    def core(self) -> Dict[str, Any]:
        return {
            "message_id": self.message_id,
            "sequence_number": self.sequence_number,
            "timestamp": self.timestamp,
            "source_cell_id": self.source_cell_id,
            "target_cell_id": self.target_cell_id,
            "operation_id": self.operation_id,
            "payload": self.payload,
        }


class SecureCoordinationBus:
    """Authenticated, replay-resistant, monotonically-sequenced coordination bus."""

    def __init__(self) -> None:
        self._keys: Dict[str, bytes] = {}
        self._seq = 0
        self._delivered_ids: set[str] = set()
        self._last_seq: Dict[Tuple[str, str], int] = {}

    def register_cell(self, cell_id: str, key: bytes) -> None:
        self._keys[cell_id] = key

    def publish(self, *, source_cell_id: str, target_cell_id: str, operation_id: str,
                payload: Dict[str, Any], key: bytes) -> AuthenticatedMessage:
        self._seq += 1
        core = {
            "message_id": f"MSG-{self._seq:06d}",
            "sequence_number": self._seq,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source_cell_id": source_cell_id,
            "target_cell_id": target_cell_id,
            "operation_id": operation_id,
            "payload": dict(payload),
        }
        return AuthenticatedMessage(mac=_mac(key, core), **core)

    def deliver(self, message: AuthenticatedMessage) -> Tuple[bool, Optional[str]]:
        """Return (accepted, reason). Reason is a rejection code when not accepted."""
        key = self._keys.get(message.source_cell_id)
        if key is None:
            return False, "AUTH_UNKNOWN_SOURCE"
        if not hmac.compare_digest(message.mac, _mac(key, message.core())):
            return False, "AUTH_FAILED"  # spoofed or tampered
        if message.message_id in self._delivered_ids:
            return False, "REPLAY_DETECTED"
        seq_key = (message.source_cell_id, message.target_cell_id)
        if message.sequence_number <= self._last_seq.get(seq_key, 0):
            return False, "STALE_SEQUENCE"  # replayed/reordered
        self._delivered_ids.add(message.message_id)
        self._last_seq[seq_key] = message.sequence_number
        return True, None


def reject_verdict_forwarding(payload: Dict[str, Any]) -> bool:
    """True if the payload attempts to forward an authorization/verdict between cells."""
    if not isinstance(payload, dict):
        return False
    return any(k in CRITICAL_PAYLOAD_KEYS for k in payload)


class SharedStateValidator:
    """Require quorum corroboration before accepting a critical shared-state value."""

    def __init__(self, quorum: int) -> None:
        self.quorum = max(1, int(quorum))
        self._evidence: Dict[Tuple[str, str], set] = {}

    def submit(self, state_key: str, value: Any, source_cell_id: str) -> Tuple[bool, str]:
        bucket = self._evidence.setdefault((state_key, json.dumps(value, sort_keys=True)), set())
        bucket.add(source_cell_id)
        if len(bucket) >= self.quorum:
            return True, "ACCEPTED_QUORUM"
        return False, "SHARED_STATE_QUORUM_NOT_MET"


class EscalationRateLimiter:
    """Dedup + cap escalations within a window to resist flooding (and surface suppression)."""

    def __init__(self, max_per_window: int) -> None:
        self.max = max(0, int(max_per_window))
        self._seen: set[str] = set()
        self._count = 0

    def offer(self, escalation_id: str) -> Tuple[bool, str]:
        if escalation_id in self._seen:
            return False, "DUPLICATE_SUPPRESSED"
        if self._count >= self.max:
            self._seen.add(escalation_id)
            return False, "RATE_LIMIT_EXCEEDED"
        self._seen.add(escalation_id)
        self._count += 1
        return True, "ACCEPTED"


def detect_fan_out(events: List[Dict[str, Any]], threshold: int) -> List[str]:
    """Flag (operation_id, target) pairs driven across >= threshold cells from one event.

    Such fan-out is not a per-cell bypass, but it requires per-cell
    re-authorization (and, for high-consequence classes, operator approval)
    before coordinated execution proceeds.
    """
    counts = Counter((str(e.get("operation_id")), str(e.get("target"))) for e in events)
    return [f"{op}:{tgt}" for (op, tgt), n in counts.items() if n >= threshold]
