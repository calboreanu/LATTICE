"""Adversarial tests for coordination-plane security (R4).

Covers the four system-level attacks the threat model names, plus the invariant
that no coordination message may carry an authorization/verdict between cells.
"""
from __future__ import annotations

from dataclasses import replace

from lattice.coordination_security import (
    SecureCoordinationBus,
    SharedStateValidator,
    EscalationRateLimiter,
    detect_fan_out,
    reject_verdict_forwarding,
)

KEY_A = b"key-cell-a"
KEY_B = b"key-cell-b"


def _bus() -> SecureCoordinationBus:
    bus = SecureCoordinationBus()
    bus.register_cell("CELL-A", KEY_A)
    bus.register_cell("CELL-B", KEY_B)
    return bus


def test_legitimate_message_delivers():
    bus = _bus()
    m = bus.publish(source_cell_id="CELL-A", target_cell_id="CELL-B",
                    operation_id="OP1", payload={"status": "ready"}, key=KEY_A)
    assert bus.deliver(m) == (True, None)


# --- Attack 1: message spoofing -------------------------------------------

def test_spoofed_message_rejected():
    bus = _bus()
    # Attacker forges a message from CELL-A but doesn't hold KEY_A.
    forged = bus.publish(source_cell_id="CELL-A", target_cell_id="CELL-B",
                         operation_id="OP1", payload={"status": "ready"}, key=b"wrong-key")
    assert bus.deliver(forged) == (False, "AUTH_FAILED")


def test_tampered_payload_rejected():
    bus = _bus()
    m = bus.publish(source_cell_id="CELL-A", target_cell_id="CELL-B",
                    operation_id="OP1", payload={"status": "ready"}, key=KEY_A)
    tampered = replace(m, payload={"status": "compromised"})  # MAC no longer matches
    assert bus.deliver(tampered) == (False, "AUTH_FAILED")


# --- Attack 2: replay ------------------------------------------------------

def test_replay_rejected():
    bus = _bus()
    m = bus.publish(source_cell_id="CELL-A", target_cell_id="CELL-B",
                    operation_id="OP1", payload={"x": 1}, key=KEY_A)
    assert bus.deliver(m) == (True, None)
    assert bus.deliver(m) == (False, "REPLAY_DETECTED")


def test_stale_sequence_rejected():
    bus = _bus()
    m1 = bus.publish(source_cell_id="CELL-A", target_cell_id="CELL-B", operation_id="OP", payload={"n": 1}, key=KEY_A)
    m2 = bus.publish(source_cell_id="CELL-A", target_cell_id="CELL-B", operation_id="OP", payload={"n": 2}, key=KEY_A)
    assert bus.deliver(m2)[0] is True
    # m1 has a lower sequence number than the already-delivered m2 -> stale.
    assert bus.deliver(m1) == (False, "STALE_SEQUENCE")


# --- Attack 3: shared-state poisoning -------------------------------------

def test_shared_state_requires_quorum():
    v = SharedStateValidator(quorum=2)
    assert v.submit("target_clear", True, "CELL-A") == (False, "SHARED_STATE_QUORUM_NOT_MET")
    assert v.submit("target_clear", True, "CELL-B") == (True, "ACCEPTED_QUORUM")


def test_single_source_poison_not_accepted():
    v = SharedStateValidator(quorum=3)
    # One compromised cell cannot push a critical value on its own.
    accepted, reason = v.submit("safe_to_proceed", True, "CELL-A")
    assert accepted is False and reason == "SHARED_STATE_QUORUM_NOT_MET"


# --- Attack 4: escalation flooding / suppression ---------------------------

def test_escalation_flood_rate_limited():
    rl = EscalationRateLimiter(max_per_window=3)
    accepted = [rl.offer(f"E{i}")[0] for i in range(5)]
    assert accepted == [True, True, True, False, False]


def test_escalation_duplicate_suppressed():
    rl = EscalationRateLimiter(max_per_window=10)
    assert rl.offer("E1") == (True, "ACCEPTED")
    assert rl.offer("E1") == (False, "DUPLICATE_SUPPRESSED")


# --- Fan-out amplification -------------------------------------------------

def test_fan_out_detected():
    events = [
        {"operation_id": "OP", "target": "SUB-47", "cell": c}
        for c in ("A", "B", "C", "D")
    ]
    flagged = detect_fan_out(events, threshold=3)
    assert "OP:SUB-47" in flagged


def test_fan_out_below_threshold_not_flagged():
    events = [{"operation_id": "OP", "target": "SUB-47", "cell": c} for c in ("A", "B")]
    assert detect_fan_out(events, threshold=3) == []


# --- Invariant: no verdict forwarding -------------------------------------

def test_verdict_forwarding_rejected():
    assert reject_verdict_forwarding({"verdict": "ALLOW"}) is True
    assert reject_verdict_forwarding({"authorization_token": "abc"}) is True
    assert reject_verdict_forwarding({"status": "ready"}) is False
