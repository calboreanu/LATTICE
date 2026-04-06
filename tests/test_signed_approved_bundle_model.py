"""Tests for lattice.models.SignedApprovedBundle."""
from __future__ import annotations

from lattice.models import SignedApprovedBundle


def _valid_signed_bundle_dict() -> dict:
    return {
        "bundle_id": "B-301-001",
        "bundle_version": "1.0.0",
        "bundle_hash": "a" * 64,
        "safe_state_id": "HALT",
        "authorized_tools": ["echo"],
        "tool_hashes": {"echo": "b" * 64},
        "constraints": {
            "allowed_targets": ["example.local"],
            "time_window": {
                "start": "2026-02-10T00:00:00Z",
                "end": "2026-12-31T00:00:00Z"
            }
        },
        "coa": {
            "default_coa_id": "A",
            "fallback_sequence": ["B"],
            "coas": [
                {
                    "coa_id": "A",
                    "steps": [
                        {"step_id": "a1", "tool_id": "echo", "params": {"msg": "hello"}}
                    ]
                },
                {"coa_id": "B", "steps": []}
            ]
        },
        "decision_tree": {
            "start": "exec",
            "nodes": [
                {
                    "id": "exec",
                    "kind": "EXECUTE_STEP",
                    "default": "exec",
                    "edges": [
                        {"when": {"signal": "DONE"}, "to": "end"},
                        {"when": {"signal": "HALT"}, "to": "safe"}
                    ]
                },
                {"id": "safe", "kind": "SAFE_STATE", "default": "end"},
                {"id": "end", "kind": "END", "default": "end"}
            ]
        },
        "tripwire_predicates": [
            {
                "predicate_id": "TW-301-01",
                "metric": "RATE",
                "operator": "GT",
                "threshold": 2.0,
                "on_trigger": "ESCALATE",
                "window": {"kind": "EVENT_COUNT", "size": 5},
                "enabled": True
            }
        ],
        "inputs": {
            "mandate": {
                "mandate_id": "MND-1",
                "version": "1.0",
                "anchor_hash": "c" * 64,
                "trace_chain_hash": "d" * 64,
                "selected_coa": "A",
                "fallback_sequence": ["B"]
            },
            "lattice_policy": {
                "policy_id": "POL-1",
                "version": "v1",
                "policy_hash": "e" * 64
            }
        },
        "signature": {
            "alg": "ECDSA_P256_SHA256",
            "pubkey_id": "gov_k1",
            "sig_b64": "ZmFrZV9zaWduYXR1cmU="
        }
    }


def test_signed_approved_bundle_round_trip_and_contract_validation() -> None:
    payload = _valid_signed_bundle_dict()
    bundle = SignedApprovedBundle.from_dict(payload)

    assert bundle.validate_cross_layer_contracts() == []
    assert bundle.to_dict() == payload


def test_signed_approved_bundle_contract_rejects_unknown_selected_coa() -> None:
    payload = _valid_signed_bundle_dict()
    payload["inputs"]["mandate"]["selected_coa"] = "UNKNOWN"
    bundle = SignedApprovedBundle.from_dict(payload)

    errors = bundle.validate_cross_layer_contracts()
    assert "inputs.mandate.selected_coa must reference a known COA" in errors


def test_signed_approved_bundle_contract_rejects_unauthorized_step_tool() -> None:
    payload = _valid_signed_bundle_dict()
    payload["coa"]["coas"][0]["steps"][0]["tool_id"] = "nmap"
    bundle = SignedApprovedBundle.from_dict(payload)

    errors = bundle.validate_cross_layer_contracts()
    assert "coa 'A' uses unauthorized tool 'nmap'" in errors


def test_signed_approved_bundle_contract_rejects_duplicate_tripwire_ids() -> None:
    payload = _valid_signed_bundle_dict()
    payload["tripwire_predicates"] = [
        payload["tripwire_predicates"][0],
        dict(payload["tripwire_predicates"][0]),
    ]
    bundle = SignedApprovedBundle.from_dict(payload)

    errors = bundle.validate_cross_layer_contracts()
    assert "tripwire_predicates must have unique predicate_id values" in errors
