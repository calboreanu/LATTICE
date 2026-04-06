"""Schema validation tests for LATTICE SignedApprovedBundle contracts."""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, ValidationError
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT202012


LATTICE_SCHEMA_DIR = (
    Path(__file__).parent.parent
    / "src"
    / "lattice"
    / "schemas"
)
SIGNED_SCHEMA_PATH = LATTICE_SCHEMA_DIR / "signed_approved_bundle.schema.json"
DECISION_TREE_SCHEMA_PATH = LATTICE_SCHEMA_DIR / "decision_tree.schema.json"
TRIPWIRE_SCHEMA_PATH = LATTICE_SCHEMA_DIR / "tripwire_predicate.schema.json"
TRACE_BUNDLE_SCHEMA_PATH = (
    Path(__file__).parent.parent
    / "src"
    / "trace_runtime"
    / "schemas"
    / "bundle.schema.json"
)


def _load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _signed_validator() -> Draft202012Validator:
    signed = _load_json(SIGNED_SCHEMA_PATH)
    decision_tree = _load_json(DECISION_TREE_SCHEMA_PATH)
    tripwire = _load_json(TRIPWIRE_SCHEMA_PATH)
    registry = Registry().with_resources(
        [
            (
                decision_tree["$id"],
                Resource.from_contents(decision_tree, default_specification=DRAFT202012),
            ),
            (
                tripwire["$id"],
                Resource.from_contents(tripwire, default_specification=DRAFT202012),
            ),
        ]
    )
    return Draft202012Validator(signed, registry=registry)


def _valid_signed_bundle() -> dict:
    return {
        "bundle_id": "B-301-SCHEMA",
        "bundle_version": "1.0.0",
        "bundle_hash": "a" * 64,
        "safe_state_id": "HALT",
        "authorized_tools": ["echo"],
        "tool_hashes": {"echo": "b" * 64},
        "constraints": {},
        "coa": {
            "default_coa_id": "A",
            "coas": [
                {
                    "coa_id": "A",
                    "steps": [{"tool_id": "echo", "params": {"msg": "hi"}}]
                }
            ]
        },
        "decision_tree": {
            "start": "exec",
            "nodes": [
                {
                    "id": "exec",
                    "kind": "EXECUTE_STEP",
                    "default": "exec",
                    "edges": [{"when": {"signal": "DONE"}, "to": "end"}]
                },
                {"id": "end", "kind": "END", "default": "end"}
            ]
        },
        "tripwire_predicates": [
            {
                "predicate_id": "TW-301",
                "metric": "RATE",
                "operator": "GT",
                "threshold": 1.0,
                "on_trigger": "ESCALATE",
                "window": {"kind": "EVENT_COUNT", "size": 10}
            }
        ],
        "signature": {
            "alg": "ECDSA_P256_SHA256",
            "pubkey_id": "gov_key",
            "sig_b64": "ZmFrZV9zaWc="
        }
    }


def test_schema_accepts_valid_signed_approved_bundle() -> None:
    validator = _signed_validator()
    validator.validate(_valid_signed_bundle())


def test_schema_rejects_invalid_bundle_hash_pattern() -> None:
    validator = _signed_validator()
    bundle = _valid_signed_bundle()
    bundle["bundle_hash"] = "not-a-hash"
    with pytest.raises(ValidationError):
        validator.validate(bundle)


def test_schema_rejects_invalid_tripwire_metric() -> None:
    validator = _signed_validator()
    bundle = _valid_signed_bundle()
    bundle["tripwire_predicates"][0]["metric"] = "BOGUS"
    with pytest.raises(ValidationError):
        validator.validate(bundle)


@pytest.mark.skipif(
    not TRACE_BUNDLE_SCHEMA_PATH.exists(),
    reason="trace_runtime schemas not available in standalone LATTICE repo",
)
def test_signed_bundle_contract_is_trace_schema_compatible() -> None:
    bundle = _valid_signed_bundle()
    signed_validator = _signed_validator()
    signed_validator.validate(bundle)

    trace_schema = _load_json(TRACE_BUNDLE_SCHEMA_PATH)
    Draft202012Validator(trace_schema).validate(bundle)
