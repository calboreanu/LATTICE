"""Schema tests for LATTICE policy bundle rule definitions."""
from __future__ import annotations

import json
from pathlib import Path

import jsonschema
import pytest


SCHEMA_PATH = (
    Path(__file__).parent.parent
    / "src"
    / "lattice"
    / "schemas"
    / "policy_bundle.schema.json"
)


def _load_schema() -> dict:
    return json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))


def _valid_policy_bundle() -> dict:
    return {
        "policy_id": "POL-302-001",
        "version": "1.0",
        "allowed_targets": ["acme.example.com"],
        "permitted_tools": {"DEFAULT": ["echo"]},
        "rules": [
            {
                "rule_id": "R1",
                "type": "TOOL_DENYLIST",
                "effect": "ESCALATE",
                "values": ["nmap"],
            }
        ],
        "thresholds": {"autonomous": 85, "hitl": 65, "escalate": 45},
    }


def test_schema_accepts_policy_with_structured_rules() -> None:
    schema = _load_schema()
    jsonschema.Draft202012Validator(schema).validate(_valid_policy_bundle())


def test_schema_rejects_rule_missing_type() -> None:
    schema = _load_schema()
    policy = _valid_policy_bundle()
    policy["rules"][0].pop("type")
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.Draft202012Validator(schema).validate(policy)


def test_schema_rejects_rule_with_invalid_effect() -> None:
    schema = _load_schema()
    policy = _valid_policy_bundle()
    policy["rules"][0]["effect"] = "INVALID"
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.Draft202012Validator(schema).validate(policy)
