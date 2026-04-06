"""Schema validation tests for LATTICE action bundles."""
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
    / "action_bundle.schema.json"
)


def _load_schema() -> dict:
    return json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))


def _valid_bundle() -> dict:
    return {
        "bundle_id": "AB-298-001",
        "target": "example.local",
        "tool": "dns_query",
        "tool_class": "RECON",
        "parameters": {"qname": "example.local", "qtype": "A"},
        "confidence_scores": {
            "objective_clarity": 0.9,
            "tool_specificity": 0.8,
            "constraint_completeness": 0.95,
            "risk_assessment_depth": 0.7,
            "precedent_availability": 0.6,
            "composite": 0.79,
        },
        "scope_tags": ["LAB"],
        "time_bound": "2026-12-31T00:00:00Z",
        "evidence_plan": {"evidence_level": "BASIC"},
    }


def test_schema_accepts_bundle_with_confidence_scores() -> None:
    schema = _load_schema()
    jsonschema.Draft202012Validator(schema).validate(_valid_bundle())


def test_schema_rejects_missing_confidence_scores() -> None:
    schema = _load_schema()
    bundle = _valid_bundle()
    bundle.pop("confidence_scores")
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.Draft202012Validator(schema).validate(bundle)


def test_schema_rejects_out_of_range_confidence_component() -> None:
    schema = _load_schema()
    bundle = _valid_bundle()
    bundle["confidence_scores"]["composite"] = 1.5
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.Draft202012Validator(schema).validate(bundle)
