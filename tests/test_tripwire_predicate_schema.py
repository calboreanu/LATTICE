"""Schema validation tests for LATTICE tripwire predicates."""
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
    / "tripwire_predicate.schema.json"
)


def _load_schema() -> dict:
    return json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))


def _valid_predicate() -> dict:
    return {
        "predicate_id": "TW-300-ARI",
        "metric": "ARI",
        "operator": "GTE",
        "threshold": 0.4,
        "on_trigger": "HALT",
        "window": {"kind": "TIME_SECONDS", "size": 30},
        "enabled": True,
        "parameters": {"note": "test"},
    }


def test_schema_accepts_valid_tripwire_predicate() -> None:
    schema = _load_schema()
    jsonschema.Draft202012Validator(schema).validate(_valid_predicate())


def test_schema_rejects_missing_required_field() -> None:
    schema = _load_schema()
    predicate = _valid_predicate()
    predicate.pop("metric")
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.Draft202012Validator(schema).validate(predicate)


def test_schema_rejects_invalid_metric() -> None:
    schema = _load_schema()
    predicate = _valid_predicate()
    predicate["metric"] = "UNKNOWN_METRIC"
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.Draft202012Validator(schema).validate(predicate)


def test_schema_rejects_invalid_window_size() -> None:
    schema = _load_schema()
    predicate = _valid_predicate()
    predicate["window"]["size"] = 0
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.Draft202012Validator(schema).validate(predicate)


def test_schema_rejects_additional_properties() -> None:
    schema = _load_schema()
    predicate = _valid_predicate()
    predicate["unexpected"] = "field"
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.Draft202012Validator(schema).validate(predicate)
