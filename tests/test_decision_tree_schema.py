"""Schema validation tests for LATTICE decision trees."""
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
    / "decision_tree.schema.json"
)


def _load_schema() -> dict:
    return json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))


def _valid_tree() -> dict:
    return {
        "start": "exec",
        "nodes": [
            {
                "id": "exec",
                "kind": "EXECUTE_STEP",
                "default": "exec",
                "edges": [
                    {"when": {"signal": "DONE"}, "to": "end"},
                    {"when": {"signal": "HALT"}, "to": "safe"},
                ],
            },
            {"id": "safe", "kind": "SAFE_STATE", "default": "end"},
            {"id": "end", "kind": "END", "default": "end"},
        ],
    }


def test_schema_accepts_valid_decision_tree() -> None:
    schema = _load_schema()
    jsonschema.Draft202012Validator(schema).validate(_valid_tree())


def test_schema_rejects_node_missing_default() -> None:
    schema = _load_schema()
    tree = _valid_tree()
    tree["nodes"][0].pop("default")
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.Draft202012Validator(schema).validate(tree)


def test_schema_rejects_invalid_node_kind() -> None:
    schema = _load_schema()
    tree = _valid_tree()
    tree["nodes"][0]["kind"] = "INVALID_KIND"
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.Draft202012Validator(schema).validate(tree)


def test_schema_rejects_edge_without_signal() -> None:
    schema = _load_schema()
    tree = _valid_tree()
    tree["nodes"][0]["edges"][0]["when"] = {}
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.Draft202012Validator(schema).validate(tree)


def test_schema_rejects_additional_properties() -> None:
    schema = _load_schema()
    tree = _valid_tree()
    tree["nodes"][0]["unexpected_field"] = True
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.Draft202012Validator(schema).validate(tree)
