"""Tests for lattice.models.DecisionTree primitives."""
from __future__ import annotations

import pytest

from lattice.models import DecisionNodeKind, DecisionTree


def _valid_tree_dict() -> dict:
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


def test_decision_tree_round_trip_and_totality_valid() -> None:
    payload = _valid_tree_dict()
    tree = DecisionTree.from_dict(payload)

    assert tree.start == "exec"
    assert tree.nodes[0].kind is DecisionNodeKind.EXECUTE_STEP
    assert tree.validate_totality() == []
    assert tree.to_dict() == payload


def test_decision_tree_totality_rejects_unknown_start_node() -> None:
    payload = _valid_tree_dict()
    payload["start"] = "missing-node"

    tree = DecisionTree.from_dict(payload)
    errors = tree.validate_totality()

    assert "start node is not present in nodes" in errors


def test_decision_tree_totality_rejects_duplicate_edge_signals() -> None:
    payload = _valid_tree_dict()
    payload["nodes"][0]["edges"] = [
        {"when": {"signal": "DONE"}, "to": "end"},
        {"when": {"signal": "DONE"}, "to": "safe"},
    ]

    tree = DecisionTree.from_dict(payload)
    errors = tree.validate_totality()

    assert "node 'exec' duplicate edge signal 'DONE'" in errors


def test_decision_tree_from_dict_rejects_invalid_kind() -> None:
    payload = _valid_tree_dict()
    payload["nodes"][0]["kind"] = "NOT_A_KIND"

    with pytest.raises(ValueError):
        DecisionTree.from_dict(payload)


def test_decision_tree_from_dict_rejects_non_object_node() -> None:
    payload = _valid_tree_dict()
    payload["nodes"] = ["bad-node"]

    with pytest.raises(ValueError, match="decision_tree.nodes\\[0\\] must be an object"):
        DecisionTree.from_dict(payload)
