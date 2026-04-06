"""Tests for lattice.decision_tree_engine."""
from __future__ import annotations

from lattice.decision_tree_engine import (
    extract_safe_state_definitions,
    evaluate_guard_condition,
    select_transition_target,
    validate_decision_tree_payload,
    verify_safe_state_reachability,
)
from lattice.models import DecisionTree


def _valid_tree_payload() -> dict:
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


def test_validator_accepts_valid_tree_payload() -> None:
    result = validate_decision_tree_payload(_valid_tree_payload())
    assert result.ok is True
    assert result.errors == []


def test_validator_rejects_non_object_payload() -> None:
    result = validate_decision_tree_payload("bad-payload")  # type: ignore[arg-type]
    assert result.ok is False
    assert result.first_error == "decision_tree must be an object"


def test_validator_rejects_missing_start() -> None:
    payload = _valid_tree_payload()
    payload.pop("start")
    result = validate_decision_tree_payload(payload)
    assert result.ok is False
    assert result.first_error == "decision_tree.start is required"


def test_validator_rejects_duplicate_node_ids() -> None:
    payload = _valid_tree_payload()
    payload["nodes"].append({"id": "end", "kind": "END", "default": "end"})
    result = validate_decision_tree_payload(payload)
    assert result.ok is False
    assert "node ids must be unique" in result.errors


def test_validator_rejects_unknown_default_target() -> None:
    payload = _valid_tree_payload()
    payload["nodes"][0]["default"] = "missing"
    result = validate_decision_tree_payload(payload)
    assert result.ok is False
    assert "node 'exec' default target 'missing' is unknown" in result.errors


def test_validator_rejects_duplicate_signal_edges() -> None:
    payload = _valid_tree_payload()
    payload["nodes"][0]["edges"] = [
        {"when": {"signal": "DONE"}, "to": "end"},
        {"when": {"signal": "DONE"}, "to": "safe"},
    ]
    result = validate_decision_tree_payload(payload)
    assert result.ok is False
    assert "node 'exec' duplicate edge signal 'DONE'" in result.errors


def test_validator_rejects_unknown_edge_target() -> None:
    payload = _valid_tree_payload()
    payload["nodes"][0]["edges"][0]["to"] = "missing"
    result = validate_decision_tree_payload(payload)
    assert result.ok is False
    assert "node 'exec' edge target 'missing' is unknown" in result.errors


def test_validator_accepts_model_round_trip() -> None:
    tree = DecisionTree.from_dict(_valid_tree_payload())
    result = validate_decision_tree_payload(tree.to_dict())
    assert result.ok is True


def test_guard_evaluator_matches_signal_only_condition() -> None:
    condition = {"signal": "DONE"}
    assert evaluate_guard_condition(condition, signal="DONE", value=None) is True
    assert evaluate_guard_condition(condition, signal="HALT", value=None) is False


def test_guard_evaluator_matches_signal_and_value() -> None:
    condition = {"signal": "SWITCH_COA", "value": "TW_RATE"}
    assert evaluate_guard_condition(condition, signal="SWITCH_COA", value="TW_RATE") is True
    assert evaluate_guard_condition(condition, signal="SWITCH_COA", value="TW_OTHER") is False
    assert evaluate_guard_condition(condition, signal="SWITCH_COA", value=None) is False


def test_select_transition_target_uses_first_matching_edge() -> None:
    node = {
        "id": "exec",
        "kind": "EXECUTE_STEP",
        "default": "exec",
        "edges": [
            {"when": {"signal": "SWITCH_COA", "value": "TW_X"}, "to": "switch_x"},
            {"when": {"signal": "SWITCH_COA", "value": "TW_Y"}, "to": "switch_y"},
            {"when": {"signal": "DONE"}, "to": "end"},
        ],
    }
    assert select_transition_target(node, signal="SWITCH_COA", value="TW_Y") == "switch_y"
    assert select_transition_target(node, signal="DONE", value=None) == "end"
    assert select_transition_target(node, signal="HALT", value=None) is None


def test_safe_state_definition_extraction() -> None:
    tree = DecisionTree.from_dict(_valid_tree_payload())
    definitions = extract_safe_state_definitions(tree)
    assert "safe" in definitions
    assert definitions["safe"]["node_id"] == "safe"


def test_safe_state_reachability_accepts_reachable_tree() -> None:
    tree = DecisionTree.from_dict(_valid_tree_payload())
    result = verify_safe_state_reachability(tree)
    assert result.ok is True
    assert result.unreachable_nodes == []
    assert result.reachable_safe_state_nodes == ["safe"]


def test_safe_state_reachability_rejects_unreachable_node() -> None:
    payload = _valid_tree_payload()
    payload["nodes"].append({"id": "orphan", "kind": "END", "default": "orphan"})
    tree = DecisionTree.from_dict(payload)
    result = verify_safe_state_reachability(tree)
    assert result.ok is False
    assert "node 'orphan' is unreachable from start" in result.errors


def test_safe_state_reachability_rejects_safe_state_without_end_path() -> None:
    payload = _valid_tree_payload()
    payload["nodes"] = [
        {
            "id": "exec",
            "kind": "EXECUTE_STEP",
            "default": "safe",
            "edges": [{"when": {"signal": "DONE"}, "to": "safe"}],
        },
        {"id": "safe", "kind": "SAFE_STATE", "default": "safe"},
        {"id": "end", "kind": "END", "default": "end"},
    ]
    tree = DecisionTree.from_dict(payload)
    result = verify_safe_state_reachability(tree)
    assert result.ok is False
    assert "node 'end' is unreachable from start" in result.errors
    assert "SAFE_STATE node 'safe' cannot reach an END node" in result.errors
