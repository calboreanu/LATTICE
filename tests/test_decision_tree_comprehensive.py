"""Comprehensive decision-tree validation matrix (KAN-309)."""
from __future__ import annotations

import pytest

from lattice.decision_tree_engine import (
    evaluate_guard_condition,
    select_transition_target,
    validate_decision_tree_payload,
    verify_safe_state_reachability,
)
from lattice.models import DecisionTree


def _base_tree_payload() -> dict:
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


@pytest.mark.parametrize(
    ("case_id", "expected_substring"),
    [
        ("missing_start", "decision_tree.start is required"),
        ("blank_start", "decision_tree.start must be a non-empty string"),
        ("nodes_not_list", "decision_tree.nodes must be a list"),
        ("nodes_empty", "nodes must be non-empty"),
        ("node_not_object", "decision_tree.nodes[0] must be an object"),
        ("missing_node_id", "node.id is required"),
        ("missing_node_kind", "node.kind is required"),
        ("missing_node_default", "node.default is required"),
        ("invalid_node_kind", "NOT_A_KIND"),
        ("edges_not_list", "node.edges must be a list"),
        ("edge_not_object", "node.edges[0] must be an object"),
        ("edge_when_not_object", "edge.when must be an object"),
        ("edge_missing_to", "edge.to is required"),
        ("edge_missing_signal", "edge.when.signal is required"),
        ("edge_non_string_value", "edge.when.value must be a string"),
        ("duplicate_node_ids", "node ids must be unique"),
        ("unknown_default_target", "default target 'missing' is unknown"),
        ("duplicate_edge_signal", "duplicate edge signal"),
        ("unknown_edge_target", "edge target 'missing' is unknown"),
        ("start_not_in_nodes", "start node is not present in nodes"),
    ],
)
def test_decision_tree_payload_validation_matrix(
    case_id: str,
    expected_substring: str,
) -> None:
    payload = _base_tree_payload()

    if case_id == "missing_start":
        payload.pop("start")
    elif case_id == "blank_start":
        payload["start"] = "   "
    elif case_id == "nodes_not_list":
        payload["nodes"] = "bad-nodes"
    elif case_id == "nodes_empty":
        payload["nodes"] = []
    elif case_id == "node_not_object":
        payload["nodes"] = ["bad-node"]
    elif case_id == "missing_node_id":
        payload["nodes"][0].pop("id")
    elif case_id == "missing_node_kind":
        payload["nodes"][0].pop("kind")
    elif case_id == "missing_node_default":
        payload["nodes"][0].pop("default")
    elif case_id == "invalid_node_kind":
        payload["nodes"][0]["kind"] = "NOT_A_KIND"
    elif case_id == "edges_not_list":
        payload["nodes"][0]["edges"] = "bad-edges"
    elif case_id == "edge_not_object":
        payload["nodes"][0]["edges"] = ["bad-edge"]
    elif case_id == "edge_when_not_object":
        payload["nodes"][0]["edges"][0]["when"] = "bad-when"
    elif case_id == "edge_missing_to":
        payload["nodes"][0]["edges"][0].pop("to")
    elif case_id == "edge_missing_signal":
        payload["nodes"][0]["edges"][0]["when"] = {}
    elif case_id == "edge_non_string_value":
        payload["nodes"][0]["edges"][0]["when"]["value"] = 123
    elif case_id == "duplicate_node_ids":
        payload["nodes"].append({"id": "end", "kind": "END", "default": "end"})
    elif case_id == "unknown_default_target":
        payload["nodes"][0]["default"] = "missing"
    elif case_id == "duplicate_edge_signal":
        payload["nodes"][0]["edges"] = [
            {"when": {"signal": "DONE"}, "to": "end"},
            {"when": {"signal": "DONE"}, "to": "safe"},
        ]
    elif case_id == "unknown_edge_target":
        payload["nodes"][0]["edges"][0]["to"] = "missing"
    elif case_id == "start_not_in_nodes":
        payload["start"] = "missing"

    result = validate_decision_tree_payload(payload)
    assert result.ok is False
    assert any(expected_substring in error for error in result.errors)


@pytest.mark.parametrize(
    ("condition", "signal", "value", "expected"),
    [
        ({"signal": "DONE"}, "DONE", None, True),
        ({"signal": "DONE"}, "DONE", "x", True),
        ({"signal": "DONE"}, "HALT", None, False),
        ({"signal": "SWITCH_COA", "value": "TW_RATE"}, "SWITCH_COA", "TW_RATE", True),
        ({"signal": "SWITCH_COA", "value": "TW_RATE"}, "SWITCH_COA", "TW_OTHER", False),
        ({"signal": "SWITCH_COA", "value": "TW_RATE"}, "SWITCH_COA", None, False),
        ({"signal": "SWITCH_COA", "value": "TW_RATE"}, "ESCALATE", "TW_RATE", False),
        ({"signal": "HALT", "value": "max_step_attempts"}, "HALT", "max_step_attempts", True),
        ({"signal": "HALT", "value": "max_step_attempts"}, "HALT", "hitl_required", False),
        ({}, "DONE", None, False),
        ({"signal": ""}, "DONE", None, False),
        ({"signal": "ESCALATE", "value": 9}, "ESCALATE", "9", False),
    ],
)
def test_guard_evaluator_matrix(
    condition: dict,
    signal: str,
    value: str | None,
    expected: bool,
) -> None:
    assert evaluate_guard_condition(condition, signal=signal, value=value) is expected


@pytest.mark.parametrize(
    ("signal", "value", "expected_target"),
    [
        ("DONE", None, "end"),
        ("HALT", None, "safe"),
        ("SWITCH_COA", "TW_RATE", "switch_rate"),
        ("SWITCH_COA", "TW_OTHER", "switch_other"),
        ("SWITCH_COA", None, None),
        ("ESCALATE", None, None),
        ("DONE", "ignored", "end"),
    ],
)
def test_transition_selection_matrix(signal: str, value: str | None, expected_target: str | None) -> None:
    node = {
        "id": "exec",
        "kind": "EXECUTE_STEP",
        "default": "exec",
        "edges": [
            {"when": {"signal": "SWITCH_COA", "value": "TW_RATE"}, "to": "switch_rate"},
            {"when": {"signal": "SWITCH_COA", "value": "TW_OTHER"}, "to": "switch_other"},
            {"when": {"signal": "DONE"}, "to": "end"},
            {"when": {"signal": "HALT"}, "to": "safe"},
            "invalid-edge",
            {"when": "invalid-when", "to": "ignored"},
        ],
    }
    assert select_transition_target(node, signal=signal, value=value) == expected_target


@pytest.mark.parametrize(
    ("case_id", "expect_ok", "expected_substring"),
    [
        ("all_reachable", True, ""),
        ("orphan_node", False, "unreachable from start"),
        ("no_safe_state_nodes", True, ""),
        ("safe_state_unreachable", False, "no SAFE_STATE node is reachable from start"),
        ("safe_state_no_end_path", False, "cannot reach an END node"),
        ("start_missing_from_graph", False, "unreachable from start"),
        ("reachable_cycle", True, ""),
        ("multiple_safe_states_one_unreachable", False, "unreachable from start"),
    ],
)
def test_reachability_verification_matrix(
    case_id: str,
    expect_ok: bool,
    expected_substring: str,
) -> None:
    payload = _base_tree_payload()

    if case_id == "orphan_node":
        payload["nodes"].append({"id": "orphan", "kind": "END", "default": "orphan"})
    elif case_id == "no_safe_state_nodes":
        payload["nodes"] = [
            {
                "id": "exec",
                "kind": "EXECUTE_STEP",
                "default": "end",
                "edges": [{"when": {"signal": "DONE"}, "to": "end"}],
            },
            {"id": "end", "kind": "END", "default": "end"},
        ]
    elif case_id == "safe_state_unreachable":
        payload["nodes"] = [
            {
                "id": "exec",
                "kind": "EXECUTE_STEP",
                "default": "end",
                "edges": [{"when": {"signal": "DONE"}, "to": "end"}],
            },
            {"id": "end", "kind": "END", "default": "end"},
            {"id": "safe", "kind": "SAFE_STATE", "default": "end"},
        ]
    elif case_id == "safe_state_no_end_path":
        payload["nodes"] = [
            {
                "id": "exec",
                "kind": "EXECUTE_STEP",
                "default": "safe",
                "edges": [{"when": {"signal": "HALT"}, "to": "safe"}],
            },
            {"id": "safe", "kind": "SAFE_STATE", "default": "safe"},
            {"id": "end", "kind": "END", "default": "end"},
        ]
    elif case_id == "start_missing_from_graph":
        payload["start"] = "missing"
    elif case_id == "reachable_cycle":
        payload["nodes"] = [
            {
                "id": "exec",
                "kind": "EXECUTE_STEP",
                "default": "safe",
                "edges": [{"when": {"signal": "DONE"}, "to": "end"}],
            },
            {"id": "safe", "kind": "SAFE_STATE", "default": "exec"},
            {"id": "end", "kind": "END", "default": "end"},
        ]
    elif case_id == "multiple_safe_states_one_unreachable":
        payload["nodes"] = [
            {
                "id": "exec",
                "kind": "EXECUTE_STEP",
                "default": "safe_a",
                "edges": [{"when": {"signal": "DONE"}, "to": "end"}],
            },
            {"id": "safe_a", "kind": "SAFE_STATE", "default": "end"},
            {"id": "safe_b", "kind": "SAFE_STATE", "default": "end"},
            {"id": "end", "kind": "END", "default": "end"},
        ]

    tree = DecisionTree.from_dict(payload)
    result = verify_safe_state_reachability(tree)
    assert result.ok is expect_ok
    if expected_substring:
        assert any(expected_substring in error for error in result.errors)
