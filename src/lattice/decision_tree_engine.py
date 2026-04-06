"""Decision-tree validation and totality checks for LATTICE."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Set

from .models import DecisionNodeKind, DecisionTree, DecisionTreeEdgeCondition


@dataclass(frozen=True)
class DecisionTreeValidationResult:
    ok: bool
    errors: List[str]

    @property
    def first_error(self) -> str:
        return self.errors[0] if self.errors else ""


@dataclass(frozen=True)
class SafeStateVerificationResult:
    ok: bool
    errors: List[str]
    reachable_nodes: List[str]
    unreachable_nodes: List[str]
    safe_state_nodes: List[str]
    reachable_safe_state_nodes: List[str]

    @property
    def first_error(self) -> str:
        return self.errors[0] if self.errors else ""


def validate_decision_tree_payload(payload: Dict[str, Any]) -> DecisionTreeValidationResult:
    """
    Parse and validate a decision tree payload.

    Validation scope for KAN-306:
    - schema-shape parseability into DecisionTree model
    - deterministic totality constraints from DecisionTree.validate_totality()
    """
    if not isinstance(payload, dict):
        return DecisionTreeValidationResult(False, ["decision_tree must be an object"])

    try:
        tree = DecisionTree.from_dict(payload)
    except Exception as exc:
        return DecisionTreeValidationResult(False, [str(exc)])

    return validate_decision_tree(tree)


def validate_decision_tree(tree: DecisionTree) -> DecisionTreeValidationResult:
    errors = tree.validate_totality()
    return DecisionTreeValidationResult(ok=not errors, errors=errors)


def evaluate_guard_condition(
    condition: Dict[str, Any] | DecisionTreeEdgeCondition,
    *,
    signal: str,
    value: Optional[str] = None,
) -> bool:
    """Evaluate a single edge guard against runtime signal/value."""
    try:
        parsed = (
            condition
            if isinstance(condition, DecisionTreeEdgeCondition)
            else DecisionTreeEdgeCondition.from_dict(condition)
        )
    except Exception:
        return False

    if parsed.signal != signal:
        return False
    if parsed.value is None:
        return True
    return value is not None and parsed.value == value


def select_transition_target(
    node_payload: Dict[str, Any],
    *,
    signal: str,
    value: Optional[str] = None,
) -> Optional[str]:
    """
    Select the first transition target whose guard matches signal/value.

    Returns None when no edge matches.
    """
    raw_edges = node_payload.get("edges") or []
    if not isinstance(raw_edges, list):
        return None
    for edge in raw_edges:
        if not isinstance(edge, dict):
            continue
        when = edge.get("when")
        if not isinstance(when, dict):
            continue
        if evaluate_guard_condition(when, signal=signal, value=value):
            to = edge.get("to")
            return str(to) if isinstance(to, str) and to else None
    return None


def extract_safe_state_definitions(tree: DecisionTree) -> Dict[str, Dict[str, str]]:
    """Extract SAFE_STATE node definitions from a parsed tree."""
    definitions: Dict[str, Dict[str, str]] = {}
    for node in tree.nodes:
        if node.kind is DecisionNodeKind.SAFE_STATE:
            definitions[node.id] = {
                "node_id": node.id,
                "description": node.description,
            }
    return definitions


def _build_graph(tree: DecisionTree) -> Dict[str, Set[str]]:
    graph: Dict[str, Set[str]] = {}
    for node in tree.nodes:
        outgoing: Set[str] = {node.default}
        for edge in node.edges:
            outgoing.add(edge.to)
        graph[node.id] = outgoing
    return graph


def _reachable_from(graph: Dict[str, Set[str]], start: str) -> Set[str]:
    if start not in graph:
        return set()
    visited: Set[str] = set()
    queue: List[str] = [start]
    while queue:
        node_id = queue.pop(0)
        if node_id in visited:
            continue
        visited.add(node_id)
        for nxt in graph.get(node_id, set()):
            if nxt not in visited and nxt in graph:
                queue.append(nxt)
    return visited


def verify_safe_state_reachability(tree: DecisionTree) -> SafeStateVerificationResult:
    """
    Verify structural reachability and SAFE_STATE connectivity.

    KAN-308 checks:
    - all nodes are reachable from start (no dead/unreferenced states)
    - SAFE_STATE nodes, when present, are reachable from start
    - each SAFE_STATE node can eventually reach an END node
    """
    graph = _build_graph(tree)
    all_nodes: Set[str] = set(graph.keys())
    reachable = _reachable_from(graph, tree.start)
    unreachable = sorted(all_nodes - reachable)

    safe_state_nodes = sorted(
        [node.id for node in tree.nodes if node.kind is DecisionNodeKind.SAFE_STATE]
    )
    reachable_safe = sorted([node_id for node_id in safe_state_nodes if node_id in reachable])
    end_nodes = {node.id for node in tree.nodes if node.kind is DecisionNodeKind.END}

    errors: List[str] = []
    for node_id in unreachable:
        errors.append(f"node '{node_id}' is unreachable from start")

    if safe_state_nodes and not reachable_safe:
        errors.append("no SAFE_STATE node is reachable from start")

    for safe_node in safe_state_nodes:
        safe_reachable = _reachable_from(graph, safe_node)
        if end_nodes and not safe_reachable.intersection(end_nodes):
            errors.append(f"SAFE_STATE node '{safe_node}' cannot reach an END node")

    return SafeStateVerificationResult(
        ok=not errors,
        errors=errors,
        reachable_nodes=sorted(reachable),
        unreachable_nodes=unreachable,
        safe_state_nodes=safe_state_nodes,
        reachable_safe_state_nodes=reachable_safe,
    )
