"""Core data models for the LATTICE authorization layer."""
from __future__ import annotations

import math
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


def _bounded_unit(value: float, name: str) -> float:
    v = float(value)
    if not (0.0 <= v <= 1.0):
        raise ValueError(f"{name} must be in [0.0, 1.0], got {value!r}")
    return v


def _non_empty_string(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a non-empty string")
    return value


@dataclass
class ConfidenceScore:
    """
    Five-component confidence model used by LATTICE planning/governance.

    Components are normalized to [0.0, 1.0].
    """

    objective_clarity: float
    tool_specificity: float
    constraint_completeness: float
    risk_assessment_depth: float
    precedent_availability: float
    composite: Optional[float] = None

    def __post_init__(self) -> None:
        self.objective_clarity = _bounded_unit(
            self.objective_clarity,
            "objective_clarity",
        )
        self.tool_specificity = _bounded_unit(
            self.tool_specificity,
            "tool_specificity",
        )
        self.constraint_completeness = _bounded_unit(
            self.constraint_completeness,
            "constraint_completeness",
        )
        self.risk_assessment_depth = _bounded_unit(
            self.risk_assessment_depth,
            "risk_assessment_depth",
        )
        self.precedent_availability = _bounded_unit(
            self.precedent_availability,
            "precedent_availability",
        )
        if self.composite is None:
            self.composite = self.compute_composite()
        else:
            self.composite = _bounded_unit(self.composite, "composite")

    def compute_composite(
        self,
        *,
        weights: Optional[Dict[str, float]] = None,
    ) -> float:
        """Compute weighted composite confidence in [0.0, 1.0]."""
        components = {
            "objective_clarity": self.objective_clarity,
            "tool_specificity": self.tool_specificity,
            "constraint_completeness": self.constraint_completeness,
            "risk_assessment_depth": self.risk_assessment_depth,
            "precedent_availability": self.precedent_availability,
        }

        if not weights:
            return sum(components.values()) / len(components)

        total_weight = 0.0
        weighted_sum = 0.0
        for key, value in components.items():
            w = float(weights.get(key, 0.0))
            if w < 0:
                raise ValueError(f"weight for {key} must be >= 0.0")
            total_weight += w
            weighted_sum += w * value

        if total_weight <= 0.0:
            raise ValueError("weights must sum to > 0.0")

        return weighted_sum / total_weight

    def to_dict(self) -> Dict[str, float]:
        return {
            "objective_clarity": self.objective_clarity,
            "tool_specificity": self.tool_specificity,
            "constraint_completeness": self.constraint_completeness,
            "risk_assessment_depth": self.risk_assessment_depth,
            "precedent_availability": self.precedent_availability,
            "composite": self.composite if self.composite is not None else self.compute_composite(),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ConfidenceScore":
        return cls(
            objective_clarity=float(data["objective_clarity"]),
            tool_specificity=float(data["tool_specificity"]),
            constraint_completeness=float(data["constraint_completeness"]),
            risk_assessment_depth=float(data["risk_assessment_depth"]),
            precedent_availability=float(data["precedent_availability"]),
            composite=float(data["composite"]) if "composite" in data else None,
        )


class DecisionNodeKind(str, Enum):
    """Supported node kinds for decision-tree execution graphs."""

    EXECUTE_STEP = "EXECUTE_STEP"
    ESCALATE_CONTAINMENT = "ESCALATE_CONTAINMENT"
    SWITCH_COA = "SWITCH_COA"
    SAFE_STATE = "SAFE_STATE"
    END = "END"


@dataclass
class DecisionTreeEdgeCondition:
    """Guard condition for an edge transition."""

    signal: str
    value: Optional[str] = None

    def to_dict(self) -> Dict[str, str]:
        payload: Dict[str, str] = {"signal": self.signal}
        if self.value is not None:
            payload["value"] = self.value
        return payload

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "DecisionTreeEdgeCondition":
        if "signal" not in data:
            raise ValueError("edge.when.signal is required")
        raw_value = data.get("value")
        if raw_value is not None and not isinstance(raw_value, str):
            raise ValueError("edge.when.value must be a string when provided")
        return cls(
            signal=_non_empty_string(data["signal"], "edge.when.signal"),
            value=raw_value,
        )


@dataclass
class DecisionTreeEdge:
    """Directed transition edge between two decision-tree nodes."""

    when: DecisionTreeEdgeCondition
    to: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "when": self.when.to_dict(),
            "to": self.to,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "DecisionTreeEdge":
        when = data.get("when", {})
        if not isinstance(when, dict):
            raise ValueError("edge.when must be an object")
        if "to" not in data:
            raise ValueError("edge.to is required")
        return cls(
            when=DecisionTreeEdgeCondition.from_dict(when),
            to=_non_empty_string(data["to"], "edge.to"),
        )


@dataclass
class DecisionTreeNode:
    """Node in a deterministic decision tree."""

    id: str
    kind: DecisionNodeKind
    default: str
    edges: List[DecisionTreeEdge] = field(default_factory=list)
    description: str = ""

    def to_dict(self) -> Dict[str, Any]:
        payload: Dict[str, Any] = {
            "id": self.id,
            "kind": self.kind.value,
            "default": self.default,
        }
        if self.description:
            payload["description"] = self.description
        if self.edges:
            payload["edges"] = [edge.to_dict() for edge in self.edges]
        return payload

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "DecisionTreeNode":
        if "id" not in data:
            raise ValueError("node.id is required")
        if "kind" not in data:
            raise ValueError("node.kind is required")
        if "default" not in data:
            raise ValueError("node.default is required")
        raw_edges = data.get("edges", [])
        if not isinstance(raw_edges, list):
            raise ValueError("node.edges must be a list")
        parsed_edges: List[DecisionTreeEdge] = []
        for idx, edge in enumerate(raw_edges):
            if not isinstance(edge, dict):
                raise ValueError(f"node.edges[{idx}] must be an object")
            parsed_edges.append(DecisionTreeEdge.from_dict(edge))
        return cls(
            id=_non_empty_string(data["id"], "node.id"),
            kind=DecisionNodeKind(str(data["kind"])),
            default=_non_empty_string(data["default"], "node.default"),
            edges=parsed_edges,
            description=str(data.get("description", "")),
        )


@dataclass
class DecisionTree:
    """Deterministic decision tree with totality checks."""

    start: str
    nodes: List[DecisionTreeNode]

    def validate_totality(self) -> List[str]:
        """
        Validate deterministic totality constraints.

        Returns:
            List of validation errors (empty when valid).
        """
        errors: List[str] = []
        if not self.nodes:
            errors.append("nodes must be non-empty")
            return errors

        node_ids = [node.id for node in self.nodes]
        if self.start not in node_ids:
            errors.append("start node is not present in nodes")

        if len(set(node_ids)) != len(node_ids):
            errors.append("node ids must be unique")

        known_ids = set(node_ids)
        for node in self.nodes:
            if not node.default:
                errors.append(f"node '{node.id}' missing default target")
            elif node.default not in known_ids:
                errors.append(f"node '{node.id}' default target '{node.default}' is unknown")

            seen_signals = set()
            for edge in node.edges:
                signal = edge.when.signal
                if signal in seen_signals:
                    errors.append(f"node '{node.id}' duplicate edge signal '{signal}'")
                seen_signals.add(signal)
                if edge.to not in known_ids:
                    errors.append(f"node '{node.id}' edge target '{edge.to}' is unknown")

        return errors

    def to_dict(self) -> Dict[str, Any]:
        return {
            "start": self.start,
            "nodes": [node.to_dict() for node in self.nodes],
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "DecisionTree":
        if "start" not in data:
            raise ValueError("decision_tree.start is required")
        raw_nodes = data.get("nodes", [])
        if not isinstance(raw_nodes, list):
            raise ValueError("decision_tree.nodes must be a list")
        parsed_nodes: List[DecisionTreeNode] = []
        for idx, node in enumerate(raw_nodes):
            if not isinstance(node, dict):
                raise ValueError(f"decision_tree.nodes[{idx}] must be an object")
            parsed_nodes.append(DecisionTreeNode.from_dict(node))
        return cls(
            start=_non_empty_string(data["start"], "decision_tree.start"),
            nodes=parsed_nodes,
        )


class TripwireMetric(str, Enum):
    """Standard metrics used by tripwire predicates."""

    ARI = "ARI"
    PRDS = "PRDS"
    TMD = "TMD"
    RATE = "RATE"
    VOLUME = "VOLUME"
    DURATION = "DURATION"
    ERROR_RATE = "ERROR_RATE"
    UNAUTHORIZED_TOOL_ATTEMPTS = "UNAUTHORIZED_TOOL_ATTEMPTS"


class TripwireOperator(str, Enum):
    """Comparison operators for threshold predicates."""

    GT = "GT"
    GTE = "GTE"
    LT = "LT"
    LTE = "LTE"
    EQ = "EQ"
    NEQ = "NEQ"


class TripwireDecision(str, Enum):
    """Containment decision produced when a predicate fires."""

    CONTINUE = "CONTINUE"
    ESCALATE = "ESCALATE"
    HALT = "HALT"


class TripwireWindowKind(str, Enum):
    """Windowing modes for deterministic predicate evaluation."""

    EVENT_COUNT = "EVENT_COUNT"
    TIME_SECONDS = "TIME_SECONDS"


@dataclass
class TripwireWindow:
    """Window specification for tripwire evaluation."""

    kind: TripwireWindowKind
    size: int

    def __post_init__(self) -> None:
        if int(self.size) <= 0:
            raise ValueError("tripwire window size must be > 0")
        self.size = int(self.size)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "kind": self.kind.value,
            "size": self.size,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "TripwireWindow":
        if "kind" not in data:
            raise ValueError("tripwire window kind is required")
        if "size" not in data:
            raise ValueError("tripwire window size is required")
        return cls(
            kind=TripwireWindowKind(str(data["kind"])),
            size=int(data["size"]),
        )


@dataclass
class TripwirePredicate:
    """Specification-level tripwire predicate contract."""

    predicate_id: str
    metric: TripwireMetric
    operator: TripwireOperator
    threshold: float
    on_trigger: TripwireDecision
    window: TripwireWindow
    enabled: bool = True
    description: str = ""
    rationale: str = ""
    parameters: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.predicate_id = _non_empty_string(self.predicate_id, "predicate_id")
        self.threshold = float(self.threshold)
        if not math.isfinite(self.threshold):
            raise ValueError("threshold must be finite")
        if not isinstance(self.parameters, dict):
            raise ValueError("parameters must be an object")

    def to_dict(self) -> Dict[str, Any]:
        payload: Dict[str, Any] = {
            "predicate_id": self.predicate_id,
            "metric": self.metric.value,
            "operator": self.operator.value,
            "threshold": self.threshold,
            "on_trigger": self.on_trigger.value,
            "window": self.window.to_dict(),
            "enabled": self.enabled,
        }
        if self.description:
            payload["description"] = self.description
        if self.rationale:
            payload["rationale"] = self.rationale
        if self.parameters:
            payload["parameters"] = dict(self.parameters)
        return payload

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "TripwirePredicate":
        if "window" not in data or not isinstance(data["window"], dict):
            raise ValueError("window is required and must be an object")
        return cls(
            predicate_id=str(data.get("predicate_id", "")),
            metric=TripwireMetric(str(data.get("metric", ""))),
            operator=TripwireOperator(str(data.get("operator", ""))),
            threshold=float(data["threshold"]),
            on_trigger=TripwireDecision(str(data.get("on_trigger", ""))),
            window=TripwireWindow.from_dict(data["window"]),
            enabled=bool(data.get("enabled", True)),
            description=str(data.get("description", "")),
            rationale=str(data.get("rationale", "")),
            parameters=dict(data.get("parameters", {})),
        )


@dataclass
class BundleSignature:
    """Governance signature metadata for an approved bundle."""

    alg: str
    pubkey_id: str
    sig_b64: str

    def __post_init__(self) -> None:
        self.alg = _non_empty_string(self.alg, "signature.alg")
        self.pubkey_id = _non_empty_string(self.pubkey_id, "signature.pubkey_id")
        self.sig_b64 = _non_empty_string(self.sig_b64, "signature.sig_b64")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "alg": self.alg,
            "pubkey_id": self.pubkey_id,
            "sig_b64": self.sig_b64,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "BundleSignature":
        return cls(
            alg=str(data.get("alg", "")),
            pubkey_id=str(data.get("pubkey_id", "")),
            sig_b64=str(data.get("sig_b64", "")),
        )


@dataclass
class MandateInputReference:
    """Optional embedded MANDATE provenance contract."""

    mandate_id: str
    version: str
    anchor_hash: str
    trace_chain_hash: str
    selected_coa: str = ""
    fallback_sequence: List[str] = field(default_factory=list)
    artifact: Optional[Dict[str, Any]] = None

    def __post_init__(self) -> None:
        self.mandate_id = _non_empty_string(self.mandate_id, "inputs.mandate.mandate_id")
        self.version = _non_empty_string(self.version, "inputs.mandate.version")
        self.anchor_hash = _non_empty_string(self.anchor_hash, "inputs.mandate.anchor_hash")
        self.trace_chain_hash = _non_empty_string(self.trace_chain_hash, "inputs.mandate.trace_chain_hash")
        self.fallback_sequence = [str(x) for x in self.fallback_sequence]
        if self.artifact is not None and not isinstance(self.artifact, dict):
            raise ValueError("inputs.mandate.artifact must be an object when provided")

    def to_dict(self) -> Dict[str, Any]:
        payload: Dict[str, Any] = {
            "mandate_id": self.mandate_id,
            "version": self.version,
            "anchor_hash": self.anchor_hash,
            "trace_chain_hash": self.trace_chain_hash,
        }
        if self.selected_coa:
            payload["selected_coa"] = self.selected_coa
        if self.fallback_sequence:
            payload["fallback_sequence"] = list(self.fallback_sequence)
        if self.artifact is not None:
            payload["artifact"] = dict(self.artifact)
        return payload

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "MandateInputReference":
        fallback = data.get("fallback_sequence", [])
        if fallback is None:
            fallback = []
        if not isinstance(fallback, list):
            raise ValueError("inputs.mandate.fallback_sequence must be a list")
        return cls(
            mandate_id=str(data.get("mandate_id", "")),
            version=str(data.get("version", "")),
            anchor_hash=str(data.get("anchor_hash", "")),
            trace_chain_hash=str(data.get("trace_chain_hash", "")),
            selected_coa=str(data.get("selected_coa", "")),
            fallback_sequence=[str(x) for x in fallback],
            artifact=dict(data["artifact"]) if isinstance(data.get("artifact"), dict) else None,
        )


@dataclass
class LatticePolicyInputReference:
    """Optional embedded LATTICE policy provenance contract."""

    policy_id: str
    version: str
    policy_hash: str = ""
    policy: Optional[Dict[str, Any]] = None

    def __post_init__(self) -> None:
        self.policy_id = _non_empty_string(self.policy_id, "inputs.lattice_policy.policy_id")
        self.version = _non_empty_string(self.version, "inputs.lattice_policy.version")
        if self.policy is not None and not isinstance(self.policy, dict):
            raise ValueError("inputs.lattice_policy.policy must be an object when provided")

    def to_dict(self) -> Dict[str, Any]:
        payload: Dict[str, Any] = {
            "policy_id": self.policy_id,
            "version": self.version,
        }
        if self.policy_hash:
            payload["policy_hash"] = self.policy_hash
        if self.policy is not None:
            payload["policy"] = dict(self.policy)
        return payload

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "LatticePolicyInputReference":
        return cls(
            policy_id=str(data.get("policy_id", "")),
            version=str(data.get("version", "")),
            policy_hash=str(data.get("policy_hash", "")),
            policy=dict(data["policy"]) if isinstance(data.get("policy"), dict) else None,
        )


@dataclass
class CrossLayerInputs:
    """Cross-layer contract between MANDATE/LATTICE and TRACE runtime."""

    mandate: Optional[MandateInputReference] = None
    lattice_policy: Optional[LatticePolicyInputReference] = None

    def to_dict(self) -> Dict[str, Any]:
        payload: Dict[str, Any] = {}
        if self.mandate is not None:
            payload["mandate"] = self.mandate.to_dict()
        if self.lattice_policy is not None:
            payload["lattice_policy"] = self.lattice_policy.to_dict()
        return payload

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CrossLayerInputs":
        mandate_data = data.get("mandate")
        lattice_data = data.get("lattice_policy")
        return cls(
            mandate=MandateInputReference.from_dict(mandate_data) if isinstance(mandate_data, dict) else None,
            lattice_policy=LatticePolicyInputReference.from_dict(lattice_data) if isinstance(lattice_data, dict) else None,
        )


@dataclass
class SignedApprovedBundle:
    """LATTICE output contract handed to TRACE for deterministic execution."""

    bundle_id: str
    bundle_hash: str
    safe_state_id: str
    authorized_tools: List[str]
    tool_hashes: Dict[str, str]
    constraints: Dict[str, Any]
    coa: Dict[str, Any]
    decision_tree: DecisionTree
    signature: BundleSignature
    bundle_version: str = ""
    inputs: Optional[CrossLayerInputs] = None
    tripwire_predicates: List[TripwirePredicate] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.bundle_id = _non_empty_string(self.bundle_id, "bundle_id")
        self.bundle_hash = _non_empty_string(self.bundle_hash, "bundle_hash")
        self.safe_state_id = _non_empty_string(self.safe_state_id, "safe_state_id")
        if not self.authorized_tools:
            raise ValueError("authorized_tools must be non-empty")
        self.authorized_tools = [_non_empty_string(t, "authorized_tools[]") for t in self.authorized_tools]
        if not isinstance(self.tool_hashes, dict):
            raise ValueError("tool_hashes must be an object")
        if not isinstance(self.constraints, dict):
            raise ValueError("constraints must be an object")
        if not isinstance(self.coa, dict):
            raise ValueError("coa must be an object")

    def validate_cross_layer_contracts(self) -> List[str]:
        errors: List[str] = []

        missing_hashes = [t for t in self.authorized_tools if t not in self.tool_hashes]
        for tool_id in missing_hashes:
            errors.append(f"tool_hashes missing entry for authorized tool '{tool_id}'")

        coa_entries = self.coa.get("coas", [])
        if not isinstance(coa_entries, list) or not coa_entries:
            errors.append("coa.coas must be a non-empty list")
            return errors

        coa_ids = {
            str(entry.get("coa_id"))
            for entry in coa_entries
            if isinstance(entry, dict) and entry.get("coa_id")
        }
        default_coa = self.coa.get("default_coa_id")
        if str(default_coa) not in coa_ids:
            errors.append("coa.default_coa_id must reference a known COA")

        fallback_seq = self.coa.get("fallback_sequence", [])
        if fallback_seq is None:
            fallback_seq = []
        if not isinstance(fallback_seq, list):
            errors.append("coa.fallback_sequence must be a list")
            fallback_seq = []
        for coa_id in fallback_seq:
            if str(coa_id) not in coa_ids:
                errors.append(f"coa.fallback_sequence references unknown COA '{coa_id}'")

        for coa_entry in coa_entries:
            if not isinstance(coa_entry, dict):
                errors.append("coa entry must be an object")
                continue
            steps = coa_entry.get("steps", [])
            if not isinstance(steps, list):
                errors.append(f"coa '{coa_entry.get('coa_id')}' steps must be a list")
                continue
            for step in steps:
                if not isinstance(step, dict):
                    errors.append(f"coa '{coa_entry.get('coa_id')}' step must be an object")
                    continue
                tool_id = step.get("tool_id")
                if not isinstance(tool_id, str) or not tool_id:
                    errors.append(f"coa '{coa_entry.get('coa_id')}' step missing tool_id")
                    continue
                if tool_id not in self.authorized_tools:
                    errors.append(f"coa '{coa_entry.get('coa_id')}' uses unauthorized tool '{tool_id}'")

        errors.extend(self.decision_tree.validate_totality())

        predicate_ids: List[str] = [predicate.predicate_id for predicate in self.tripwire_predicates]
        if len(set(predicate_ids)) != len(predicate_ids):
            errors.append("tripwire_predicates must have unique predicate_id values")

        if self.inputs is not None and self.inputs.mandate is not None:
            if self.inputs.mandate.selected_coa and self.inputs.mandate.selected_coa not in coa_ids:
                errors.append("inputs.mandate.selected_coa must reference a known COA")
            for coa_id in self.inputs.mandate.fallback_sequence:
                if coa_id not in coa_ids:
                    errors.append(f"inputs.mandate.fallback_sequence references unknown COA '{coa_id}'")

        return errors

    def to_dict(self) -> Dict[str, Any]:
        payload: Dict[str, Any] = {
            "bundle_id": self.bundle_id,
            "bundle_hash": self.bundle_hash,
            "safe_state_id": self.safe_state_id,
            "authorized_tools": list(self.authorized_tools),
            "tool_hashes": dict(self.tool_hashes),
            "constraints": dict(self.constraints),
            "coa": dict(self.coa),
            "decision_tree": self.decision_tree.to_dict(),
            "signature": self.signature.to_dict(),
        }
        if self.bundle_version:
            payload["bundle_version"] = self.bundle_version
        if self.inputs is not None:
            payload["inputs"] = self.inputs.to_dict()
        if self.tripwire_predicates:
            payload["tripwire_predicates"] = [predicate.to_dict() for predicate in self.tripwire_predicates]
        return payload

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SignedApprovedBundle":
        if "decision_tree" not in data or not isinstance(data["decision_tree"], dict):
            raise ValueError("decision_tree is required and must be an object")
        if "signature" not in data or not isinstance(data["signature"], dict):
            raise ValueError("signature is required and must be an object")
        inputs = data.get("inputs")
        predicates = data.get("tripwire_predicates", [])
        if predicates is None:
            predicates = []
        if not isinstance(predicates, list):
            raise ValueError("tripwire_predicates must be a list")
        parsed_predicates: List[TripwirePredicate] = []
        for idx, predicate in enumerate(predicates):
            if not isinstance(predicate, dict):
                raise ValueError(f"tripwire_predicates[{idx}] must be an object")
            parsed_predicates.append(TripwirePredicate.from_dict(predicate))
        return cls(
            bundle_id=str(data.get("bundle_id", "")),
            bundle_hash=str(data.get("bundle_hash", "")),
            safe_state_id=str(data.get("safe_state_id", "")),
            authorized_tools=[str(x) for x in data.get("authorized_tools", [])],
            tool_hashes=dict(data.get("tool_hashes", {})),
            constraints=dict(data.get("constraints", {})),
            coa=dict(data.get("coa", {})),
            decision_tree=DecisionTree.from_dict(data["decision_tree"]),
            signature=BundleSignature.from_dict(data["signature"]),
            bundle_version=str(data.get("bundle_version", "")),
            inputs=CrossLayerInputs.from_dict(inputs) if isinstance(inputs, dict) else None,
            tripwire_predicates=parsed_predicates,
        )


__all__ = [
    "ConfidenceScore",
    "DecisionNodeKind",
    "DecisionTreeEdgeCondition",
    "DecisionTreeEdge",
    "DecisionTreeNode",
    "DecisionTree",
    "TripwireMetric",
    "TripwireOperator",
    "TripwireDecision",
    "TripwireWindowKind",
    "TripwireWindow",
    "TripwirePredicate",
    "BundleSignature",
    "MandateInputReference",
    "LatticePolicyInputReference",
    "CrossLayerInputs",
    "SignedApprovedBundle",
]
