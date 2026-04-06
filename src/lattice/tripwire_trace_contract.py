"""Serialization contracts for passing tripwire predicates into TRACE bundles."""
from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from typing import Any, Dict, List

from .models import (
    TripwireMetric,
    TripwireOperator,
    TripwirePredicate,
    TripwireWindowKind,
)
from .tripwire_framework import validate_tripwire_predicate_spec


@dataclass(frozen=True)
class TraceTripwireContract:
    tripwire_predicates: List[Dict[str, Any]]
    constraints_patch: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        payload: Dict[str, Any] = {"tripwire_predicates": list(self.tripwire_predicates)}
        if self.constraints_patch:
            payload["constraints"] = dict(self.constraints_patch)
        return payload


def serialize_tripwire_predicate(predicate: TripwirePredicate) -> Dict[str, Any]:
    errors = validate_tripwire_predicate_spec(predicate)
    if errors:
        raise ValueError("; ".join(errors))
    return predicate.to_dict()


def serialize_tripwire_contract(predicates: List[TripwirePredicate]) -> TraceTripwireContract:
    seen_ids = set()
    serialized: List[Dict[str, Any]] = []
    for predicate in predicates:
        if predicate.predicate_id in seen_ids:
            raise ValueError(f"duplicate predicate_id: {predicate.predicate_id}")
        seen_ids.add(predicate.predicate_id)
        serialized.append(serialize_tripwire_predicate(predicate))

    constraints_patch: Dict[str, Any] = {}
    for predicate in predicates:
        if not predicate.enabled:
            continue
        if (
            predicate.metric is TripwireMetric.RATE
            and predicate.window.kind is TripwireWindowKind.EVENT_COUNT
            and predicate.operator in {TripwireOperator.GT, TripwireOperator.GTE}
        ):
            max_calls = int(predicate.threshold)
            if predicate.operator is TripwireOperator.GT:
                max_calls = max(0, max_calls)
            constraints_patch["tripwire_rate_limit"] = {
                "max_calls": max_calls,
                "window_n": int(predicate.window.size),
            }
            break

    return TraceTripwireContract(
        tripwire_predicates=serialized,
        constraints_patch=constraints_patch,
    )


def apply_tripwire_contract(
    bundle: Dict[str, Any],
    predicates: List[TripwirePredicate],
) -> Dict[str, Any]:
    contract = serialize_tripwire_contract(predicates)
    out = deepcopy(bundle)
    out["tripwire_predicates"] = contract.tripwire_predicates
    if contract.constraints_patch:
        constraints = dict(out.get("constraints") or {})
        constraints.update(contract.constraints_patch)
        out["constraints"] = constraints
    return out


def parse_tripwire_contract(bundle: Dict[str, Any]) -> List[TripwirePredicate]:
    raw = bundle.get("tripwire_predicates", [])
    if not isinstance(raw, list):
        raise ValueError("tripwire_predicates must be a list")
    out: List[TripwirePredicate] = []
    seen_ids = set()
    for idx, predicate in enumerate(raw):
        if not isinstance(predicate, dict):
            raise ValueError(f"tripwire_predicates[{idx}] must be an object")
        parsed = TripwirePredicate.from_dict(predicate)
        if parsed.predicate_id in seen_ids:
            raise ValueError(f"duplicate predicate_id: {parsed.predicate_id}")
        seen_ids.add(parsed.predicate_id)
        errors = validate_tripwire_predicate_spec(parsed)
        if errors:
            raise ValueError("; ".join(errors))
        out.append(parsed)
    return out
