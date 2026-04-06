"""Tests for TRACE tripwire contract serialization/parsing (KAN-312)."""
from __future__ import annotations

import pytest

from lattice.models import (
    TripwireDecision,
    TripwireMetric,
    TripwireOperator,
    TripwirePredicate,
    TripwireWindow,
    TripwireWindowKind,
)
from lattice.tripwire_trace_contract import (
    apply_tripwire_contract,
    parse_tripwire_contract,
    serialize_tripwire_contract,
)


def _predicate(
    *,
    predicate_id: str = "TW-C-001",
    metric: TripwireMetric = TripwireMetric.RATE,
    operator: TripwireOperator = TripwireOperator.GT,
    threshold: float = 5.0,
    window_kind: TripwireWindowKind = TripwireWindowKind.EVENT_COUNT,
    window_size: int = 10,
    enabled: bool = True,
) -> TripwirePredicate:
    return TripwirePredicate(
        predicate_id=predicate_id,
        metric=metric,
        operator=operator,
        threshold=threshold,
        on_trigger=TripwireDecision.ESCALATE,
        window=TripwireWindow(kind=window_kind, size=window_size),
        enabled=enabled,
    )


def test_serialize_contract_adds_rate_limit_patch_for_rate_predicate() -> None:
    contract = serialize_tripwire_contract(
        [_predicate(metric=TripwireMetric.RATE, operator=TripwireOperator.GT, threshold=3.0)]
    )
    assert "tripwire_rate_limit" in contract.constraints_patch
    assert contract.constraints_patch["tripwire_rate_limit"]["max_calls"] == 3
    assert contract.constraints_patch["tripwire_rate_limit"]["window_n"] == 10


def test_serialize_contract_omits_rate_limit_patch_for_non_rate_metric() -> None:
    contract = serialize_tripwire_contract(
        [_predicate(metric=TripwireMetric.ARI, threshold=0.3)]
    )
    assert contract.constraints_patch == {}


def test_apply_tripwire_contract_merges_constraints_patch() -> None:
    bundle = {"constraints": {"allowed_targets": ["example.local"]}}
    out = apply_tripwire_contract(
        bundle,
        [_predicate(metric=TripwireMetric.RATE, operator=TripwireOperator.GT, threshold=2.0)],
    )
    assert "tripwire_predicates" in out
    assert out["constraints"]["allowed_targets"] == ["example.local"]
    assert out["constraints"]["tripwire_rate_limit"]["max_calls"] == 2


def test_parse_tripwire_contract_rejects_duplicate_ids() -> None:
    p = _predicate(predicate_id="TW-DUP")
    bundle = {"tripwire_predicates": [p.to_dict(), p.to_dict()]}
    with pytest.raises(ValueError, match="duplicate predicate_id"):
        parse_tripwire_contract(bundle)


def test_parse_tripwire_contract_rejects_invalid_payload_type() -> None:
    with pytest.raises(ValueError, match="tripwire_predicates must be a list"):
        parse_tripwire_contract({"tripwire_predicates": "bad"})


_METRICS = [
    TripwireMetric.ARI,
    TripwireMetric.PRDS,
    TripwireMetric.TMD,
    TripwireMetric.RATE,
    TripwireMetric.VOLUME,
    TripwireMetric.DURATION,
    TripwireMetric.ERROR_RATE,
    TripwireMetric.UNAUTHORIZED_TOOL_ATTEMPTS,
]
_OPERATORS = [
    TripwireOperator.GT,
    TripwireOperator.GTE,
    TripwireOperator.LT,
    TripwireOperator.LTE,
]


@pytest.mark.parametrize("metric", _METRICS)
@pytest.mark.parametrize("operator", _OPERATORS)
def test_tripwire_contract_round_trip_metric_operator_matrix(
    metric: TripwireMetric,
    operator: TripwireOperator,
) -> None:
    threshold = 0.5 if metric in {
        TripwireMetric.ARI,
        TripwireMetric.PRDS,
        TripwireMetric.TMD,
        TripwireMetric.ERROR_RATE,
    } else 5.0
    predicate = _predicate(
        predicate_id=f"TW-{metric.value}-{operator.value}",
        metric=metric,
        operator=operator,
        threshold=threshold,
        window_kind=TripwireWindowKind.EVENT_COUNT,
        window_size=7,
    )

    contract = serialize_tripwire_contract([predicate])
    bundle = {"tripwire_predicates": contract.tripwire_predicates}
    parsed = parse_tripwire_contract(bundle)

    assert len(parsed) == 1
    assert parsed[0].predicate_id == predicate.predicate_id
    assert parsed[0].metric is metric
    assert parsed[0].operator is operator
    assert parsed[0].threshold == pytest.approx(threshold)
    assert parsed[0].window.kind is TripwireWindowKind.EVENT_COUNT
    assert parsed[0].window.size == 7

