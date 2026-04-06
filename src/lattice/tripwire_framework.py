"""Tripwire predicate framework with standard metrics."""
from __future__ import annotations

import math
from dataclasses import dataclass
from enum import Enum
from statistics import pstdev
from typing import Dict, List, Optional, Sequence

from .models import TripwireMetric, TripwireOperator, TripwirePredicate


@dataclass(frozen=True)
class MetricDefinition:
    metric: TripwireMetric
    description: str
    unit: str
    minimum: float = 0.0
    maximum: Optional[float] = None

    def in_domain(self, value: float) -> bool:
        if value < self.minimum:
            return False
        if self.maximum is not None and value > self.maximum:
            return False
        return True


class SensitivityLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


@dataclass(frozen=True)
class ThresholdCalibration:
    metric: TripwireMetric
    sensitivity: SensitivityLevel
    threshold: float
    sample_size: int
    baseline_mean: float
    baseline_stddev: float
    method: str = "mean_plus_k_sigma"


_STANDARD_METRIC_DEFS: Dict[TripwireMetric, MetricDefinition] = {
    TripwireMetric.ARI: MetricDefinition(
        metric=TripwireMetric.ARI,
        description="Action Risk Index aggregated from runtime behavior and risk posture.",
        unit="ratio",
        minimum=0.0,
        maximum=1.0,
    ),
    TripwireMetric.PRDS: MetricDefinition(
        metric=TripwireMetric.PRDS,
        description="Prompt-response drift score (semantic deviation from expected behavior).",
        unit="ratio",
        minimum=0.0,
        maximum=1.0,
    ),
    TripwireMetric.TMD: MetricDefinition(
        metric=TripwireMetric.TMD,
        description="Tree-model divergence score (off-tree transition behavior).",
        unit="ratio",
        minimum=0.0,
        maximum=1.0,
    ),
    TripwireMetric.RATE: MetricDefinition(
        metric=TripwireMetric.RATE,
        description="Tool request rate over configured window.",
        unit="requests/window",
        minimum=0.0,
    ),
    TripwireMetric.VOLUME: MetricDefinition(
        metric=TripwireMetric.VOLUME,
        description="Operation volume (e.g., bytes, objects, targets) over window.",
        unit="count/window",
        minimum=0.0,
    ),
    TripwireMetric.DURATION: MetricDefinition(
        metric=TripwireMetric.DURATION,
        description="Execution duration for operation or step window.",
        unit="seconds",
        minimum=0.0,
    ),
    TripwireMetric.ERROR_RATE: MetricDefinition(
        metric=TripwireMetric.ERROR_RATE,
        description="Error fraction over recent execution window.",
        unit="ratio",
        minimum=0.0,
        maximum=1.0,
    ),
    TripwireMetric.UNAUTHORIZED_TOOL_ATTEMPTS: MetricDefinition(
        metric=TripwireMetric.UNAUTHORIZED_TOOL_ATTEMPTS,
        description="Count of unauthorized tool invocation attempts over window.",
        unit="count/window",
        minimum=0.0,
    ),
}


def list_standard_metrics() -> List[MetricDefinition]:
    return list(_STANDARD_METRIC_DEFS.values())


def get_metric_definition(metric: TripwireMetric) -> MetricDefinition:
    return _STANDARD_METRIC_DEFS[metric]


def _validate_baseline_samples(
    metric_def: MetricDefinition,
    samples: Sequence[float],
) -> List[float]:
    if not samples:
        raise ValueError("baseline_samples must be non-empty")
    values: List[float] = []
    for idx, sample in enumerate(samples):
        value = float(sample)
        if not math.isfinite(value):
            raise ValueError(f"baseline_samples[{idx}] must be finite")
        if not metric_def.in_domain(value):
            if metric_def.maximum is None:
                raise ValueError(
                    f"baseline_samples[{idx}] for {metric_def.metric.value} must be >= {metric_def.minimum}"
                )
            raise ValueError(
                f"baseline_samples[{idx}] for {metric_def.metric.value} must be in "
                f"[{metric_def.minimum}, {metric_def.maximum}]"
            )
        values.append(value)
    return values


def build_metric_threshold(
    metric: TripwireMetric,
    baseline_samples: Sequence[float],
    *,
    sensitivity: SensitivityLevel = SensitivityLevel.MEDIUM,
) -> ThresholdCalibration:
    """
    Build a threshold from baseline samples and sensitivity.

    Higher sensitivity => lower threshold for high-is-worse metrics.
    """
    metric_def = get_metric_definition(metric)
    values = _validate_baseline_samples(metric_def, baseline_samples)

    mean = sum(values) / len(values)
    stddev = pstdev(values) if len(values) > 1 else 0.0

    sigma_multiplier = {
        SensitivityLevel.LOW: 2.5,
        SensitivityLevel.MEDIUM: 2.0,
        SensitivityLevel.HIGH: 1.5,
    }[sensitivity]

    threshold = mean + (sigma_multiplier * stddev)
    threshold = max(metric_def.minimum, threshold)
    if metric_def.maximum is not None:
        threshold = min(metric_def.maximum, threshold)

    return ThresholdCalibration(
        metric=metric,
        sensitivity=sensitivity,
        threshold=threshold,
        sample_size=len(values),
        baseline_mean=mean,
        baseline_stddev=stddev,
    )


def calibrate_tripwire_predicate(
    predicate: TripwirePredicate,
    baseline_samples: Sequence[float],
    *,
    sensitivity: SensitivityLevel = SensitivityLevel.MEDIUM,
) -> TripwirePredicate:
    """
    Return a calibrated copy of a predicate with updated threshold.
    """
    calibration = build_metric_threshold(
        predicate.metric,
        baseline_samples,
        sensitivity=sensitivity,
    )
    params = dict(predicate.parameters)
    params["calibration"] = {
        "method": calibration.method,
        "sensitivity": calibration.sensitivity.value,
        "sample_size": calibration.sample_size,
        "baseline_mean": calibration.baseline_mean,
        "baseline_stddev": calibration.baseline_stddev,
    }
    return TripwirePredicate(
        predicate_id=predicate.predicate_id,
        metric=predicate.metric,
        operator=predicate.operator,
        threshold=calibration.threshold,
        on_trigger=predicate.on_trigger,
        window=predicate.window,
        enabled=predicate.enabled,
        description=predicate.description,
        rationale=predicate.rationale,
        parameters=params,
    )


def validate_tripwire_predicate_spec(predicate: TripwirePredicate) -> List[str]:
    """
    Validate TripwirePredicate structure against standard metric domains.

    Returns a list of errors (empty means valid).
    """
    errors: List[str] = []
    if not predicate.enabled:
        return errors

    metric_def = _STANDARD_METRIC_DEFS.get(predicate.metric)
    if metric_def is None:
        errors.append(f"unsupported metric '{predicate.metric.value}'")
        return errors

    threshold = float(predicate.threshold)
    if not math.isfinite(threshold):
        errors.append("threshold must be finite")
    elif not metric_def.in_domain(threshold):
        if metric_def.maximum is None:
            errors.append(
                f"threshold for {predicate.metric.value} must be >= {metric_def.minimum}"
            )
        else:
            errors.append(
                f"threshold for {predicate.metric.value} must be in "
                f"[{metric_def.minimum}, {metric_def.maximum}]"
            )

    return errors


def evaluate_tripwire_predicate(predicate: TripwirePredicate, metric_value: float) -> bool:
    """Evaluate a single predicate against a metric value."""
    value = float(metric_value)
    threshold = float(predicate.threshold)
    operator = predicate.operator

    if operator is TripwireOperator.GT:
        return value > threshold
    if operator is TripwireOperator.GTE:
        return value >= threshold
    if operator is TripwireOperator.LT:
        return value < threshold
    if operator is TripwireOperator.LTE:
        return value <= threshold
    if operator is TripwireOperator.EQ:
        return value == threshold
    if operator is TripwireOperator.NEQ:
        return value != threshold
    return False


def evaluate_tripwire_predicates(
    predicates: List[TripwirePredicate],
    metric_values: Dict[TripwireMetric, float],
) -> Dict[str, bool]:
    """
    Evaluate enabled predicates against current metric values.

    Missing metrics evaluate as not triggered.
    """
    outcomes: Dict[str, bool] = {}
    for predicate in predicates:
        if not predicate.enabled:
            outcomes[predicate.predicate_id] = False
            continue
        value = metric_values.get(predicate.metric)
        if value is None:
            outcomes[predicate.predicate_id] = False
            continue
        outcomes[predicate.predicate_id] = evaluate_tripwire_predicate(predicate, value)
    return outcomes
