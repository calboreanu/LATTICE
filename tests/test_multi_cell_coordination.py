"""Tests for deterministic multi-cell coordination primitives (KAN-297)."""
from __future__ import annotations

import pytest

from lattice.multi_cell import (
    CellAssignment,
    CoordinationMessageBus,
    DeploymentTier,
    GridCell,
    MultiCellCoordinationPlan,
    SynchronizationPoint,
)


def _cell(cell_id: str, suffix: str) -> GridCell:
    return GridCell(
        cell_id=cell_id,
        governance_agent_id=f"gov-{suffix}",
        planning_agent_id=f"plan-{suffix}",
        execution_agent_id=f"exec-{suffix}",
        coordination_agent_id=f"coord-{suffix}",
    )


def test_valid_team_plan_passes_validation() -> None:
    plan = MultiCellCoordinationPlan(
        tier=DeploymentTier.TEAM,
        cells=[_cell("cell-a", "a"), _cell("cell-b", "b")],
        assignments=[
            CellAssignment("as-1", operation_id="op-1", task_id="t-1", cell_id="cell-a"),
            CellAssignment("as-2", operation_id="op-1", task_id="t-2", cell_id="cell-b"),
        ],
        synchronization_points=[
            SynchronizationPoint(sync_id="sync-1", after_task_ids=["t-1", "t-2"], required_cell_ids=["cell-a", "cell-b"])
        ],
    )

    assert plan.validate() == []


def test_solo_tier_rejects_multiple_cells() -> None:
    plan = MultiCellCoordinationPlan(
        tier=DeploymentTier.SOLO,
        cells=[_cell("cell-a", "a"), _cell("cell-b", "b")],
        assignments=[],
    )

    errors = plan.validate()
    assert any("SOLO tier requires exactly one cell" in err for err in errors)


def test_validation_rejects_duplicate_task_assignment_to_multiple_cells() -> None:
    plan = MultiCellCoordinationPlan(
        tier=DeploymentTier.TEAM,
        cells=[_cell("cell-a", "a"), _cell("cell-b", "b")],
        assignments=[
            CellAssignment("as-1", operation_id="op-1", task_id="t-1", cell_id="cell-a"),
            CellAssignment("as-2", operation_id="op-1", task_id="t-1", cell_id="cell-b"),
        ],
    )

    errors = plan.validate()
    assert any("assigned to multiple cells" in err for err in errors)


def test_validation_rejects_sync_references_to_unknown_task_or_cell() -> None:
    plan = MultiCellCoordinationPlan(
        tier=DeploymentTier.TEAM,
        cells=[_cell("cell-a", "a")],
        assignments=[CellAssignment("as-1", operation_id="op-1", task_id="t-1", cell_id="cell-a")],
        synchronization_points=[
            SynchronizationPoint(sync_id="sync-1", after_task_ids=["missing"], required_cell_ids=["missing-cell"])
        ],
    )

    errors = plan.validate()
    assert any("unknown task" in err for err in errors)
    assert any("unknown cell" in err for err in errors)


def test_message_bus_orders_and_delivers_by_target() -> None:
    bus = CoordinationMessageBus(cell_ids=["cell-a", "cell-b", "cell-c"])
    first = bus.publish(
        source_cell_id="cell-a",
        target_cell_id="cell-b",
        operation_id="op-1",
        payload={"kind": "handoff"},
    )
    second = bus.publish(
        source_cell_id="cell-c",
        target_cell_id="cell-b",
        operation_id="op-1",
        payload={"kind": "status"},
    )
    assert first.sequence_number == 1
    assert second.sequence_number == 2

    inbox = bus.consume("cell-b")
    assert [msg.sequence_number for msg in inbox] == [1, 2]
    assert bus.consume("cell-b") == []

    with pytest.raises(ValueError, match="unknown target cell"):
        bus.consume("missing")
