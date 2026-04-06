from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


class DeploymentTier(str, Enum):
    SOLO = "SOLO"
    TEAM = "TEAM"
    SQUADRON = "SQUADRON"


@dataclass(frozen=True)
class TierProfile:
    max_cells: int
    autonomous_confidence_threshold: float
    default_oversight_mode: str


TIER_PROFILES: Dict[DeploymentTier, TierProfile] = {
    DeploymentTier.SOLO: TierProfile(max_cells=1, autonomous_confidence_threshold=0.95, default_oversight_mode="AUTONOMOUS"),
    DeploymentTier.TEAM: TierProfile(max_cells=4, autonomous_confidence_threshold=0.85, default_oversight_mode="HITL"),
    DeploymentTier.SQUADRON: TierProfile(max_cells=16, autonomous_confidence_threshold=0.70, default_oversight_mode="HITL"),
}


@dataclass(frozen=True)
class GridCell:
    """LATTICE 1+3 grid cell contract: one governance + three operational agents."""

    cell_id: str
    governance_agent_id: str
    planning_agent_id: str
    execution_agent_id: str
    coordination_agent_id: str

    def validate(self) -> List[str]:
        errors: List[str] = []
        if not self.cell_id:
            errors.append("cell_id must be non-empty")
        roles = {
            "governance_agent_id": self.governance_agent_id,
            "planning_agent_id": self.planning_agent_id,
            "execution_agent_id": self.execution_agent_id,
            "coordination_agent_id": self.coordination_agent_id,
        }
        for role, agent_id in roles.items():
            if not agent_id:
                errors.append(f"{self.cell_id}.{role} must be non-empty")
        if len(set(roles.values())) != len(roles):
            errors.append(f"{self.cell_id} must map each role to a distinct agent")
        return errors

    def to_dict(self) -> Dict[str, Any]:
        return {
            "cell_id": self.cell_id,
            "governance_agent_id": self.governance_agent_id,
            "planning_agent_id": self.planning_agent_id,
            "execution_agent_id": self.execution_agent_id,
            "coordination_agent_id": self.coordination_agent_id,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "GridCell":
        return cls(
            cell_id=str(data.get("cell_id", "")),
            governance_agent_id=str(data.get("governance_agent_id", "")),
            planning_agent_id=str(data.get("planning_agent_id", "")),
            execution_agent_id=str(data.get("execution_agent_id", "")),
            coordination_agent_id=str(data.get("coordination_agent_id", "")),
        )


@dataclass(frozen=True)
class CellAssignment:
    assignment_id: str
    operation_id: str
    task_id: str
    cell_id: str
    priority: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "assignment_id": self.assignment_id,
            "operation_id": self.operation_id,
            "task_id": self.task_id,
            "cell_id": self.cell_id,
            "priority": self.priority,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CellAssignment":
        return cls(
            assignment_id=str(data.get("assignment_id", "")),
            operation_id=str(data.get("operation_id", "")),
            task_id=str(data.get("task_id", "")),
            cell_id=str(data.get("cell_id", "")),
            priority=int(data.get("priority", 0)),
        )


@dataclass(frozen=True)
class SynchronizationPoint:
    sync_id: str
    after_task_ids: List[str]
    required_cell_ids: List[str]
    timeout_seconds: int = 300

    def to_dict(self) -> Dict[str, Any]:
        return {
            "sync_id": self.sync_id,
            "after_task_ids": list(self.after_task_ids),
            "required_cell_ids": list(self.required_cell_ids),
            "timeout_seconds": self.timeout_seconds,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SynchronizationPoint":
        return cls(
            sync_id=str(data.get("sync_id", "")),
            after_task_ids=[str(x) for x in data.get("after_task_ids", [])],
            required_cell_ids=[str(x) for x in data.get("required_cell_ids", [])],
            timeout_seconds=int(data.get("timeout_seconds", 300)),
        )


def validate_multi_cell_configuration(cells: Sequence[GridCell], tier: DeploymentTier) -> List[str]:
    errors: List[str] = []
    if not cells:
        return ["at least one grid cell is required"]

    cell_ids = [cell.cell_id for cell in cells]
    if len(set(cell_ids)) != len(cell_ids):
        errors.append("cell_id values must be unique")

    for cell in cells:
        errors.extend(cell.validate())

    profile = TIER_PROFILES[tier]
    if len(cells) > profile.max_cells:
        errors.append(f"{tier.value} tier supports at most {profile.max_cells} cells")
    if tier == DeploymentTier.SOLO and len(cells) != 1:
        errors.append("SOLO tier requires exactly one cell")
    return errors


def validate_assignments(assignments: Sequence[CellAssignment], cells: Sequence[GridCell]) -> List[str]:
    errors: List[str] = []
    valid_cell_ids = {cell.cell_id for cell in cells}
    assignment_ids: Set[str] = set()
    task_to_cell: Dict[str, str] = {}

    for assignment in assignments:
        if assignment.assignment_id in assignment_ids:
            errors.append(f"duplicate assignment_id '{assignment.assignment_id}'")
        assignment_ids.add(assignment.assignment_id)

        if assignment.cell_id not in valid_cell_ids:
            errors.append(f"assignment '{assignment.assignment_id}' references unknown cell '{assignment.cell_id}'")
        if assignment.task_id in task_to_cell and task_to_cell[assignment.task_id] != assignment.cell_id:
            errors.append(
                f"task '{assignment.task_id}' assigned to multiple cells: '{task_to_cell[assignment.task_id]}' and '{assignment.cell_id}'"
            )
        task_to_cell[assignment.task_id] = assignment.cell_id

    return errors


def validate_synchronization_points(
    sync_points: Sequence[SynchronizationPoint],
    assignments: Sequence[CellAssignment],
    cells: Sequence[GridCell],
) -> List[str]:
    errors: List[str] = []
    known_tasks = {assignment.task_id for assignment in assignments}
    known_cells = {cell.cell_id for cell in cells}
    seen_sync_ids: Set[str] = set()

    for sync in sync_points:
        if sync.sync_id in seen_sync_ids:
            errors.append(f"duplicate sync_id '{sync.sync_id}'")
        seen_sync_ids.add(sync.sync_id)

        if sync.timeout_seconds <= 0:
            errors.append(f"sync '{sync.sync_id}' timeout_seconds must be > 0")
        if not sync.after_task_ids:
            errors.append(f"sync '{sync.sync_id}' must specify after_task_ids")
        if not sync.required_cell_ids:
            errors.append(f"sync '{sync.sync_id}' must specify required_cell_ids")

        for task_id in sync.after_task_ids:
            if task_id not in known_tasks:
                errors.append(f"sync '{sync.sync_id}' references unknown task '{task_id}'")
        for cell_id in sync.required_cell_ids:
            if cell_id not in known_cells:
                errors.append(f"sync '{sync.sync_id}' references unknown cell '{cell_id}'")

    return errors


@dataclass
class MultiCellCoordinationPlan:
    tier: DeploymentTier
    cells: List[GridCell]
    assignments: List[CellAssignment]
    synchronization_points: List[SynchronizationPoint] = field(default_factory=list)

    def validate(self) -> List[str]:
        errors: List[str] = []
        errors.extend(validate_multi_cell_configuration(self.cells, self.tier))
        errors.extend(validate_assignments(self.assignments, self.cells))
        errors.extend(validate_synchronization_points(self.synchronization_points, self.assignments, self.cells))
        return errors

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tier": self.tier.value,
            "cells": [cell.to_dict() for cell in self.cells],
            "assignments": [assignment.to_dict() for assignment in self.assignments],
            "synchronization_points": [sync.to_dict() for sync in self.synchronization_points],
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "MultiCellCoordinationPlan":
        return cls(
            tier=DeploymentTier(str(data.get("tier", "SOLO"))),
            cells=[GridCell.from_dict(x) for x in data.get("cells", []) if isinstance(x, dict)],
            assignments=[CellAssignment.from_dict(x) for x in data.get("assignments", []) if isinstance(x, dict)],
            synchronization_points=[
                SynchronizationPoint.from_dict(x) for x in data.get("synchronization_points", []) if isinstance(x, dict)
            ],
        )


@dataclass(frozen=True)
class CoordinationMessage:
    message_id: str
    sequence_number: int
    timestamp: str
    source_cell_id: str
    target_cell_id: str
    operation_id: str
    payload: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "message_id": self.message_id,
            "sequence_number": self.sequence_number,
            "timestamp": self.timestamp,
            "source_cell_id": self.source_cell_id,
            "target_cell_id": self.target_cell_id,
            "operation_id": self.operation_id,
            "payload": dict(self.payload),
        }


class CoordinationMessageBus:
    """Deterministic in-memory coordination message bus."""

    def __init__(self, cell_ids: Iterable[str]) -> None:
        ids = [str(x) for x in cell_ids]
        if len(set(ids)) != len(ids):
            raise ValueError("cell_ids must be unique")
        self._cell_ids = set(ids)
        self._seq = 0
        self._messages: List[CoordinationMessage] = []
        self._cursors: Dict[str, int] = {cell_id: 0 for cell_id in ids}

    def publish(self, *, source_cell_id: str, target_cell_id: str, operation_id: str, payload: Dict[str, Any]) -> CoordinationMessage:
        if source_cell_id not in self._cell_ids:
            raise ValueError(f"unknown source cell '{source_cell_id}'")
        if target_cell_id not in self._cell_ids:
            raise ValueError(f"unknown target cell '{target_cell_id}'")
        self._seq += 1
        message = CoordinationMessage(
            message_id=f"MSG-{self._seq:06d}",
            sequence_number=self._seq,
            timestamp=_utc_now(),
            source_cell_id=source_cell_id,
            target_cell_id=target_cell_id,
            operation_id=operation_id,
            payload=dict(payload),
        )
        self._messages.append(message)
        return message

    def consume(self, target_cell_id: str) -> List[CoordinationMessage]:
        if target_cell_id not in self._cell_ids:
            raise ValueError(f"unknown target cell '{target_cell_id}'")
        start = self._cursors[target_cell_id]
        pending = [msg for msg in self._messages[start:] if msg.target_cell_id == target_cell_id]
        self._cursors[target_cell_id] = len(self._messages)
        return pending

    def all_messages(self) -> List[CoordinationMessage]:
        return list(self._messages)


__all__ = [
    "DeploymentTier",
    "TierProfile",
    "TIER_PROFILES",
    "GridCell",
    "CellAssignment",
    "SynchronizationPoint",
    "MultiCellCoordinationPlan",
    "CoordinationMessage",
    "CoordinationMessageBus",
    "validate_multi_cell_configuration",
    "validate_assignments",
    "validate_synchronization_points",
]
