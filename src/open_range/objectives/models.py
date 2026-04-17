"""Objective model definitions."""

from __future__ import annotations

from dataclasses import dataclass

from pydantic import BaseModel, ConfigDict

from open_range.catalog.contracts import (
    ObjectiveGraderKind,
    ObjectiveTargetKind,
    StandardAttackObjective,
)


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class ObjectiveGraderSpec(_StrictModel):
    objective_tag: StandardAttackObjective
    grader_kind: ObjectiveGraderKind
    service_id: str = ""
    target_id: str = ""
    path: str = ""
    event_type: str = ""
    expected_ref: str = ""


@dataclass(frozen=True, slots=True)
class ResolvedObjectiveSpec:
    predicate: str
    objective_tags: tuple[StandardAttackObjective, ...] = ()
    grader: ObjectiveGraderSpec | None = None
    target_kind: ObjectiveTargetKind = "none"
    target_id: str = ""
    target_service: str = ""
    event_type: str = ""

    @property
    def groundable(self) -> bool:
        return bool(self.grader is not None or self.target_service or self.target_id)
