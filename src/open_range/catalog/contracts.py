"""Typed contracts for catalog-backed rewrite data."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

StandardAttackObjective = Literal[
    "dos",
    "file_access",
    "file_creation",
    "db_modification",
    "db_access",
    "unauthorized_admin_login",
    "privilege_escalation",
    "outbound_service",
]

STANDARD_ATTACK_OBJECTIVE_NAMES: tuple[StandardAttackObjective, ...] = (
    "dos",
    "file_access",
    "file_creation",
    "db_modification",
    "db_access",
    "unauthorized_admin_login",
    "privilege_escalation",
    "outbound_service",
)

ObjectiveGraderKind = Literal[
    "service_health",
    "file_exists",
    "db_row_read",
    "db_row_write",
    "event_present",
    "outbound_request",
]

ObjectiveResolutionKind = Literal[
    "direct_objective",
    "asset_read",
    "credential_obtained",
    "observation_only",
]

OBJECTIVE_RESOLUTION_KINDS: tuple[ObjectiveResolutionKind, ...] = (
    "direct_objective",
    "asset_read",
    "credential_obtained",
    "observation_only",
)


@dataclass(frozen=True, slots=True)
class ObjectiveRuleSpec:
    predicate_name: str
    resolution_kind: ObjectiveResolutionKind
    objective_tag: StandardAttackObjective | None = None


@dataclass(frozen=True, slots=True)
class WeaknessObjectiveTagSpec:
    family: str
    kind: str
    objective_tags: tuple[StandardAttackObjective, ...]


@dataclass(frozen=True, slots=True)
class ServiceCatalogEntry:
    kind: str
    host_id: str
    service_id: str
    zone: str
    exposure: str
    ports: tuple[int, ...]
    dependencies: tuple[str, ...]
    telemetry_surfaces: tuple[str, ...]
