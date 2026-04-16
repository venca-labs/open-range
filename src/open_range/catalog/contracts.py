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

ObjectiveTargetKind = Literal["none", "asset", "service"]
ObjectiveGraderKind = Literal[
    "service_health",
    "file_exists",
    "db_row_read",
    "db_row_write",
    "event_present",
    "outbound_request",
]
ProbeTemplateKind = Literal["smoke", "shortcut", "determinism", "necessity"]

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
    target_kind: ObjectiveTargetKind = "none"
    event_type: str = ""
    default_service: str = ""


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


@dataclass(frozen=True, slots=True)
class PersonaDefaultsSpec:
    role: str
    home_service: str
    routine: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class AssetPlacementRuleSpec:
    match_tokens: tuple[str, ...]
    owner_service: str
    location_template: str


@dataclass(frozen=True, slots=True)
class AssetConfidentialitySpec:
    asset_class: str
    confidentiality: Literal["low", "medium", "high", "critical"]


@dataclass(frozen=True, slots=True)
class WorkflowTemplateStepSpec:
    id: str
    actor_role: str
    action: str
    service: str = ""
    asset: str = ""


@dataclass(frozen=True, slots=True)
class WorkflowTemplateSpec:
    name: str
    steps: tuple[WorkflowTemplateStepSpec, ...]


@dataclass(frozen=True, slots=True)
class WeaknessFamilyContract:
    family: str
    default_target_kind: str
    available_when_any_service_kinds: tuple[str, ...]
    benchmark_tags: tuple[str, ...]
    instantiation_mode: str


@dataclass(frozen=True, slots=True)
class WeaknessKindSpec:
    family: str
    kind: str


@dataclass(frozen=True, slots=True)
class WeaknessPreconditionSpec:
    family: str
    tokens: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class WeaknessSeedSelectionSpec:
    family: str
    auto_include: bool = False
    priority: int = 1


@dataclass(frozen=True, slots=True)
class WeaknessExpectedEventsSpec:
    family: str
    kind: str
    expected_event_signatures: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class WeaknessObservabilitySurfaceSpec:
    family: str
    kind: str = ""
    target: str = ""
    surfaces: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class WeaknessBuildDefaultsSpec:
    benchmark_tags: tuple[str, ...]
    objective_tags: tuple[str, ...]
    preconditions: tuple[str, ...]
    expected_event_signatures: tuple[str, ...]
    blue_observability_surfaces: tuple[str, ...]
    instantiation_mode: str
    remediation: str


@dataclass(frozen=True, slots=True)
class ProbeTemplateSpec:
    id: str
    kind: ProbeTemplateKind
    description: str
    command: str = ""


@dataclass(frozen=True, slots=True)
class ShortcutWebRouteProbeSpec:
    weakness_kind: str
    path: str
    query: tuple[tuple[str, str], ...]


@dataclass(frozen=True, slots=True)
class BlueReferencePlanSpec:
    detect_index: int
    detect_event: str
    detect_target: str
    contain_target: str
    observe_step_count: int
