"""Typed WorldIR models."""

from __future__ import annotations

from collections import defaultdict
from typing import Iterable, Literal

from pydantic import BaseModel, ConfigDict, Field

from open_range.manifest import (
    CodeFlawKind,
    NoiseDensity,
    PinnedWeaknessSpec,
    WeaknessFamily,
    WeaknessTargetKind,
)
from open_range.objectives import StandardAttackObjective


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)


CredentialKind = Literal["password", "token", "key", "cookie", "cert"]
EdgeKind = Literal["network", "trust", "data", "workflow", "telemetry"]
ExposureKind = Literal["public", "corp", "data", "management", "sandbox"]
WeaknessStatus = Literal["seeded", "mitigated", "disabled"]
ObjectiveOwner = Literal["red", "blue"]
WeaknessRealizationKind = Literal[
    "code", "config", "seed_data", "workflow", "mailbox", "telemetry"
]
WeaknessRemediationKind = Literal["shell", "manual"]
WeaknessInstantiationMode = Literal["exact_code", "exact_config", "exact_workflow"]


class HostSpec(_StrictModel):
    id: str = Field(min_length=1)
    zone: str = Field(min_length=1)
    exposure: ExposureKind = "corp"
    services: tuple[str, ...] = Field(default_factory=tuple)


class ServiceSpec(_StrictModel):
    id: str = Field(min_length=1)
    kind: str = Field(min_length=1)
    host: str = Field(min_length=1)
    ports: tuple[int, ...] = Field(default_factory=tuple)
    dependencies: tuple[str, ...] = Field(default_factory=tuple)
    telemetry_surfaces: tuple[str, ...] = Field(default_factory=tuple)


class UserSpec(_StrictModel):
    id: str = Field(min_length=1)
    role: str = Field(min_length=1)
    department: str = ""
    primary_host: str = ""
    groups: tuple[str, ...] = Field(default_factory=tuple)
    email: str = ""


class GroupSpec(_StrictModel):
    id: str = Field(min_length=1)
    members: tuple[str, ...] = Field(default_factory=tuple)
    privileges: tuple[str, ...] = Field(default_factory=tuple)


class CredentialSpec(_StrictModel):
    id: str = Field(min_length=1)
    subject: str = Field(min_length=1)
    kind: CredentialKind = "password"
    secret_ref: str = Field(min_length=1)
    scope: tuple[str, ...] = Field(default_factory=tuple)


class AssetSpec(_StrictModel):
    id: str = Field(min_length=1)
    asset_class: str = Field(min_length=1)
    location: str = Field(min_length=1)
    owner_service: str = ""
    confidentiality: Literal["low", "medium", "high", "critical"] = "high"


class WorkflowStepSpec(_StrictModel):
    id: str = Field(min_length=1)
    actor_role: str = Field(min_length=1)
    action: str = Field(min_length=1)
    service: str = ""
    asset: str = ""


class WorkflowSpec(_StrictModel):
    id: str = Field(min_length=1)
    name: str = Field(min_length=1)
    steps: tuple[WorkflowStepSpec, ...] = Field(default_factory=tuple)


class EdgeSpec(_StrictModel):
    id: str = Field(min_length=1)
    kind: EdgeKind
    source: str = Field(min_length=1)
    target: str = Field(min_length=1)
    label: str = ""


class WeaknessSpec(_StrictModel):
    id: str = Field(min_length=1)
    family: WeaknessFamily
    kind: str = Field(min_length=1)
    target: str = Field(min_length=1)
    target_kind: WeaknessTargetKind = "service"
    target_ref: str = ""
    benchmark_tags: tuple[str, ...] = Field(default_factory=tuple)
    objective_tags: tuple[StandardAttackObjective, ...] = Field(default_factory=tuple)
    preconditions: tuple[str, ...] = Field(default_factory=tuple)
    expected_event_signatures: tuple[str, ...] = Field(default_factory=tuple)
    blue_observability_surfaces: tuple[str, ...] = Field(default_factory=tuple)
    realization: tuple["WeaknessRealizationSpec", ...] = Field(default_factory=tuple)
    remediation: str = ""
    remediation_id: str = ""
    remediation_kind: WeaknessRemediationKind = "manual"
    remediation_command: str = ""
    instantiation_mode: WeaknessInstantiationMode = "exact_config"
    status: WeaknessStatus = "seeded"


class WeaknessRealizationSpec(_StrictModel):
    kind: WeaknessRealizationKind
    service: str = Field(min_length=1)
    path: str = Field(min_length=1)
    summary: str = ""


class ObjectiveSpec(_StrictModel):
    id: str = Field(min_length=1)
    owner: ObjectiveOwner
    predicate: str = Field(min_length=1)
    objective_tags: tuple[StandardAttackObjective, ...] = Field(default_factory=tuple)
    terminal: bool = True


class GreenPersona(_StrictModel):
    id: str = Field(min_length=1)
    role: str = Field(min_length=1)
    department: str = ""
    home_host: str = ""
    mailbox: str = ""
    awareness: float = Field(default=0.5, ge=0.0, le=1.0)
    susceptibility: dict[str, float] = Field(default_factory=dict)
    routine: tuple[str, ...] = Field(default_factory=tuple)


class GreenWorkloadSpec(_StrictModel):
    noise_density: NoiseDensity
    routine_interval_ticks: int = Field(default=1, ge=1)
    max_parallel_actions: int = Field(default=4, ge=1)
    reactive_branch_budget: int = Field(default=1, ge=0)


class MutationBoundsSpec(_StrictModel):
    max_new_hosts: int = Field(default=0, ge=0)
    max_new_services: int = Field(default=0, ge=0)
    max_new_users: int = Field(default=0, ge=0)
    max_new_weaknesses: int = Field(default=0, ge=0)
    allow_patch_old_weaknesses: bool = True


class LineageSpec(_StrictModel):
    generation: int = Field(default=0, ge=0)
    seed: int
    parent_world_id: str | None = None
    mutation_ops: tuple[str, ...] = Field(default_factory=tuple)


class WorldIR(_StrictModel):
    world_id: str = Field(min_length=1)
    world_family: Literal["enterprise_saas_v1"] = "enterprise_saas_v1"
    seed: int
    business_archetype: str = Field(min_length=1)
    allowed_service_kinds: tuple[str, ...] = Field(default_factory=tuple, min_length=1)
    allowed_weakness_families: tuple[WeaknessFamily, ...] = Field(default_factory=tuple)
    allowed_code_flaw_kinds: tuple[CodeFlawKind, ...] = Field(default_factory=tuple)
    pinned_weaknesses: tuple[PinnedWeaknessSpec, ...] = Field(default_factory=tuple)
    target_weakness_count: int = Field(default=2, ge=1)
    phishing_surface_enabled: bool = True
    target_red_path_depth: int = Field(default=1, ge=1)
    target_blue_signal_points: int = Field(default=1, ge=1)
    zones: tuple[str, ...] = Field(default_factory=tuple, min_length=1)
    hosts: tuple[HostSpec, ...] = Field(default_factory=tuple)
    services: tuple[ServiceSpec, ...] = Field(default_factory=tuple)
    users: tuple[UserSpec, ...] = Field(default_factory=tuple)
    groups: tuple[GroupSpec, ...] = Field(default_factory=tuple)
    credentials: tuple[CredentialSpec, ...] = Field(default_factory=tuple)
    assets: tuple[AssetSpec, ...] = Field(default_factory=tuple)
    workflows: tuple[WorkflowSpec, ...] = Field(default_factory=tuple)
    edges: tuple[EdgeSpec, ...] = Field(default_factory=tuple)
    weaknesses: tuple[WeaknessSpec, ...] = Field(default_factory=tuple)
    red_objectives: tuple[ObjectiveSpec, ...] = Field(default_factory=tuple)
    blue_objectives: tuple[ObjectiveSpec, ...] = Field(default_factory=tuple)
    green_personas: tuple[GreenPersona, ...] = Field(default_factory=tuple)
    green_workload: GreenWorkloadSpec
    mutation_bounds: MutationBoundsSpec = Field(default_factory=MutationBoundsSpec)
    lineage: LineageSpec

    @property
    def network_edges(self) -> tuple[EdgeSpec, ...]:
        return _edges_by_kind(self.edges)["network"]

    @property
    def trust_edges(self) -> tuple[EdgeSpec, ...]:
        return _edges_by_kind(self.edges)["trust"]

    @property
    def data_edges(self) -> tuple[EdgeSpec, ...]:
        return _edges_by_kind(self.edges)["data"]

    @property
    def workflow_edges(self) -> tuple[EdgeSpec, ...]:
        return _edges_by_kind(self.edges)["workflow"]

    @property
    def telemetry_edges(self) -> tuple[EdgeSpec, ...]:
        return _edges_by_kind(self.edges)["telemetry"]

    def replace_edges(
        self,
        *,
        network: tuple[EdgeSpec, ...] | None = None,
        trust: tuple[EdgeSpec, ...] | None = None,
        data: tuple[EdgeSpec, ...] | None = None,
        workflow: tuple[EdgeSpec, ...] | None = None,
        telemetry: tuple[EdgeSpec, ...] | None = None,
    ) -> WorldIR:
        grouped = _edges_by_kind(self.edges)
        next_edges = (
            tuple(network if network is not None else grouped["network"])
            + tuple(trust if trust is not None else grouped["trust"])
            + tuple(data if data is not None else grouped["data"])
            + tuple(workflow if workflow is not None else grouped["workflow"])
            + tuple(telemetry if telemetry is not None else grouped["telemetry"])
        )
        return self.model_copy(update={"edges": next_edges})


def _edges_by_kind(edges: Iterable[EdgeSpec]) -> dict[str, tuple[EdgeSpec, ...]]:
    grouped: dict[str, list[EdgeSpec]] = defaultdict(list)
    for edge in edges:
        grouped[edge.kind].append(edge)
    return {
        "network": tuple(grouped.get("network", ())),
        "trust": tuple(grouped.get("trust", ())),
        "data": tuple(grouped.get("data", ())),
        "workflow": tuple(grouped.get("workflow", ())),
        "telemetry": tuple(grouped.get("telemetry", ())),
    }
