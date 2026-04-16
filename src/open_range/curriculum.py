"""Deterministic curriculum and typed mutation policy."""

from __future__ import annotations

import hashlib
import json
from typing import Literal, Protocol

from pydantic import BaseModel, ConfigDict, Field

from open_range._runtime_store import load_world_ir
from open_range.predicate_expr import predicate_inner
from open_range.store import FileSnapshotStore
from open_range.weaknesses import build_catalog_weakness
from open_range.world_ir import (
    CredentialSpec,
    EdgeSpec,
    GreenPersona,
    GroupSpec,
    HostSpec,
    ServiceSpec,
    UserSpec,
    WeaknessSpec,
    WorkflowStepSpec,
    WorldIR,
)

PoolSplit = Literal["train", "eval"]
MutationKind = Literal[
    "add_host",
    "add_service",
    "add_user",
    "add_workflow_branch",
    "add_trust_edge",
    "add_noise_source",
    "seed_weakness",
    "alter_observability",
    "patch_weakness",
    "harden_route_expose_alternate",
]


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class PopulationStats(_StrictModel):
    snapshot_id: str = Field(min_length=1)
    world_id: str = Field(min_length=1)
    split: PoolSplit = "train"
    episodes: int = Field(default=0, ge=0)
    red_win_rate: float = Field(default=0.0, ge=0.0, le=1.0)
    blue_win_rate: float = Field(default=0.0, ge=0.0, le=1.0)
    avg_ticks: float = Field(default=0.0, ge=0.0)
    flake_rate: float = Field(default=0.0, ge=0.0, le=1.0)
    novelty: float = Field(default=0.5, ge=0.0, le=1.0)
    blue_signal_points: int = Field(default=0, ge=0)


class ParentScore(_StrictModel):
    snapshot_id: str = Field(min_length=1)
    world_id: str = Field(min_length=1)
    total: float
    signals: dict[str, float] = Field(default_factory=dict)


class MutationOp(_StrictModel):
    kind: MutationKind
    target: str = ""
    details: dict[str, str] = Field(default_factory=dict)


class MutationPolicy(Protocol):
    def choose_parent(self, population: list[PopulationStats]) -> str: ...
    def mutate(
        self,
        parent: WorldIR,
        *,
        parent_stats: PopulationStats | None = None,
        child_seed: int | None = None,
    ) -> WorldIR: ...


class FrontierMutationPolicy:
    """Heuristic deterministic curriculum policy for admitted worlds."""

    def score_parents(
        self, population: list[PopulationStats]
    ) -> tuple[ParentScore, ...]:
        ranked: list[ParentScore] = []
        for entry in population:
            if entry.split != "train":
                continue
            stability = 1.0 - entry.flake_rate
            frontier = max(0.0, 1.0 - abs(entry.red_win_rate - 0.5) * 2.0)
            signal_richness = min(entry.blue_signal_points / 6.0, 1.0)
            coverage = min(entry.episodes / 10.0, 1.0)
            total = (
                0.35 * stability
                + 0.30 * frontier
                + 0.15 * entry.novelty
                + 0.10 * signal_richness
                + 0.10 * coverage
            )
            ranked.append(
                ParentScore(
                    snapshot_id=entry.snapshot_id,
                    world_id=entry.world_id,
                    total=round(total, 6),
                    signals={
                        "stability": round(stability, 6),
                        "frontier": round(frontier, 6),
                        "novelty": round(entry.novelty, 6),
                        "signal_richness": round(signal_richness, 6),
                        "coverage": round(coverage, 6),
                    },
                )
            )
        return tuple(sorted(ranked, key=lambda item: (-item.total, item.snapshot_id)))

    def choose_parent(self, population: list[PopulationStats]) -> str:
        ranked = self.score_parents(population)
        if not ranked:
            raise ValueError("population must contain at least one train-split parent")
        return ranked[0].snapshot_id

    def propose(
        self,
        store: FileSnapshotStore,
        population: list[PopulationStats],
        *,
        child_count: int = 1,
    ) -> tuple[WorldIR, ...]:
        if child_count < 1:
            return ()
        stats_by_snapshot = {entry.snapshot_id: entry for entry in population}
        children: list[WorldIR] = []
        for rank, score in enumerate(
            self.score_parents(population)[:child_count], start=1
        ):
            world = load_world_ir(store, score.snapshot_id)
            child_seed = _stable_seed(world.world_id, score.snapshot_id, rank)
            children.append(
                self.mutate(
                    world,
                    parent_stats=stats_by_snapshot.get(score.snapshot_id),
                    child_seed=child_seed,
                )
            )
        return tuple(children)

    def mutate(
        self,
        parent: WorldIR,
        *,
        parent_stats: PopulationStats | None = None,
        child_seed: int | None = None,
    ) -> WorldIR:
        child = parent.model_copy(deep=True)
        applied: list[MutationOp] = []

        for op in self._plan_ops(parent, parent_stats):
            updated = self._apply_op(child, op)
            if updated is None:
                continue
            child = updated
            applied.append(op)

        effective_seed = (
            child_seed
            if child_seed is not None
            else _stable_seed(parent.world_id, "child", len(applied))
        )
        child_generation = parent.lineage.generation + 1
        op_tokens = tuple(_op_token(op) for op in applied)
        suffix = (
            hashlib.sha256("|".join(op_tokens).encode("utf-8")).hexdigest()[:8]
            if op_tokens
            else "noop0000"
        )
        lineage = parent.lineage.model_copy(
            update={
                "generation": child_generation,
                "seed": effective_seed,
                "parent_world_id": parent.world_id,
                "mutation_ops": tuple(parent.lineage.mutation_ops) + op_tokens,
            }
        )
        return child.model_copy(
            update={
                "world_id": f"{parent.world_family}-{effective_seed}-{suffix}",
                "seed": effective_seed,
                "lineage": lineage,
            }
        )

    def _plan_ops(
        self,
        parent: WorldIR,
        parent_stats: PopulationStats | None,
    ) -> tuple[MutationOp, ...]:
        stats = parent_stats or PopulationStats(
            snapshot_id="synthetic", world_id=parent.world_id
        )
        ops: list[MutationOp] = []

        if (
            parent.mutation_bounds.max_new_hosts > 0
            and parent.mutation_bounds.max_new_services > 0
        ):
            objective_service = _first_objective_service(parent)
            if objective_service:
                ops.append(MutationOp(kind="add_service", target=objective_service))
        elif parent.mutation_bounds.max_new_hosts > 0:
            ops.append(MutationOp(kind="add_host", target="corp"))

        if parent.mutation_bounds.max_new_users > 0:
            ops.append(
                MutationOp(kind="add_user", target=_least_populated_role(parent))
            )

        if stats.red_win_rate >= 0.65:
            ops.append(MutationOp(kind="add_noise_source"))
            ops.append(MutationOp(kind="alter_observability"))
        elif stats.blue_win_rate >= 0.65 or stats.red_win_rate <= 0.35:
            if parent.mutation_bounds.allow_patch_old_weaknesses:
                ops.append(MutationOp(kind="patch_weakness"))
            ops.append(MutationOp(kind="add_trust_edge"))
            ops.append(MutationOp(kind="seed_weakness"))
        else:
            ops.append(MutationOp(kind="add_workflow_branch"))
            if parent.mutation_bounds.allow_patch_old_weaknesses:
                ops.append(MutationOp(kind="harden_route_expose_alternate"))
            ops.append(MutationOp(kind="seed_weakness"))

        deduped: list[MutationOp] = []
        seen: set[str] = set()
        for op in ops:
            token = _op_token(op)
            if token in seen:
                continue
            deduped.append(op)
            seen.add(token)
        return tuple(deduped)

    def _apply_op(self, world: WorldIR, op: MutationOp) -> WorldIR | None:
        if op.kind == "add_host":
            return _add_host(world)
        if op.kind == "add_service":
            return _add_service(world, objective_service_id=op.target)
        if op.kind == "add_user":
            return _add_user(world, role=op.target)
        if op.kind == "add_workflow_branch":
            return _add_workflow_branch(world)
        if op.kind == "add_trust_edge":
            return _add_trust_edge(world)
        if op.kind == "add_noise_source":
            return _add_noise_source(world)
        if op.kind == "seed_weakness":
            return _seed_additional_weakness(world)
        if op.kind == "alter_observability":
            return _alter_observability(world)
        if op.kind == "patch_weakness":
            return _patch_weakness(world)
        if op.kind == "harden_route_expose_alternate":
            return _harden_route_expose_alternate(world)
        raise ValueError(f"unsupported mutation op: {op.kind}")


def propose_mutations(
    population: list[PopulationStats],
    *,
    store: FileSnapshotStore,
    child_count: int = 1,
    policy: FrontierMutationPolicy | None = None,
) -> tuple[WorldIR, ...]:
    """Generate deterministic child worlds from the train split."""
    return (policy or FrontierMutationPolicy()).propose(
        store, population, child_count=child_count
    )


def _op_token(op: MutationOp) -> str:
    if not op.details:
        return op.kind if not op.target else f"{op.kind}:{op.target}"
    payload = ",".join(f"{key}={value}" for key, value in sorted(op.details.items()))
    if op.target:
        return f"{op.kind}:{op.target}:{payload}"
    return f"{op.kind}:{payload}"


def _stable_seed(*parts: object) -> int:
    payload = "|".join(str(part) for part in parts)
    return int(hashlib.sha256(payload.encode("utf-8")).hexdigest()[:8], 16)


def _first_objective_service(world: WorldIR) -> str:
    objective = next(iter(world.red_objectives), None)
    if objective is None:
        return world.services[0].id
    asset_id = predicate_inner(objective.predicate)
    asset = next((item for item in world.assets if item.id == asset_id), None)
    if asset is not None:
        return asset.owner_service
    return "svc-siem"


def _least_populated_role(world: WorldIR) -> str:
    counts: dict[str, int] = {}
    for user in world.users:
        counts[user.role] = counts.get(user.role, 0) + 1
    if not counts:
        return "sales"
    return sorted(counts.items(), key=lambda item: (item[1], item[0]))[0][0]


def _add_host(world: WorldIR) -> WorldIR | None:
    if world.mutation_bounds.max_new_hosts < 1:
        return None
    host_ids = {host.id for host in world.hosts}
    host_id = _next_host_id("workstation", host_ids)
    hosts = world.hosts + (
        HostSpec(id=host_id, zone="corp", exposure="corp", services=()),
    )
    users = list(world.users)
    personas = list(world.green_personas)
    if users:
        users[0] = users[0].model_copy(update={"primary_host": host_id})
    if personas:
        personas[0] = personas[0].model_copy(update={"home_host": host_id})
    return world.model_copy(
        update={
            "hosts": tuple(hosts),
            "users": tuple(users),
            "green_personas": tuple(personas),
        }
    )


def _add_service(world: WorldIR, *, objective_service_id: str) -> WorldIR | None:
    if (
        world.mutation_bounds.max_new_hosts < 1
        or world.mutation_bounds.max_new_services < 1
    ):
        return None
    service_by_id = {service.id: service for service in world.services}
    source_service = service_by_id.get(objective_service_id)
    if source_service is None:
        return None
    host_by_id = {host.id: host for host in world.hosts}
    source_host = host_by_id[source_service.host]

    new_host_id = _next_host_id(source_service.kind, set(host_by_id))
    new_service_id = _next_service_id(
        source_service.id, {service.id for service in world.services}
    )
    dependency_ids = tuple(
        dict.fromkeys((source_service.id,) + source_service.dependencies)
    )
    new_host = HostSpec(
        id=new_host_id,
        zone=source_host.zone,
        exposure=source_host.exposure,
        services=(new_service_id,),
    )
    new_service = ServiceSpec(
        id=new_service_id,
        kind=source_service.kind,
        host=new_host_id,
        ports=source_service.ports,
        dependencies=dependency_ids,
        telemetry_surfaces=source_service.telemetry_surfaces,
    )
    network_edges = list(world.network_edges)
    trust_edges = list(world.trust_edges)
    for dep in dependency_ids:
        network_edges.append(
            EdgeSpec(
                id=f"net-{new_service_id}-to-{dep}",
                kind="network",
                source=new_service_id,
                target=dep,
                label="mutated_dependency",
            )
        )
        trust_edges.append(
            EdgeSpec(
                id=f"trust-{new_service_id}-to-{dep}",
                kind="trust",
                source=new_service_id,
                target=dep,
                label="mutated_trust",
            )
        )
    telemetry_edges = world.telemetry_edges + (
        EdgeSpec(
            id=f"telemetry-{new_service_id}-to-siem",
            kind="telemetry",
            source=new_service_id,
            target="svc-siem",
            label="log_ship",
        ),
    )

    assets = list(world.assets)
    first_asset_id = (
        predicate_inner(world.red_objectives[0].predicate)
        if world.red_objectives
        else ""
    )
    for idx, asset in enumerate(assets):
        if asset.id != first_asset_id or asset.owner_service != source_service.id:
            continue
        location = _moved_asset_location(asset.location, new_service_id)
        assets[idx] = asset.model_copy(
            update={"owner_service": new_service_id, "location": location}
        )
        break

    return world.replace_edges(
        network=tuple(network_edges),
        trust=tuple(trust_edges),
        telemetry=telemetry_edges,
    ).model_copy(
        update={
            "hosts": world.hosts + (new_host,),
            "services": world.services + (new_service,),
            "assets": tuple(assets),
        }
    )


def _add_user(world: WorldIR, *, role: str) -> WorldIR | None:
    if world.mutation_bounds.max_new_users < 1:
        return None
    existing_role_users = [user for user in world.users if user.role == role]
    template_user = (
        existing_role_users[0]
        if existing_role_users
        else (world.users[0] if world.users else None)
    )
    template_persona = next(
        (persona for persona in world.green_personas if persona.role == role), None
    )
    if template_user is None:
        return None

    user_id = _next_user_id(role, {user.id for user in world.users})
    home_host = template_user.primary_host or (
        world.hosts[0].id if world.hosts else "web-1"
    )
    group_id = f"group-{role}"

    new_user = UserSpec(
        id=user_id,
        role=role,
        department=template_user.department or role,
        primary_host=home_host,
        groups=(group_id,),
        email=f"{user_id}@corp.local",
    )
    new_credential = CredentialSpec(
        id=f"cred-{user_id}",
        subject=user_id,
        secret_ref=f"secret://idp/{user_id}",
        scope=("svc-idp",),
    )
    new_persona = GreenPersona(
        id=user_id,
        role=role,
        department=template_user.department or role,
        home_host=home_host,
        mailbox=f"{user_id}@corp.local",
        awareness=template_persona.awareness if template_persona else 0.5,
        susceptibility=template_persona.susceptibility if template_persona else {},
        routine=template_persona.routine
        if template_persona
        else ("check_mail", "browse_app"),
    )

    groups = list(world.groups)
    for idx, group in enumerate(groups):
        if group.id != group_id:
            continue
        groups[idx] = group.model_copy(update={"members": group.members + (user_id,)})
        break
    else:
        groups.append(
            GroupSpec(id=group_id, members=(user_id,), privileges=("svc-web",))
        )

    return world.model_copy(
        update={
            "users": world.users + (new_user,),
            "credentials": world.credentials + (new_credential,),
            "green_personas": world.green_personas + (new_persona,),
            "groups": tuple(groups),
        }
    )


def _add_workflow_branch(world: WorldIR) -> WorldIR | None:
    if not world.workflows:
        return None
    workflow = world.workflows[0]
    asset = next(
        (item for item in world.assets if item.confidentiality in {"critical", "high"}),
        None,
    )
    service_id = _first_objective_service(world)
    new_step = WorkflowStepSpec(
        id=f"{workflow.id}-branch-{len(workflow.steps) + 1}",
        actor_role=world.users[0].role if world.users else "sales",
        action=f"review_{asset.id}" if asset is not None else "branch_review",
        service=service_id,
        asset=asset.id if asset is not None else "",
    )
    workflows = list(world.workflows)
    workflows[0] = workflow.model_copy(update={"steps": workflow.steps + (new_step,)})
    workflow_edges = list(world.workflow_edges)
    data_edges = list(world.data_edges)
    workflow_edges.append(
        EdgeSpec(
            id=f"workflow-{workflow.id}-branch-{len(workflow_edges) + 1}",
            kind="workflow",
            source=new_step.actor_role,
            target=service_id,
            label=new_step.action,
        )
    )
    if asset is not None:
        data_edges.append(
            EdgeSpec(
                id=f"data-{workflow.id}-branch-{len(data_edges) + 1}",
                kind="data",
                source=service_id,
                target=asset.id,
                label=new_step.action,
            )
        )
    return world.replace_edges(
        data=tuple(data_edges), workflow=tuple(workflow_edges)
    ).model_copy(update={"workflows": tuple(workflows)})


def _add_trust_edge(world: WorldIR) -> WorldIR | None:
    objective_service = _first_objective_service(world)
    public_service = next(
        (
            service.id
            for service in world.services
            if service.kind in {"web_app", "email"}
        ),
        "",
    )
    if (
        not public_service
        or not objective_service
        or public_service == objective_service
    ):
        return None
    edge_id = f"trust-{public_service}-to-{objective_service}-mut"
    if any(edge.id == edge_id for edge in world.trust_edges):
        return None
    return world.replace_edges(
        trust=world.trust_edges
        + (
            EdgeSpec(
                id=edge_id,
                kind="trust",
                source=public_service,
                target=objective_service,
                label="curriculum_route",
            ),
        )
    )


def _add_noise_source(world: WorldIR) -> WorldIR | None:
    workload = world.green_workload.model_copy(
        update={
            "max_parallel_actions": min(
                world.green_workload.max_parallel_actions + 1, 8
            ),
            "reactive_branch_budget": min(
                world.green_workload.reactive_branch_budget + 1, 4
            ),
        }
    )
    personas = list(world.green_personas)
    if personas:
        persona = personas[0]
        routine = (
            persona.routine
            if "send_update" in persona.routine
            else persona.routine + ("send_update",)
        )
        personas[0] = persona.model_copy(update={"routine": routine})
    return world.model_copy(
        update={"green_workload": workload, "green_personas": tuple(personas)}
    )


def _seed_additional_weakness(world: WorldIR) -> WorldIR | None:
    if world.mutation_bounds.max_new_weaknesses < 1:
        return None
    existing_ids = {weak.id for weak in world.weaknesses}
    existing_families = {weak.family for weak in world.weaknesses}
    family = next(
        (
            candidate
            for candidate in world.allowed_weakness_families
            if candidate not in existing_families
        ),
        None,
    )
    if family is None:
        return None
    target_service = _weakness_target(world, family)
    if target_service is None:
        return None
    weakness = _make_weakness(world, family, target_service, existing_ids=existing_ids)
    return world.model_copy(update={"weaknesses": world.weaknesses + (weakness,)})


def _alter_observability(world: WorldIR) -> WorldIR | None:
    services = list(world.services)
    for idx, service in enumerate(services):
        if service.id == "svc-siem":
            continue
        if "audit" in service.telemetry_surfaces:
            continue
        services[idx] = service.model_copy(
            update={"telemetry_surfaces": service.telemetry_surfaces + ("audit",)}
        )
        return world.model_copy(update={"services": tuple(services)})
    return None


def _patch_weakness(world: WorldIR) -> WorldIR | None:
    if not world.mutation_bounds.allow_patch_old_weaknesses:
        return None
    seeded = [weak for weak in world.weaknesses if weak.status == "seeded"]
    if not seeded:
        return None
    target = next((weak for weak in seeded if weak.family == "code_web"), seeded[0])
    remaining = tuple(weak for weak in world.weaknesses if weak.id != target.id)
    return world.model_copy(update={"weaknesses": remaining})


def _harden_route_expose_alternate(world: WorldIR) -> WorldIR | None:
    if not world.mutation_bounds.allow_patch_old_weaknesses:
        return None
    start = next(
        (service.id for service in world.services if service.kind == "web_app"), ""
    )
    alternate = next(
        (
            service.id
            for service in world.services
            if service.kind == "email" and service.id != start
        ),
        "",
    )
    objective = _first_objective_service(world)
    route_target = _route_hardening_target(world, start, objective)
    if (
        not start
        or not objective
        or not route_target
        or start == objective
        or not alternate
    ):
        return None

    direct_pairs = {(start, route_target), (route_target, start)}
    network_edges = tuple(
        edge
        for edge in world.network_edges
        if (edge.source, edge.target) not in direct_pairs
    )
    trust_edges = tuple(
        edge
        for edge in world.trust_edges
        if (edge.source, edge.target) not in direct_pairs
    )
    if len(network_edges) == len(world.network_edges) and len(trust_edges) == len(
        world.trust_edges
    ):
        return None

    alt_net_id = f"net-{alternate}-to-{objective}-alt"
    alt_trust_id = f"trust-{alternate}-to-{objective}-alt"
    if all(edge.id != alt_net_id for edge in network_edges):
        network_edges += (
            EdgeSpec(
                id=alt_net_id,
                kind="network",
                source=alternate,
                target=objective,
                label="alternate_route",
            ),
        )
    if all(edge.id != alt_trust_id for edge in trust_edges):
        trust_edges += (
            EdgeSpec(
                id=alt_trust_id,
                kind="trust",
                source=alternate,
                target=objective,
                label="alternate_route",
            ),
        )
    return world.replace_edges(network=network_edges, trust=trust_edges)


def _route_hardening_target(world: WorldIR, start: str, objective: str) -> str:
    if any(
        edge.source == start and edge.target == objective
        for edge in world.network_edges
    ):
        return objective
    objective_service = next(
        (service for service in world.services if service.id == objective), None
    )
    if objective_service is not None:
        for dependency in objective_service.dependencies:
            if any(
                edge.source == start and edge.target == dependency
                for edge in world.network_edges
            ):
                return dependency
    for edge in world.network_edges:
        if edge.source == start and edge.target not in {"svc-db"}:
            return edge.target
    return ""


def _next_host_id(prefix: str, existing: set[str]) -> str:
    base = {
        "workstation": "workstation",
        "web_app": "web",
        "email": "mail",
        "idp": "idp",
        "fileshare": "files",
        "db": "db",
        "siem": "siem",
    }.get(prefix, prefix)
    idx = 1
    while f"{base}-{idx}" in existing:
        idx += 1
    return f"{base}-{idx}"


def _next_service_id(base_service_id: str, existing: set[str]) -> str:
    if base_service_id not in existing:
        return base_service_id
    idx = 2
    while f"{base_service_id}-{idx}" in existing:
        idx += 1
    return f"{base_service_id}-{idx}"


def _next_user_id(role: str, existing: set[str]) -> str:
    idx = 1
    while f"{role}-{idx:02d}" in existing:
        idx += 1
    return f"{role}-{idx:02d}"


def _moved_asset_location(location: str, new_service_id: str) -> str:
    if "://" in location:
        _, suffix = location.split("://", 1)
        return f"{new_service_id}://{suffix}"
    if ":" in location:
        _, suffix = location.split(":", 1)
        return f"{new_service_id}:{suffix}"
    return f"{new_service_id}:{location}"


def _weakness_target(world: WorldIR, family: str) -> str | None:
    service_by_kind = {service.kind: service.id for service in world.services}
    objective_service = _first_objective_service(world)
    if family in {"code_web", "workflow_abuse"}:
        return service_by_kind.get("web_app")
    if family == "config_identity":
        return service_by_kind.get("idp")
    if family == "telemetry_blindspot":
        return service_by_kind.get("email") or service_by_kind.get("web_app")
    if objective_service:
        return objective_service
    return (
        service_by_kind.get("fileshare")
        or service_by_kind.get("db")
        or service_by_kind.get("idp")
    )


def _make_weakness(
    world: WorldIR,
    family: str,
    target_service: str,
    *,
    existing_ids: set[str],
) -> WeaknessSpec:
    suffix = 1
    weak_id = f"wk-{family.replace('_', '-')}-{suffix}"
    while weak_id in existing_ids:
        suffix += 1
        weak_id = f"wk-{family.replace('_', '-')}-{suffix}"
    kind, target_kind, target_ref = _mutation_kind_target(world, family, target_service)
    return build_catalog_weakness(
        world,
        family,
        kind=kind,
        target=target_service,
        target_kind=target_kind,
        target_ref=target_ref,
        weakness_id=weak_id,
    )


def _mutation_kind_target(
    world: WorldIR, family: str, target_service: str
) -> tuple[str, str, str]:
    if family == "code_web":
        return "sql_injection", "service", target_service
    if family == "workflow_abuse":
        workflow = next(
            (item for item in world.workflows if item.name == "document_sharing"), None
        )
        if workflow is not None:
            return "document_share_abuse", "workflow", workflow.id
        workflow = next(
            (item for item in world.workflows if item.name == "internal_email"), None
        )
        if workflow is not None:
            return "phishing_credential_capture", "workflow", workflow.id
        workflow = world.workflows[0] if world.workflows else None
        return (
            "helpdesk_reset_bypass",
            "workflow",
            workflow.id if workflow is not None else "wf-generic",
        )
    if family == "config_identity":
        if any(user.role == "it_admin" for user in world.users):
            credential = next(
                (
                    item
                    for item in world.credentials
                    if item.subject.startswith("it_admin-")
                ),
                None,
            )
            if credential is not None:
                return "weak_password", "credential", credential.id
        return "admin_surface_exposed", "service", target_service
    if family == "telemetry_blindspot":
        if target_service == "svc-email":
            return "silent_mail_rule", "telemetry", target_service
        if target_service == "svc-web":
            return "missing_web_logs", "telemetry", target_service
        return "missing_idp_logs", "telemetry", target_service
    exposed_asset = next(
        (asset.id for asset in world.assets if asset.owner_service == target_service),
        predicate_inner(world.red_objectives[0].predicate)
        if world.red_objectives
        else target_service,
    )
    if target_service == "svc-email":
        return "token_in_email", "asset", exposed_asset
    if target_service == "svc-fileshare":
        return "backup_leak", "asset", exposed_asset
    return "hardcoded_app_secret", "asset", exposed_asset


def mutation_summary(world: WorldIR) -> dict[str, object]:
    """Compact inspection view for mutated worlds used in tests and tooling."""
    return {
        "world_id": world.world_id,
        "generation": world.lineage.generation,
        "parent_world_id": world.lineage.parent_world_id,
        "mutation_ops": list(world.lineage.mutation_ops),
        "service_count": len(world.services),
        "user_count": len(world.users),
        "weakness_count": len(world.weaknesses),
        "telemetry_sources": sorted(edge.source for edge in world.telemetry_edges),
        "workflows": json.loads(
            json.dumps([wf.model_dump(mode="json") for wf in world.workflows])
        ),
    }
