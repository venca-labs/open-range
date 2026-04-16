"""Shared helpers for family-specific weakness builders."""

from __future__ import annotations

import shlex
from dataclasses import dataclass

from open_range.admission.models import ReferenceAction
from open_range.manifest import WeaknessFamily
from open_range.objectives.engine import PredicateEngine
from open_range.objectives.expr import predicate_inner
from open_range.world_ir import WeaknessRealizationSpec, WeaknessSpec, WorldIR


@dataclass(frozen=True, slots=True)
class WeaknessBuildContext:
    world: WorldIR
    family: WeaknessFamily
    kind: str
    target: str
    target_kind: str
    target_ref: str
    weakness_id: str
    benchmark_tags: tuple[str, ...]
    objective_tags: tuple[str, ...]
    preconditions: tuple[str, ...]
    expected_event_signatures: tuple[str, ...]
    blue_observability_surfaces: tuple[str, ...]
    instantiation_mode: str
    remediation: str


@dataclass(frozen=True, slots=True)
class RedReferencePlan:
    steps: tuple[ReferenceAction, ...]
    current: str
    satisfied_predicates: tuple[str, ...] = ()


def first_objective_service(world: WorldIR) -> str:
    objective = next(iter(world.red_objectives), None)
    if objective is None:
        return world.services[0].id
    asset_id = predicate_inner(objective.predicate)
    asset = next((item for item in world.assets if item.id == asset_id), None)
    if asset is not None:
        return asset.owner_service
    return "svc-siem"


def traverse_to_target(
    engine: PredicateEngine,
    start: str,
    target: str,
) -> tuple[ReferenceAction, ...]:
    if start == target:
        return ()
    steps = [
        ReferenceAction(
            actor="red",
            kind="api",
            target=start,
            payload={"action": "initial_access"},
        )
    ]
    path = engine.shortest_path(start, target)
    for service_id in path[1:]:
        steps.append(
            ReferenceAction(
                actor="red",
                kind="api",
                target=service_id,
                payload={"action": "traverse"},
            )
        )
    return tuple(steps)


def shell_payload(
    *,
    action: str,
    weakness_id: str,
    target: str,
    path: str | None,
    expect_contains: str,
) -> dict[str, object]:
    payload: dict[str, object] = {
        "action": action,
        "weakness_id": weakness_id,
        "target": target,
        "origin": target,
        "expect_contains": expect_contains,
    }
    if path:
        payload["path"] = path
        payload["command"] = f"cat {shlex.quote(path)}"
    return payload


def first_realization_path(
    weakness: WeaknessSpec,
    *,
    kind: str | None = None,
) -> str | None:
    for realization in weakness.realization:
        if kind is not None and realization.kind != kind:
            continue
        return realization.path
    return None


def target_ref_objective(world: WorldIR, target_ref: str) -> str | None:
    for objective in world.red_objectives:
        if target_ref and target_ref in objective.predicate:
            return objective.predicate
    return None


def mailbox_from_path(path: str) -> str:
    slug = path.split("/mailboxes/", 1)[1].split("/", 1)[0]
    return slug.replace("_at_", "@").replace("_", ".")


def effect_marker_command(
    *,
    realization_path: str,
    effect_path: str,
    effect_content: str,
    markers: tuple[str, ...],
) -> str:
    tests = " && ".join(
        [f"test -f {shlex.quote(realization_path)}"]
        + [
            f"grep -Fq {shlex.quote(marker)} {shlex.quote(realization_path)}"
            for marker in markers
        ]
    )
    return (
        f"{tests} && mkdir -p {shlex.quote(effect_path.rsplit('/', 1)[0])} && "
        f"printf %s {shlex.quote(effect_content)} > {shlex.quote(effect_path)} && "
        f"cat {shlex.quote(effect_path)}"
    )


def secret_material(world: WorldIR, target_ref: str) -> str:
    asset = next((item for item in world.assets if item.id == target_ref), None)
    if asset is not None:
        return f"seeded-{asset.asset_class}-{asset.id}"
    user = next((item for item in world.users if item.id == target_ref), None)
    if user is not None:
        return f"{user.id}-pass"
    credential = next(
        (item for item in world.credentials if item.id == target_ref),
        None,
    )
    if credential is not None:
        return f"seeded-secret-{credential.id}"
    return target_ref


def assemble_weakness_spec(
    context: WeaknessBuildContext,
    *,
    realization: tuple[WeaknessRealizationSpec, ...],
    remediation_command: str,
) -> WeaknessSpec:
    return WeaknessSpec(
        id=context.weakness_id,
        family=context.family,
        kind=context.kind,
        target=context.target,
        target_kind=context.target_kind,
        target_ref=context.target_ref,
        benchmark_tags=context.benchmark_tags,
        objective_tags=context.objective_tags,
        preconditions=context.preconditions,
        expected_event_signatures=context.expected_event_signatures,
        blue_observability_surfaces=context.blue_observability_surfaces,
        realization=realization,
        remediation=context.remediation,
        remediation_id=f"remediate-{context.kind}",
        remediation_kind="shell",
        remediation_command=remediation_command,
        instantiation_mode=context.instantiation_mode,
    )


def realization_summary(family: WeaknessFamily, kind: str) -> str:
    return (
        f"{family}::{kind} realized for deterministic admission and runtime validation"
    )


def write_text_command(path: str, content: str) -> str:
    directory = path.rsplit("/", 1)[0]
    return (
        f"mkdir -p {shlex.quote(directory)} && cat <<'EOF' > {shlex.quote(path)}\n"
        f"{content}EOF"
    )


def mailbox_remediated_message(kind: str) -> str:
    return (
        f"Subject: {kind} remediated\n\n"
        "OpenRange rotated or revoked the affected material.\n"
    )


def mailbox_for_ref(world: WorldIR, target_ref: str) -> str:
    user = next((item for item in world.users if item.id == target_ref), None)
    if user is not None and user.email:
        return user.email
    credential = next(
        (
            item
            for item in world.credentials
            if item.id == target_ref or item.subject == target_ref
        ),
        None,
    )
    if credential is not None:
        subject = next(
            (item for item in world.users if item.id == credential.subject), None
        )
        if subject is not None and subject.email:
            return subject.email
    workflow = next(
        (
            item
            for item in world.workflows
            if item.id == target_ref or item.name == target_ref
        ),
        None,
    )
    if workflow is not None:
        for step in workflow.steps:
            subject = next(
                (
                    item
                    for item in world.users
                    if item.role == step.actor_role and item.email
                ),
                None,
            )
            if subject is not None:
                return subject.email
    fallback = next(
        (item.email for item in world.users if item.email and item.role != "it_admin"),
        "",
    )
    if fallback:
        return fallback
    return next(
        (item.email for item in world.users if item.email), "openrange@corp.local"
    )


def mailbox_slug(mailbox: str) -> str:
    return mailbox.replace("@", "_at_").replace(".", "_")
