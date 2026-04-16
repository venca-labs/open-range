"""Shared helpers for family-specific weakness builders."""

from __future__ import annotations

import shlex
from dataclasses import dataclass

from open_range.manifest import WeaknessFamily
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
