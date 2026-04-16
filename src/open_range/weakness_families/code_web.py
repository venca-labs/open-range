"""Code-web family weakness builder."""

from __future__ import annotations

from open_range.code_web import code_web_realizations, code_web_remediation_command
from open_range.weakness_families.common import (
    WeaknessBuildContext,
    assemble_weakness_spec,
)
from open_range.world_ir import WorldIR


def build(context: WeaknessBuildContext):
    base = assemble_weakness_spec(
        context,
        realization=(),
        remediation_command="",
    )
    return base.model_copy(
        update={
            "realization": code_web_realizations(context.world, base),
            "remediation_command": code_web_remediation_command(base),
        }
    )


def seed_defaults(world: WorldIR) -> tuple[str, str]:
    del world
    return ("svc-web", "svc-web")


def default_kind(world: WorldIR, target: str, target_ref: str) -> str:
    del target, target_ref
    return (
        world.allowed_code_flaw_kinds[0]
        if world.allowed_code_flaw_kinds
        else "sql_injection"
    )


def normalize_target(
    world: WorldIR,
    kind: str,
    target: str,
    target_kind: str,
    target_ref: str,
) -> tuple[str, str, str]:
    del world, kind
    return (target, target_kind, target_ref)
