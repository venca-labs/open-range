"""Code-web family weakness builder."""

from __future__ import annotations

from open_range.admission import ReferenceAction
from open_range.code_web import (
    code_web_payload,
    code_web_realizations,
    code_web_remediation_command,
)
from open_range.predicates import PredicateEngine
from open_range.weakness_families.common import (
    RedReferencePlan,
    WeaknessBuildContext,
    assemble_weakness_spec,
)
from open_range.world_ir import WeaknessSpec, WorldIR


def mutation_target_service(world: WorldIR) -> str | None:
    return next(
        (service.id for service in world.services if service.kind == "web_app"), None
    )


def mutation_spec(world: WorldIR, target_service: str) -> tuple[str, str, str]:
    del world
    return ("sql_injection", "service", target_service)


def build_red_reference_plan(
    world: WorldIR,
    engine: PredicateEngine,
    start: str,
    weakness: WeaknessSpec,
) -> RedReferencePlan:
    del engine, start
    payload = {
        "action": "initial_access",
        "weakness_id": weakness.id,
        "weakness": weakness.id,
    }
    payload.update(code_web_payload(world, weakness))
    return RedReferencePlan(
        steps=(
            ReferenceAction(
                actor="red",
                kind="api",
                target=weakness.target,
                payload=payload,
            ),
        ),
        current=weakness.target,
    )


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
