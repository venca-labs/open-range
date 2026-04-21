"""Code-web family weakness builder."""

from __future__ import annotations

from open_range.contracts.validation import ReferenceAction
from open_range.contracts.world import WeaknessRealizationSpec, WeaknessSpec, WorldIR
from open_range.objectives.effects import effect_marker_token
from open_range.objectives.engine import PredicateEngine

from ..code_web.remediation import code_web_remediation_command
from ..code_web.render import code_web_realization_content
from ..code_web.specs import code_web_payload, code_web_realizations
from .common import (
    RedReferencePlan,
    WeaknessBuildContext,
    assemble_weakness_spec,
    target_ref_objective,
)


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
    del engine
    supports_staged_reference = weakness.kind == "sql_injection"
    initial_payload = {
        "action": "initial_access",
        "weakness_id": weakness.id,
        "weakness": weakness.id,
    }
    initial_payload.update(code_web_payload(world, weakness, include_asset=False))
    terminal_count = sum(1 for objective in world.red_objectives if objective.terminal)
    steps: list[ReferenceAction] = []
    satisfied: list[str] = []
    objective = target_ref_objective(world, weakness.target_ref)
    if start == weakness.target and (supports_staged_reference or objective is None):
        steps.append(
            ReferenceAction(
                actor="red",
                kind="api",
                target=weakness.target,
                payload=initial_payload,
            )
        )
    if objective is not None and (
        not supports_staged_reference or start != weakness.target or terminal_count == 1
    ):
        objective_payload = {
            "action": "collect_secret",
            "weakness_id": weakness.id,
            "weakness": weakness.id,
            "objective": objective,
        }
        objective_payload.update(code_web_payload(world, weakness))
        objective_payload["expect_contains"] = effect_marker_token(weakness)
        steps.append(
            ReferenceAction(
                actor="red",
                kind="api",
                target=weakness.target,
                payload=objective_payload,
            )
        )
        satisfied.append(objective)
    if not steps:
        steps.append(
            ReferenceAction(
                actor="red",
                kind="api",
                target=weakness.target,
                payload=initial_payload,
            )
        )
    return RedReferencePlan(
        steps=tuple(steps),
        current=weakness.target,
        satisfied_predicates=tuple(satisfied),
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
    asset_id = next(
        (
            asset.id
            for asset in world.assets
            if asset.asset_class in {"crown_jewel", "sensitive"}
        ),
        world.assets[0].id if world.assets else "svc-web",
    )
    return ("svc-web", asset_id)


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


def render_realization_content(
    world: WorldIR,
    weakness: WeaknessSpec,
    realization: WeaknessRealizationSpec,
) -> str:
    return code_web_realization_content(world, weakness, realization)
