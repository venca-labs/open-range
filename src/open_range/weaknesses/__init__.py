"""Public facade for deterministic weakness seeding."""

from __future__ import annotations

import random
from typing import Any

from open_range.catalog.weaknesses import (
    default_target_kind_for_family,
    is_supported_weakness_kind,
    resolve_pinned_target,
    selected_seed_families_for_world,
    supported_weakness_kinds_for_family,
    weakness_build_defaults,
    weakness_id_for,
)
from open_range.contracts.world import (
    WeaknessRealizationSpec,
    WeaknessSpec,
    WorldIR,
)
from open_range.manifest import WeaknessFamily
from open_range.objectives.engine import PredicateEngine

from ..objectives.effects import effect_marker_cleanup_command, effect_marker_service
from .code_web import code_web_cleanup_commands
from .families import (
    code_web as code_web_family,
)
from .families import (
    config_identity as config_identity_family,
)
from .families import (
    secret_exposure as secret_exposure_family,
)
from .families import (
    telemetry_blindspot as telemetry_blindspot_family,
)
from .families import (
    workflow_abuse as workflow_abuse_family,
)
from .families.common import (
    RedReferencePlan,
    WeaknessBuildContext,
    first_objective_service,
)

__all__ = [
    "CatalogWeaknessSeeder",
    "build_catalog_weakness",
    "build_reference_plan_for_weakness",
    "cleanup_steps_for_weakness",
    "first_objective_service",
    "mutation_spec",
    "mutation_target_service",
    "remediation_command_for_weakness",
    "render_realization_content",
    "seed_catalog_weakness",
    "supported_weakness_kinds",
]


class CatalogWeaknessSeeder:
    """Apply a bounded deterministic weakness catalog to a compiled world."""

    def apply(self, world: WorldIR, seed: int | None = None) -> WorldIR:
        rng = random.Random(world.seed if seed is None else seed)
        if world.pinned_weaknesses:
            weaknesses = tuple(
                build_catalog_weakness(
                    world,
                    pinned.family,
                    kind=pinned.kind,
                    target=target,
                    target_kind=target_kind,
                    target_ref=target_ref,
                )
                for pinned in world.pinned_weaknesses
                for target, target_kind, target_ref in [
                    resolve_pinned_target(world, pinned.target)
                ]
            )
        else:
            selected = selected_seed_families_for_world(world, rng=rng)
            if not selected:
                return world
            weaknesses = tuple(
                seed_catalog_weakness(world, family) for family in selected
            )
        lineage = world.lineage.model_copy(
            update={
                "mutation_ops": tuple(world.lineage.mutation_ops)
                + tuple(f"seed:{weak.family}:{weak.target}" for weak in weaknesses)
            }
        )
        return world.model_copy(update={"weaknesses": weaknesses, "lineage": lineage})


_FAMILY_MODULES: dict[str, Any] = {
    "code_web": code_web_family,
    "workflow_abuse": workflow_abuse_family,
    "secret_exposure": secret_exposure_family,
    "config_identity": config_identity_family,
    "telemetry_blindspot": telemetry_blindspot_family,
}


def _family_module(family: str) -> Any:
    module = _FAMILY_MODULES.get(family)
    if module is None:
        raise ValueError(f"unsupported weakness family {family!r}")
    return module


def build_catalog_weakness(
    world: WorldIR,
    family: str,
    *,
    kind: str,
    target: str,
    target_kind: str,
    target_ref: str,
    weakness_id: str | None = None,
) -> WeaknessSpec:
    if not is_supported_weakness_kind(family, kind):
        raise ValueError(f"unsupported kind {kind!r} for family {family!r}")
    module = _family_module(family)
    target, target_kind, target_ref = module.normalize_target(
        world, kind, target, target_kind, target_ref
    )
    defaults = weakness_build_defaults(
        family,
        kind=kind,
        target=target,
        target_ref=target_ref,
    )
    return module.build(
        WeaknessBuildContext(
            world=world,
            family=family,
            kind=kind,
            target=target,
            target_kind=target_kind,
            target_ref=target_ref,
            weakness_id=weakness_id
            or weakness_id_for(kind, target=target, target_ref=target_ref),
            benchmark_tags=defaults.benchmark_tags,
            objective_tags=defaults.objective_tags,
            preconditions=defaults.preconditions,
            expected_event_signatures=defaults.expected_event_signatures,
            blue_observability_surfaces=defaults.blue_observability_surfaces,
            instantiation_mode=defaults.instantiation_mode,
            remediation=defaults.remediation,
        )
    )


def seed_catalog_weakness(world: WorldIR, family: str) -> WeaknessSpec:
    module = _family_module(family)
    target, target_ref = module.seed_defaults(world)
    return build_catalog_weakness(
        world,
        family,
        kind=module.default_kind(world, target, target_ref),
        target=target,
        target_kind=default_target_kind_for_family(family),
        target_ref=target_ref,
    )


def mutation_target_service(world: WorldIR, family: str) -> str | None:
    return _family_module(family).mutation_target_service(world)


def mutation_spec(
    world: WorldIR,
    family: str,
    target_service: str,
) -> tuple[str, str, str]:
    return _family_module(family).mutation_spec(world, target_service)


def build_reference_plan_for_weakness(
    world: WorldIR,
    engine: PredicateEngine,
    start: str,
    weakness: WeaknessSpec,
) -> RedReferencePlan:
    return _family_module(weakness.family).build_red_reference_plan(
        world, engine, start, weakness
    )


def render_realization_content(
    world: WorldIR,
    weakness: WeaknessSpec,
    realization: WeaknessRealizationSpec,
) -> str:
    return _family_module(weakness.family).render_realization_content(
        world, weakness, realization
    )


def supported_weakness_kinds(family: WeaknessFamily) -> tuple[str, ...]:
    return supported_weakness_kinds_for_family(family)


def cleanup_steps_for_weakness(weakness: WeaknessSpec) -> tuple[tuple[str, str], ...]:
    steps: list[tuple[str, str]] = []
    marker_cleanup = effect_marker_cleanup_command(weakness)
    if marker_cleanup:
        steps.append(
            (effect_marker_service(weakness) or weakness.target, marker_cleanup)
        )
    if weakness.family == "code_web":
        steps.extend(
            (weakness.target, command)
            for command in code_web_cleanup_commands(weakness)
        )
    return tuple(steps)


def remediation_command_for_weakness(weakness: WeaknessSpec) -> str:
    if weakness.remediation_kind == "shell" and (
        command := weakness.remediation_command.strip()
    ):
        return command
    if weakness.remediation.startswith("shell:"):
        return weakness.remediation.removeprefix("shell:").strip()
    return ""
