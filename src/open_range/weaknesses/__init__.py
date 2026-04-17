"""Public facade for deterministic weakness seeding."""

from __future__ import annotations

import random
from typing import Protocol

from open_range.catalog.weaknesses import (
    resolve_pinned_target,
    selected_seed_families_for_world,
    supported_weakness_kinds_for_family,
)
from open_range.manifest import (
    PinnedWeaknessSpec,
    WeaknessFamily,
)
from open_range.objectives.engine import PredicateEngine
from open_range.world_ir import (
    WeaknessRealizationSpec,
    WeaknessSpec,
    WorldIR,
)

from ..objectives.effects import effect_marker_cleanup_command, effect_marker_service
from .code_web import code_web_cleanup_commands
from .families import (
    build_catalog_weakness_for_family,
    build_red_reference_plan_for_family,
    mutation_spec_for_family,
    mutation_target_service_for_family,
    render_realization_content_for_family,
    seed_catalog_weakness,
)
from .families.common import first_objective_service as first_objective_service


class WeaknessSeeder(Protocol):
    def apply(self, world: WorldIR, seed: int | None = None) -> WorldIR: ...


class CatalogWeaknessSeeder:
    """Apply a bounded deterministic weakness catalog to a compiled world."""

    def apply(self, world: WorldIR, seed: int | None = None) -> WorldIR:
        rng = random.Random(world.seed if seed is None else seed)
        if world.pinned_weaknesses:
            weaknesses = tuple(
                _build_pinned_weakness(world, pinned)
                for pinned in world.pinned_weaknesses
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


def supported_weakness_kinds(family: WeaknessFamily) -> tuple[str, ...]:
    return supported_weakness_kinds_for_family(family)


def build_catalog_weakness(
    world: WorldIR,
    family: WeaknessFamily,
    *,
    kind: str,
    target: str,
    target_kind: str,
    target_ref: str,
    weakness_id: str | None = None,
) -> WeaknessSpec:
    return build_catalog_weakness_for_family(
        world,
        family,
        kind=kind,
        target=target,
        target_kind=target_kind,
        target_ref=target_ref,
        weakness_id=weakness_id,
    )


def build_reference_plan_for_weakness(
    world: WorldIR,
    engine: PredicateEngine,
    start: str,
    weakness: WeaknessSpec,
):
    return build_red_reference_plan_for_family(world, engine, start, weakness)


def mutation_target_service(world: WorldIR, family: WeaknessFamily) -> str | None:
    return mutation_target_service_for_family(world, family)


def mutation_spec(
    world: WorldIR,
    family: WeaknessFamily,
    target_service: str,
) -> tuple[str, str, str]:
    return mutation_spec_for_family(world, family, target_service)


def render_realization_content(
    world: WorldIR,
    weakness: WeaknessSpec,
    realization: WeaknessRealizationSpec,
) -> str:
    return render_realization_content_for_family(world, weakness, realization)


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


def _build_pinned_weakness(world: WorldIR, pinned: PinnedWeaknessSpec) -> WeaknessSpec:
    target, target_kind, target_ref = resolve_pinned_target(world, pinned.target)
    return build_catalog_weakness(
        world,
        pinned.family,
        kind=pinned.kind,
        target=target,
        target_kind=target_kind,
        target_ref=target_ref,
    )
