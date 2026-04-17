"""Public facade for deterministic weakness seeding."""

from __future__ import annotations

import random
from typing import Protocol

from open_range.catalog.weaknesses import (
    resolve_pinned_target,
    selected_seed_families_for_world,
    supported_weakness_kinds_for_family,
)
from open_range.contracts.world import WeaknessSpec, WorldIR
from open_range.manifest import (
    PinnedWeaknessSpec,
    WeaknessFamily,
)

from ..objectives.effects import effect_marker_cleanup_command, effect_marker_service
from .code_web import code_web_cleanup_commands
from .families import (
    build_catalog_weakness_for_family as build_catalog_weakness,
)
from .families import (
    build_red_reference_plan_for_family as build_reference_plan_for_weakness,
)
from .families import (
    mutation_spec_for_family as mutation_spec,
)
from .families import (
    mutation_target_service_for_family as mutation_target_service,
)
from .families import (
    render_realization_content_for_family as render_realization_content,
)
from .families import (
    seed_catalog_weakness,
)
from .families.common import first_objective_service as first_objective_service

__all__ = [
    "CatalogWeaknessSeeder",
    "WeaknessSeeder",
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
