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
from open_range.weakness_families import (
    build_catalog_weakness_for_family,
    seed_catalog_weakness,
)
from open_range.world_ir import WeaknessSpec, WorldIR


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
