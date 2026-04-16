"""Deterministic weakness seeding."""

from __future__ import annotations

import random
from typing import Protocol

from open_range.catalog.weaknesses import (
    available_weakness_families_for_service_kinds,
    benchmark_tags_for_family,
    default_target_kind_for_family,
    expected_events_for_weakness,
    instantiation_mode_for_family,
    is_supported_weakness_kind,
    observability_surfaces_for_weakness,
    preconditions_for_weakness,
    resolve_pinned_target,
    select_seed_families,
    supported_weakness_kinds_for_family,
)
from open_range.manifest import (
    PinnedWeaknessSpec,
    WeaknessFamily,
)
from open_range.objectives import weakness_objective_tags
from open_range.weakness_families import (
    WeaknessBuildContext,
    build_family_weakness,
    default_kind_for_family,
    normalize_target_for_family,
    seed_family_target,
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
                self._seed_pinned(world, pinned) for pinned in world.pinned_weaknesses
            )
        else:
            available = sorted(self._available_families(world))
            if not available:
                return world
            weakness_count = min(world.target_weakness_count, len(available))
            selected = select_seed_families(
                available,
                weakness_count=weakness_count,
                rng=rng,
            )
            weaknesses = tuple(self._seed_family(world, family) for family in selected)
        lineage = world.lineage.model_copy(
            update={
                "mutation_ops": tuple(world.lineage.mutation_ops)
                + tuple(f"seed:{weak.family}:{weak.target}" for weak in weaknesses)
            }
        )
        return world.model_copy(update={"weaknesses": weaknesses, "lineage": lineage})

    @staticmethod
    def _available_families(world: WorldIR) -> set[WeaknessFamily]:
        service_kinds = {service.kind for service in world.services}
        available: set[WeaknessFamily] = set(
            available_weakness_families_for_service_kinds(service_kinds)
        )
        if world.allowed_weakness_families:
            available &= set(world.allowed_weakness_families)
        return available

    @staticmethod
    def _seed_pinned(world: WorldIR, pinned: PinnedWeaknessSpec) -> WeaknessSpec:
        target, target_kind, target_ref = resolve_pinned_target(world, pinned.target)
        return CatalogWeaknessSeeder._build_weakness(
            world,
            pinned.family,
            kind=pinned.kind,
            target=target,
            target_kind=target_kind,
            target_ref=target_ref,
        )

    @staticmethod
    def _seed_family(world: WorldIR, family: WeaknessFamily) -> WeaknessSpec:
        target, target_ref = seed_family_target(world, family)
        return CatalogWeaknessSeeder._build_weakness(
            world,
            family,
            kind=default_kind_for_family(world, family, target, target_ref),
            target=target,
            target_kind=default_target_kind_for_family(family),
            target_ref=target_ref,
        )

    @staticmethod
    def _build_weakness(
        world: WorldIR,
        family: WeaknessFamily,
        *,
        kind: str,
        target: str,
        target_kind: str,
        target_ref: str,
    ) -> WeaknessSpec:
        return build_catalog_weakness(
            world,
            family,
            kind=kind,
            target=target,
            target_kind=target_kind,
            target_ref=target_ref,
        )


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
    if not is_supported_weakness_kind(family, kind):
        raise ValueError(f"unsupported kind {kind!r} for family {family!r}")
    target, target_kind, target_ref = normalize_target_for_family(
        world, family, kind, target, target_kind, target_ref
    )
    weak_id = weakness_id or _weakness_id(family, kind, target, target_ref)
    return build_family_weakness(
        WeaknessBuildContext(
            world=world,
            family=family,
            kind=kind,
            target=target,
            target_kind=target_kind,
            target_ref=target_ref,
            weakness_id=weak_id,
            benchmark_tags=benchmark_tags_for_family(family),
            objective_tags=weakness_objective_tags(family, kind),
            preconditions=preconditions_for_weakness(
                family,
                kind=kind,
                target_ref=target_ref,
            ),
            expected_event_signatures=expected_events_for_weakness(family, kind),
            blue_observability_surfaces=observability_surfaces_for_weakness(
                family, kind=kind, target=target
            ),
            instantiation_mode=instantiation_mode_for_family(family),
            remediation=_remediation_text(kind),
        )
    )


def _weakness_id(
    family: WeaknessFamily, kind: str, target: str, target_ref: str
) -> str:
    suffix = target_ref or target
    return f"wk-{kind.replace('_', '-')}-{suffix}"


def _remediation_text(kind: str) -> str:
    return f"apply remediation for {kind.replace('_', ' ')}"
