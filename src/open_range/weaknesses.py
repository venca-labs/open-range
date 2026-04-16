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
            selected_families: list[WeaknessFamily] = []
            remaining = list(available)
            if "code_web" in remaining and weakness_count > 0:
                selected_families.append("code_web")
                remaining.remove("code_web")
            if len(selected_families) < weakness_count:
                selected_families.extend(
                    sorted(
                        rng.sample(remaining, k=weakness_count - len(selected_families))
                    )
                )
            selected = tuple(selected_families)
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
        target, target_kind, target_ref = _resolve_pinned_target(world, pinned.target)
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
            kind=_default_kind(world, family, target, target_ref),
            target=target,
            target_kind=_default_target_kind(family),
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
            expected_event_signatures=_expected_events(family, kind),
            blue_observability_surfaces=observability_surfaces_for_weakness(
                family, kind=kind, target=target
            ),
            instantiation_mode=instantiation_mode_for_family(family),
            remediation=_remediation_text(kind),
        )
    )


def _default_target_kind(family: WeaknessFamily) -> str:
    return default_target_kind_for_family(family)


def _default_kind(
    world: WorldIR, family: WeaknessFamily, target: str, target_ref: str
) -> str:
    return default_kind_for_family(world, family, target, target_ref)


def _resolve_pinned_target(world: WorldIR, pinned_target: str) -> tuple[str, str, str]:
    target_kind, _, target_value = pinned_target.partition(":")
    if not target_value:
        target_kind = "service"
        target_value = pinned_target
    if target_kind == "service":
        if any(service.id == target_value for service in world.services):
            return target_value, target_kind, target_value
        match = next(
            (service.id for service in world.services if service.kind == target_value),
            None,
        )
        if match:
            return match, target_kind, match
        raise ValueError(f"unknown pinned service target: {target_value}")
    if target_kind == "workflow":
        workflow = next(
            (
                workflow
                for workflow in world.workflows
                if workflow.id == target_value
                or workflow.name == target_value
                or workflow.id == f"wf-{target_value}"
            ),
            None,
        )
        if workflow is None:
            raise ValueError(f"unknown pinned workflow target: {target_value}")
        target = next(
            (step.service for step in workflow.steps if step.service), "svc-web"
        )
        return target, target_kind, workflow.id
    if target_kind == "asset":
        asset = next(
            (asset for asset in world.assets if asset.id == target_value), None
        )
        if asset is None:
            raise ValueError(f"unknown pinned asset target: {target_value}")
        return asset.owner_service, target_kind, asset.id
    if target_kind == "credential":
        credential = next(
            (
                credential
                for credential in world.credentials
                if credential.id == target_value or credential.subject == target_value
            ),
            None,
        )
        if credential is None:
            raise ValueError(f"unknown pinned credential target: {target_value}")
        service = credential.scope[0] if credential.scope else "svc-idp"
        return service, target_kind, credential.id
    if target_kind == "telemetry":
        service = next(
            (
                edge.source
                for edge in world.telemetry_edges
                if edge.source == target_value
            ),
            None,
        )
        if service is None:
            raise ValueError(f"unknown pinned telemetry target: {target_value}")
        return service, target_kind, service
    raise ValueError(f"unsupported pinned weakness target kind: {target_kind}")


def _weakness_id(
    family: WeaknessFamily, kind: str, target: str, target_ref: str
) -> str:
    suffix = target_ref or target
    return f"wk-{kind.replace('_', '-')}-{suffix}"


def _expected_events(family: WeaknessFamily, kind: str) -> tuple[str, ...]:
    return expected_events_for_weakness(family, kind)


def _remediation_text(kind: str) -> str:
    return f"apply remediation for {kind.replace('_', ' ')}"
