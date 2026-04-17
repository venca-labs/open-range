"""Family-specific weakness builders."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from types import ModuleType

from open_range.catalog.weaknesses import (
    default_target_kind_for_family,
    is_supported_weakness_kind,
    weakness_build_defaults,
    weakness_id_for,
)
from open_range.contracts.world import WeaknessRealizationSpec, WeaknessSpec, WorldIR
from open_range.objectives.engine import PredicateEngine

from . import (
    code_web,
    config_identity,
    secret_exposure,
    telemetry_blindspot,
    workflow_abuse,
)
from .common import RedReferencePlan, WeaknessBuildContext


@dataclass(frozen=True, slots=True)
class _FamilyOps:
    build: Callable[[WeaknessBuildContext], WeaknessSpec]
    seed_defaults: Callable[[WorldIR], tuple[str, str]]
    default_kind: Callable[[WorldIR, str, str], str]
    normalize_target: Callable[[WorldIR, str, str, str, str], tuple[str, str, str]]
    mutation_target_service: Callable[[WorldIR], str | None]
    mutation_spec: Callable[[WorldIR, str], tuple[str, str, str]]
    build_red_reference_plan: Callable[
        [WorldIR, PredicateEngine, str, WeaknessSpec], RedReferencePlan
    ]
    render_realization_content: Callable[
        [WorldIR, WeaknessSpec, WeaknessRealizationSpec], str
    ]


def _module_ops(module: ModuleType) -> _FamilyOps:
    return _FamilyOps(
        build=module.build,
        seed_defaults=module.seed_defaults,
        default_kind=module.default_kind,
        normalize_target=module.normalize_target,
        mutation_target_service=module.mutation_target_service,
        mutation_spec=module.mutation_spec,
        build_red_reference_plan=module.build_red_reference_plan,
        render_realization_content=module.render_realization_content,
    )


_FAMILY_REGISTRY = {
    module.__name__.rpartition(".")[2]: _module_ops(module)
    for module in (
        code_web,
        workflow_abuse,
        secret_exposure,
        config_identity,
        telemetry_blindspot,
    )
}


def _family_ops(family: str, *, label: str) -> _FamilyOps:
    ops = _FAMILY_REGISTRY.get(family)
    if ops is None:
        raise ValueError(f"unsupported weakness family {family!r} for {label}")
    return ops


def build_catalog_weakness_for_family(
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
    ops = _family_ops(family, label="builder")
    target, target_kind, target_ref = ops.normalize_target(
        world, kind, target, target_kind, target_ref
    )
    defaults = weakness_build_defaults(
        family,
        kind=kind,
        target=target,
        target_ref=target_ref,
    )
    return ops.build(
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
    ops = _family_ops(family, label="seed defaults")
    target, target_ref = ops.seed_defaults(world)
    return build_catalog_weakness_for_family(
        world,
        family,
        kind=ops.default_kind(world, target, target_ref),
        target=target,
        target_kind=default_target_kind_for_family(family),
        target_ref=target_ref,
    )


def mutation_target_service_for_family(world: WorldIR, family: str) -> str | None:
    return _family_ops(family, label="mutation target service").mutation_target_service(
        world
    )


def mutation_spec_for_family(
    world: WorldIR,
    family: str,
    target_service: str,
) -> tuple[str, str, str]:
    return _family_ops(family, label="mutation spec").mutation_spec(
        world, target_service
    )


def build_red_reference_plan_for_family(
    world: WorldIR,
    engine: PredicateEngine,
    start: str,
    weakness: WeaknessSpec,
) -> RedReferencePlan:
    return _family_ops(
        weakness.family,
        label="red reference builder",
    ).build_red_reference_plan(world, engine, start, weakness)


def render_realization_content_for_family(
    world: WorldIR,
    weakness: WeaknessSpec,
    realization: WeaknessRealizationSpec,
) -> str:
    return _family_ops(
        weakness.family,
        label="realization renderer",
    ).render_realization_content(world, weakness, realization)


__all__ = [
    "RedReferencePlan",
    "WeaknessBuildContext",
    "build_catalog_weakness_for_family",
    "build_red_reference_plan_for_family",
    "mutation_spec_for_family",
    "mutation_target_service_for_family",
    "render_realization_content_for_family",
    "seed_catalog_weakness",
]
