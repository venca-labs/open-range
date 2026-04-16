"""Family-specific weakness builders."""

from __future__ import annotations

from collections.abc import Callable

from open_range.predicates import PredicateEngine
from open_range.weakness_families import (
    code_web,
    config_identity,
    secret_exposure,
    telemetry_blindspot,
    workflow_abuse,
)
from open_range.weakness_families.common import RedReferencePlan, WeaknessBuildContext
from open_range.world_ir import WeaknessRealizationSpec, WeaknessSpec, WorldIR

_FAMILY_BUILDERS: dict[str, Callable[[WeaknessBuildContext], WeaknessSpec]] = {
    "code_web": code_web.build,
    "workflow_abuse": workflow_abuse.build,
    "secret_exposure": secret_exposure.build,
    "config_identity": config_identity.build,
    "telemetry_blindspot": telemetry_blindspot.build,
}
_FAMILY_SEED_DEFAULTS: dict[str, Callable[[WorldIR], tuple[str, str]]] = {
    "code_web": code_web.seed_defaults,
    "workflow_abuse": workflow_abuse.seed_defaults,
    "secret_exposure": secret_exposure.seed_defaults,
    "config_identity": config_identity.seed_defaults,
    "telemetry_blindspot": telemetry_blindspot.seed_defaults,
}
_FAMILY_DEFAULT_KIND_RESOLVERS: dict[str, Callable[[WorldIR, str, str], str]] = {
    "code_web": code_web.default_kind,
    "workflow_abuse": workflow_abuse.default_kind,
    "secret_exposure": secret_exposure.default_kind,
    "config_identity": config_identity.default_kind,
    "telemetry_blindspot": telemetry_blindspot.default_kind,
}
_FAMILY_TARGET_NORMALIZERS: dict[
    str, Callable[[WorldIR, str, str, str, str], tuple[str, str, str]]
] = {
    "code_web": code_web.normalize_target,
    "workflow_abuse": workflow_abuse.normalize_target,
    "secret_exposure": secret_exposure.normalize_target,
    "config_identity": config_identity.normalize_target,
    "telemetry_blindspot": telemetry_blindspot.normalize_target,
}
_FAMILY_MUTATION_TARGET_SERVICES: dict[str, Callable[[WorldIR], str | None]] = {
    "code_web": code_web.mutation_target_service,
    "workflow_abuse": workflow_abuse.mutation_target_service,
    "secret_exposure": secret_exposure.mutation_target_service,
    "config_identity": config_identity.mutation_target_service,
    "telemetry_blindspot": telemetry_blindspot.mutation_target_service,
}
_FAMILY_MUTATION_SPECS: dict[str, Callable[[WorldIR, str], tuple[str, str, str]]] = {
    "code_web": code_web.mutation_spec,
    "workflow_abuse": workflow_abuse.mutation_spec,
    "secret_exposure": secret_exposure.mutation_spec,
    "config_identity": config_identity.mutation_spec,
    "telemetry_blindspot": telemetry_blindspot.mutation_spec,
}
_FAMILY_RED_REFERENCE_BUILDERS: dict[
    str, Callable[[WorldIR, PredicateEngine, str, WeaknessSpec], RedReferencePlan]
] = {
    "workflow_abuse": workflow_abuse.build_red_reference_plan,
    "secret_exposure": secret_exposure.build_red_reference_plan,
    "config_identity": config_identity.build_red_reference_plan,
}
_FAMILY_REALIZATION_RENDERERS: dict[
    str, Callable[[WorldIR, WeaknessSpec, WeaknessRealizationSpec], str]
] = {
    "config_identity": config_identity.render_realization_content,
    "telemetry_blindspot": telemetry_blindspot.render_realization_content,
}


def _family_callable(
    family: str,
    registry: dict[str, Callable[..., object]],
    *,
    label: str,
) -> Callable[..., object]:
    entry = registry.get(family)
    if entry is None:
        raise ValueError(f"unsupported weakness family {family!r} for {label}")
    return entry


def seed_family_target(world: WorldIR, family: str) -> tuple[str, str]:
    return _family_callable(family, _FAMILY_SEED_DEFAULTS, label="seed defaults")(world)


def default_kind_for_family(
    world: WorldIR, family: str, target: str, target_ref: str
) -> str:
    return _family_callable(
        family, _FAMILY_DEFAULT_KIND_RESOLVERS, label="default kind"
    )(world, target, target_ref)


def normalize_target_for_family(
    world: WorldIR,
    family: str,
    kind: str,
    target: str,
    target_kind: str,
    target_ref: str,
) -> tuple[str, str, str]:
    return _family_callable(
        family, _FAMILY_TARGET_NORMALIZERS, label="target normalization"
    )(world, kind, target, target_kind, target_ref)


def build_family_weakness(context: WeaknessBuildContext) -> WeaknessSpec:
    return _family_callable(context.family, _FAMILY_BUILDERS, label="builder")(context)


def mutation_target_service_for_family(world: WorldIR, family: str) -> str | None:
    return _family_callable(
        family, _FAMILY_MUTATION_TARGET_SERVICES, label="mutation target service"
    )(world)


def mutation_spec_for_family(
    world: WorldIR,
    family: str,
    target_service: str,
) -> tuple[str, str, str]:
    return _family_callable(family, _FAMILY_MUTATION_SPECS, label="mutation spec")(
        world,
        target_service,
    )


def has_red_reference_plan_for_family(family: str) -> bool:
    return family in _FAMILY_RED_REFERENCE_BUILDERS


def has_realization_renderer_for_family(family: str) -> bool:
    return family in _FAMILY_REALIZATION_RENDERERS


def build_red_reference_plan_for_family(
    world: WorldIR,
    engine: PredicateEngine,
    start: str,
    weakness: WeaknessSpec,
) -> RedReferencePlan:
    return _family_callable(
        weakness.family,
        _FAMILY_RED_REFERENCE_BUILDERS,
        label="red reference builder",
    )(world, engine, start, weakness)


def render_realization_content_for_family(
    world: WorldIR,
    weakness: WeaknessSpec,
    realization: WeaknessRealizationSpec,
) -> str:
    return _family_callable(
        weakness.family,
        _FAMILY_REALIZATION_RENDERERS,
        label="realization renderer",
    )(world, weakness, realization)


__all__ = [
    "RedReferencePlan",
    "WeaknessBuildContext",
    "build_family_weakness",
    "build_red_reference_plan_for_family",
    "default_kind_for_family",
    "has_red_reference_plan_for_family",
    "has_realization_renderer_for_family",
    "mutation_spec_for_family",
    "mutation_target_service_for_family",
    "normalize_target_for_family",
    "render_realization_content_for_family",
    "seed_family_target",
]
