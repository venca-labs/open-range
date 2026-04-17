"""Runtime briefing and observation formatting helpers."""

from __future__ import annotations

from collections.abc import Mapping

from open_range.contracts.runtime import ExternalRole, ServiceHealth
from open_range.contracts.world import WeaknessSpec, WorldIR
from open_range.objectives.engine import PredicateEngine

_BRIEFING_SURFACE_LABELS = {
    "code_web": "web surface",
    "config_identity": "identity surface",
    "secret_exposure": "secret surface",
    "workflow_abuse": "workflow surface",
    "telemetry_blindspot": "telemetry gap",
}


def service_health_tuple(
    service_health: Mapping[str, float],
) -> tuple[ServiceHealth, ...]:
    return tuple(
        ServiceHealth(service_id=service_id, health=health)
        for service_id, health in sorted(service_health.items())
    )


def observation_stdout(
    *,
    sim_time: float,
    world: WorldIR | None,
    actor: ExternalRole,
    first_observation: bool,
    prompt_mode: str,
    predicates: PredicateEngine | None,
) -> str:
    base = f"sim_time={sim_time:.2f}"
    if not first_observation or world is None:
        return base
    return (
        f"{briefing_text(world, actor, prompt_mode=prompt_mode, predicates=predicates)}\n"
        f"{base}"
    )


def briefing_text(
    world: WorldIR,
    actor: ExternalRole,
    *,
    prompt_mode: str,
    predicates: PredicateEngine | None,
) -> str:
    objectives = world.red_objectives if actor == "red" else world.blue_objectives
    public_services = ",".join(
        service.id
        for service in world.services
        if predicates is not None and predicates.is_public_service(service)
    )
    lines = [
        f"briefing_mode={prompt_mode}",
        f"business={world.business_archetype}",
        f"public_services={public_services or 'none'}",
        f"objectives={'; '.join(objective.predicate for objective in objectives) or 'none'}",
    ]
    if prompt_mode == "one_day":
        surfaces = ", ".join(
            briefing_surface_summary(world, weakness)
            for weakness in world.weaknesses
            if weakness.family != "telemetry_blindspot" or actor == "blue"
        )
        lines.append(f"known_risky_surfaces={surfaces or 'none'}")
    return "\n".join(lines)


def briefing_surface_summary(world: WorldIR, weakness: WeaknessSpec) -> str:
    service = next(
        (service for service in world.services if service.id == weakness.target),
        None,
    )
    service_label = service.kind if service is not None else weakness.target_kind
    family_label = _BRIEFING_SURFACE_LABELS.get(weakness.family, weakness.family)
    return f"{service_label} {family_label}"
