"""Runtime briefing and observation formatting helpers."""

from __future__ import annotations

from collections.abc import Mapping

from open_range.contracts.runtime import ExternalRole, ServiceHealth
from open_range.contracts.world import WorldIR
from open_range.objectives.engine import PredicateEngine

_BRIEFING_SURFACE_LABELS = {
    "web_app": "web surface",
    "idp": "identity surface",
    "email": "workflow surface",
    "fileshare": "shared document surface",
    "db": "data surface",
    "siem": "telemetry surface",
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
        surfaces = ", ".join(briefing_surface_summary(world, actor))
        lines.append(f"known_risky_surfaces={surfaces or 'none'}")
    return "\n".join(lines)


def briefing_surface_summary(world: WorldIR, actor: ExternalRole) -> tuple[str, ...]:
    labels: list[str] = []
    seen: set[str] = set()
    for service in world.services:
        if actor != "blue" and service.kind == "siem":
            continue
        label = _BRIEFING_SURFACE_LABELS.get(service.kind)
        if label and label not in seen:
            labels.append(label)
            seen.add(label)
    return tuple(labels)
