"""Runtime briefing and observation formatting helpers."""

from __future__ import annotations

from collections.abc import Mapping

from open_range.contracts.runtime import ExternalRole, ServiceHealth
from open_range.contracts.world import WorldIR
from open_range.objectives.engine import PredicateEngine


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
    public_services = ",".join(
        service.id
        for service in world.services
        if predicates is not None and predicates.is_public_service(service)
    )
    lines = [
        f"briefing_mode={prompt_mode}",
        f"business={world.business_archetype}",
        f"public_services={public_services or 'none'}",
        f"public_entrypoints={briefing_public_entrypoints(world, predicates) or 'none'}",
        f"mission={'; '.join(briefing_goals(world, actor)) or 'none'}",
    ]
    return "\n".join(lines)


def briefing_goals(world: WorldIR, actor: ExternalRole) -> tuple[str, ...]:
    objectives = world.red_objectives if actor == "red" else world.blue_objectives
    return tuple(
        goal
        for objective in objectives
        if (goal := briefing_goal_text(objective.predicate))
    )


def briefing_public_entrypoints(
    world: WorldIR,
    predicates: PredicateEngine | None,
) -> str:
    if predicates is None:
        return ""
    entrypoints: list[str] = []
    for service in world.services:
        if not predicates.is_public_service(service):
            continue
        if service.kind == "web_app":
            for port in service.ports:
                if port == 443:
                    entrypoints.append(f"https://{service.id}:{port}/")
                else:
                    entrypoints.append(f"http://{service.id}:{port}/")
            continue
        if service.kind == "email":
            protocol_by_port = {
                25: "smtp",
                587: "submission",
                993: "imaps",
            }
            for port in service.ports:
                entrypoints.append(
                    f"{protocol_by_port.get(port, 'tcp')}://{service.id}:{port}"
                )
            continue
        for port in service.ports:
            entrypoints.append(f"tcp://{service.id}:{port}")
    return ", ".join(entrypoints)


def briefing_goal_text(predicate: str) -> str:
    name, _, rest = predicate.partition("(")
    raw_arg = rest[:-1] if rest.endswith(")") else rest
    arg = briefing_goal_arg_text(raw_arg)
    mapping = {
        "credential_obtained": lambda value: (
            "obtain administrative credentials"
            if raw_arg.endswith("_cred") or "admin" in raw_arg
            else f"obtain {value}"
        ),
        "asset_read": lambda value: (
            "read sensitive documents"
            if "docs" in raw_arg or "document" in raw_arg
            else f"read {value}"
        ),
        "intrusion_detected": lambda value: (
            "detect initial access quickly"
            if raw_arg == "initial_access"
            else f"detect intrusion before {value}"
        ),
        "intrusion_contained": lambda value: (
            "contain intrusion before sensitive data is read"
            if raw_arg == "before_asset_read"
            else f"contain intrusion before {value}"
        ),
        "service_health_above": lambda value: (
            f"keep service health at or above {value}"
        ),
    }
    formatter = mapping.get(name)
    if formatter is None:
        return predicate.replace("_", " ")
    return formatter(arg)


def briefing_goal_arg_text(value: str) -> str:
    text = value.replace("_", " ").strip()
    if text.endswith(" cred"):
        return text[:-5] + " credentials"
    if text.endswith(" creds"):
        return text[:-6] + " credentials"
    if text.endswith(" docs"):
        return text[:-5] + " documents"
    return text
