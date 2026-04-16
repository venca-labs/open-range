"""Pure reducer helpers for runtime state updates."""

from __future__ import annotations

from collections.abc import Mapping

SERVICE_HEALTH_BLUE_OBJECTIVE = "service_health_above(0.9)"


def continuity_for_service_health(service_health: Mapping[str, float]) -> float:
    if not service_health:
        return 1.0
    return sum(service_health.values()) / len(service_health)


def blue_objectives_after_continuity(
    current: set[str] | frozenset[str],
    *,
    continuity: float,
    continuity_threshold: float,
    continuity_enforced: bool,
) -> set[str]:
    updated = set(current)
    if not continuity_enforced:
        return updated
    if continuity < continuity_threshold:
        updated.discard(SERVICE_HEALTH_BLUE_OBJECTIVE)
    else:
        updated.add(SERVICE_HEALTH_BLUE_OBJECTIVE)
    return updated
