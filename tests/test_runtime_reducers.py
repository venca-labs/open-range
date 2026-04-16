from __future__ import annotations

from open_range.runtime_reducers import (
    SERVICE_HEALTH_BLUE_OBJECTIVE,
    blue_objectives_after_continuity,
    continuity_for_service_health,
)


def test_continuity_for_service_health_keeps_current_average_rule() -> None:
    assert continuity_for_service_health({}) == 1.0
    assert continuity_for_service_health({"svc-web": 1.0, "svc-db": 0.5}) == 0.75


def test_blue_objectives_after_continuity_keeps_service_health_rule() -> None:
    assert (
        blue_objectives_after_continuity(
            {SERVICE_HEALTH_BLUE_OBJECTIVE},
            continuity=0.4,
            continuity_threshold=0.9,
            continuity_enforced=True,
        )
        == set()
    )
    assert blue_objectives_after_continuity(
        set(),
        continuity=0.95,
        continuity_threshold=0.9,
        continuity_enforced=True,
    ) == {SERVICE_HEALTH_BLUE_OBJECTIVE}
    assert (
        blue_objectives_after_continuity(
            set(),
            continuity=0.2,
            continuity_threshold=0.9,
            continuity_enforced=False,
        )
        == set()
    )
