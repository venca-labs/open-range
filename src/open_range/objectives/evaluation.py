"""Pure objective evaluation helpers."""

from __future__ import annotations

from collections.abc import Iterable, Mapping

from open_range.objectives.common import (
    event_linked_predicates,
    event_target,
    event_type,
    snapshot_mapping,
)
from open_range.objectives.models import ObjectiveGraderSpec


def evaluate_objective_grader(
    predicate: str,
    grader: ObjectiveGraderSpec,
    *,
    snapshot: object,
    events: Iterable[object],
    service_health: Mapping[str, float],
) -> bool:
    linked_events = [
        event for event in events if predicate in event_linked_predicates(event)
    ]
    if grader.grader_kind == "event_present":
        return any(
            event_type(event) == grader.event_type
            and (not grader.target_id or event_target(event) == grader.target_id)
            for event in linked_events
        )
    if grader.grader_kind == "service_health":
        health = service_health.get(grader.service_id or grader.target_id, 1.0)
        return health < 0.9 or any(
            event_type(event) == "ServiceDegraded" for event in linked_events
        )
    if grader.grader_kind == "file_exists":
        file_assets = snapshot_mapping(snapshot, "file_assets")
        has_target = (
            grader.target_id in file_assets or grader.path in file_assets.values()
        )
        return has_target and bool(linked_events)
    if grader.grader_kind in {"db_row_read", "db_row_write"}:
        db_seed_state = snapshot_mapping(snapshot, "db_seed_state")
        db_services = db_seed_state.get("services", [])
        return grader.service_id in db_services and bool(linked_events)
    if grader.grader_kind == "outbound_request":
        return bool(linked_events)
    return False


def evaluate_red_objectives(
    *,
    snapshot: object,
    objective_specs: Iterable[object],
    graders: Mapping[str, ObjectiveGraderSpec | None],
    events: Iterable[object],
    service_health: Mapping[str, float],
) -> set[str]:
    satisfied: set[str] = set()
    event_list = tuple(events)
    for objective in objective_specs:
        predicate = getattr(objective, "predicate", "")
        if not predicate:
            continue
        grader = graders.get(predicate)
        if grader is None:
            if any(predicate in event_linked_predicates(event) for event in event_list):
                satisfied.add(predicate)
            continue
        if evaluate_objective_grader(
            predicate,
            grader,
            snapshot=snapshot,
            events=event_list,
            service_health=service_health,
        ):
            satisfied.add(predicate)
    return satisfied
