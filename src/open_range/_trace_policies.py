"""Internal reference-trace and scripted action helpers for tooling paths."""

from __future__ import annotations

from open_range.probe_planner import runtime_action
from open_range.runtime_types import Action, Observation
from open_range.snapshot import RuntimeSnapshot
from open_range.training_data import normalize_trace_action


def expected_step(steps, index: int):
    if not steps or index >= len(steps):
        return None
    return steps[index]


def reference_action(snapshot: RuntimeSnapshot, actor: str, expected) -> Action:
    if expected is None:
        return Action(actor_id=actor, role=actor, kind="sleep", payload={})
    return normalize_trace_action(snapshot, runtime_action(actor, expected))


def reference_trace_pairs(
    snapshot: RuntimeSnapshot, mode: str
) -> tuple[tuple[int, int], ...]:
    attack_count = max(1, len(snapshot.reference_bundle.reference_attack_traces))
    defense_count = max(1, len(snapshot.reference_bundle.reference_defense_traces))
    if mode == "red_only":
        return tuple((idx, idx % defense_count) for idx in range(attack_count))
    if mode in {"blue_only_live", "blue_only_from_prefix"}:
        return tuple((idx % attack_count, idx) for idx in range(defense_count))
    count = max(attack_count, defense_count)
    return tuple((idx % attack_count, idx % defense_count) for idx in range(count))


def trace_actions(
    snapshot: RuntimeSnapshot, actor: str, *, trace_index: int
) -> list[Action]:
    trace = (
        snapshot.reference_bundle.reference_attack_traces[trace_index]
        if actor == "red"
        else snapshot.reference_bundle.reference_defense_traces[trace_index]
    )
    actions = [runtime_action(actor, step) for step in trace.steps]
    if actions:
        return actions
    return [Action(actor_id=actor, role=actor, kind="sleep", payload={})]


def scripted_runtime_action(
    snapshot: RuntimeSnapshot,
    *,
    actor: str,
    observation: Observation,
    reference_action: Action,
    decision_count: int,
    remaining_targets: set[str],
) -> Action:
    if actor == "red":
        return _scripted_red_action(reference_action, decision_count)
    return _scripted_blue_action(
        snapshot,
        observation,
        reference_action,
        decision_count,
        remaining_targets,
    )


def _scripted_red_action(reference_action: Action, decision_count: int) -> Action:
    if decision_count != 0:
        return reference_action

    target = str(reference_action.payload.get("target", ""))
    if reference_action.kind == "api":
        return Action(
            actor_id="red",
            role="red",
            kind="api",
            payload={"target": target or "svc-web", "path": "/"},
        )
    if target:
        return Action(
            actor_id="red",
            role="red",
            kind="shell",
            payload={"target": target, "command": "cat /etc/hosts"},
        )
    return Action(actor_id="red", role="red", kind="sleep", payload={})


def _scripted_blue_action(
    snapshot: RuntimeSnapshot,
    observation: Observation,
    reference_action: Action,
    decision_count: int,
    remaining_targets: set[str],
) -> Action:
    malicious_visible = any(event.malicious for event in observation.visible_events)
    target = str(reference_action.payload.get("target", ""))
    visible_targets = {
        event.target_entity for event in observation.visible_events if event.malicious
    }
    wrong_target = _service_not_in(snapshot, excluded={target, *visible_targets})

    if decision_count == 0:
        if malicious_visible and observation.visible_events:
            visible = next(
                (event for event in observation.visible_events if event.malicious),
                observation.visible_events[0],
            )
            return Action(
                actor_id="blue",
                role="blue",
                kind="submit_finding",
                payload={
                    "event_type": visible.event_type,
                    "target": visible.target_entity,
                },
            )
        if reference_action.kind == "submit_finding":
            return Action(
                actor_id="blue",
                role="blue",
                kind="submit_finding",
                payload={
                    "event_type": str(
                        reference_action.payload.get(
                            "event_type",
                            reference_action.payload.get("event", "InitialAccess"),
                        )
                    ),
                    "target": wrong_target or "svc-email",
                },
            )

    if decision_count == 1 and malicious_visible and reference_action.kind == "control":
        disruptive_target = (
            _service_not_in(snapshot, excluded={target, *remaining_targets})
            or wrong_target
            or target
        )
        return normalize_trace_action(
            snapshot,
            Action(
                actor_id="blue",
                role="blue",
                kind="control",
                payload={
                    "target": disruptive_target,
                    "action": str(reference_action.payload.get("action", "contain")),
                },
            ),
        )

    return reference_action


def _service_not_in(snapshot: RuntimeSnapshot, *, excluded: set[str]) -> str:
    for preferred in (
        "svc-email",
        "svc-web",
        "svc-idp",
        "svc-fileshare",
        "svc-db",
        "svc-siem",
    ):
        if preferred not in excluded and any(
            service.id == preferred for service in snapshot.world.services
        ):
            return preferred
    for service in snapshot.world.services:
        if service.id not in excluded:
            return service.id
    return ""
