"""Pure reducer helpers for runtime state updates."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from open_range.execution import ActionExecution
from open_range.runtime_events import (
    EmitEvent,
    ServiceSurfaceResolver,
    red_events_for_step,
)
from open_range.runtime_types import Action, RuntimeEvent

SERVICE_HEALTH_BLUE_OBJECTIVE = "service_health_above(0.9)"
BLUE_CONTAINMENT_OBJECTIVE = "intrusion_contained(before_asset_read)"
OBSERVATION_ALERT_EVENT_TYPES = frozenset(
    {
        "DetectionAlertRaised",
        "ContainmentApplied",
        "PatchApplied",
        "ServiceDegraded",
    }
)


@dataclass(frozen=True, slots=True)
class RedActionReduction:
    stdout: str
    stderr: str
    emitted_events: tuple[RuntimeEvent, ...] = ()
    satisfied_objectives: tuple[str, ...] = ()
    advanced_target: str = ""
    progress_advanced: bool = False


@dataclass(frozen=True, slots=True)
class BlueControlEventSpec:
    event_type: str
    target_entity: str
    linked_objective_predicates: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class BlueControlTransition:
    stdout: str
    contained_targets: set[str]
    patched_targets: set[str]
    path_broken: bool = False
    event_spec: BlueControlEventSpec | None = None


@dataclass(frozen=True, slots=True)
class ObservationTransition:
    alerts: tuple[RuntimeEvent, ...]
    reward_delta: float
    observed_event_ids: set[str]
    next_observation_count: int | None
    first_observation: bool = False


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


def reduce_red_action(
    *,
    action: Action,
    target: str,
    live: ActionExecution,
    blocked_reason: str,
    matched_reference_step: bool,
    expected_reference_step: object | None,
    last_red_target: str,
    emit_event: EmitEvent,
    service_surfaces: ServiceSurfaceResolver,
) -> RedActionReduction:
    stderr = live.stderr
    if blocked_reason:
        blocked_msg = f"target {target} is {blocked_reason}"
        if blocked_msg not in {
            line.strip() for line in stderr.splitlines() if line.strip()
        }:
            stderr = "\n".join(filter(None, [stderr, blocked_msg])).strip()
        return RedActionReduction(
            stdout=live.stdout or "red action had no strategic effect",
            stderr=stderr,
        )

    if expected_reference_step is not None and matched_reference_step:
        batch = red_events_for_step(
            expected_reference_step,
            action,
            last_red_target=last_red_target,
            emit_event=emit_event,
            service_surfaces=service_surfaces,
        )
        return RedActionReduction(
            stdout=f"red advanced on {target}",
            stderr=stderr,
            emitted_events=batch.events,
            satisfied_objectives=batch.satisfied_objectives,
            advanced_target=batch.last_red_target,
            progress_advanced=True,
        )

    return RedActionReduction(
        stdout=live.stdout or f"red executed on {target or 'unknown target'}",
        stderr=stderr,
    )


def reduce_blue_control(
    *,
    target: str,
    directive: str,
    live: ActionExecution,
    remaining_red_targets: set[str] | frozenset[str],
    contained_targets: set[str] | frozenset[str],
    patched_targets: set[str] | frozenset[str],
) -> BlueControlTransition:
    next_contained = set(contained_targets)
    next_patched = set(patched_targets)
    path_broken = bool(
        target
        and target in remaining_red_targets
        and (live.containment_applied or live.patch_applied)
    )
    linked_objectives = (BLUE_CONTAINMENT_OBJECTIVE,) if path_broken else ()
    event_spec: BlueControlEventSpec | None = None

    if target and live.containment_applied:
        next_contained.add(target)
        next_patched.discard(target)
        event_spec = BlueControlEventSpec(
            event_type="ContainmentApplied",
            target_entity=target,
            linked_objective_predicates=linked_objectives,
        )
    elif target and live.patch_applied:
        next_patched.add(target)
        next_contained.discard(target)
        event_spec = BlueControlEventSpec(
            event_type="PatchApplied",
            target_entity=target,
            linked_objective_predicates=linked_objectives,
        )
    elif target and live.recovery_applied:
        next_contained.discard(target)
        next_patched.discard(target)
        event_spec = BlueControlEventSpec(
            event_type="RecoveryCompleted",
            target_entity=target,
        )

    if path_broken:
        if live.patch_applied:
            stdout = (
                f"mitigation applied to {target}"
                if directive == "mitigate"
                else f"patch applied to {target}"
            )
        else:
            stdout = f"containment applied to {target}"
    elif live.recovery_applied:
        stdout = live.stdout or f"recovery applied to {target or 'unknown target'}"
    elif live.patch_applied:
        noun = "mitigation" if directive == "mitigate" else "patch"
        stdout = (
            live.stdout
            or f"{noun} on {target or 'unknown target'} did not break the remaining path"
        )
    elif directive == "contain":
        stdout = (
            live.stdout
            or f"control action on {target or 'unknown target'} had no path-breaking effect"
        )
    else:
        stdout = (
            live.stdout
            or f"{directive} on {target or 'unknown target'} had no path-breaking effect"
        )

    return BlueControlTransition(
        stdout=stdout,
        contained_targets=next_contained,
        patched_targets=next_patched,
        path_broken=path_broken,
        event_spec=event_spec,
    )


def reduce_observation_state(
    *,
    visible_events: tuple[RuntimeEvent, ...],
    previous_reward_delta: float,
    observed_event_ids: set[str] | frozenset[str],
    observation_count: int | None,
) -> ObservationTransition:
    return ObservationTransition(
        alerts=tuple(
            event
            for event in visible_events
            if event.malicious or event.event_type in OBSERVATION_ALERT_EVENT_TYPES
        ),
        reward_delta=previous_reward_delta,
        observed_event_ids=set(observed_event_ids)
        | {event.id for event in visible_events},
        next_observation_count=(
            observation_count + 1 if observation_count is not None else None
        ),
        first_observation=observation_count == 0,
    )
