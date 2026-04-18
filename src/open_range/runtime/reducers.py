"""Pure reducer helpers for runtime state updates."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from open_range.contracts.runtime import (
    Action,
    ActionEffect,
    ExternalRole,
    RuntimeEvent,
)
from open_range.contracts.snapshot import RuntimeSnapshot
from open_range.objectives.engine import PredicateEngine
from open_range.runtime.events import (
    EmitEvent,
    ServiceSurfaceResolver,
    events_for_effects,
)
from open_range.runtime.execution import ActionExecution
from open_range.runtime.replay import action_for_reference_step

DETECTABLE_EVENT_TYPES = frozenset(
    {
        "InitialAccess",
        "CredentialObtained",
        "UnauthorizedCredentialUse",
        "PrivilegeEscalation",
        "CrossZoneTraversal",
        "SensitiveAssetRead",
        "PersistenceEstablished",
    }
)
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
    effects: tuple[ActionEffect, ...] = ()
    emitted_events: tuple[RuntimeEvent, ...] = ()


@dataclass(frozen=True, slots=True)
class BlueActionEventSpec:
    event_type: str
    target_entity: str


@dataclass(frozen=True, slots=True)
class BlueFindingTransition:
    stdout: str
    detected_event_ids: set[str]
    blue_detected: bool
    initial_access_detected: bool
    event_spec: BlueActionEventSpec | None = None


@dataclass(frozen=True, slots=True)
class BlueControlTransition:
    stdout: str
    contained_targets: set[str]
    patched_targets: set[str]
    blue_contained: bool
    path_broken: bool = False
    event_spec: BlueActionEventSpec | None = None


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


def reduce_red_action(
    *,
    action: Action,
    target: str,
    live: ActionExecution,
    blocked_reason: str,
    use_reference_semantics: bool,
    matched_reference_step: bool,
    reference_step: object | None,
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

    if (
        use_reference_semantics
        and reference_step is not None
        and matched_reference_step
        and not live.effects
    ):
        effects = _reference_effects(reference_step, action, live=live)
        return RedActionReduction(
            stdout=f"red advanced on {target}",
            stderr=stderr,
            effects=effects,
            emitted_events=events_for_effects(
                effects,
                actor="red",
                malicious=True,
                default_source=live.runner_service or action.actor_id,
                default_target=target,
                emit_event=emit_event,
                service_surfaces=service_surfaces,
            ),
        )

    if live.effects:
        emitted = events_for_effects(
            live.effects,
            actor="red",
            malicious=True,
            default_source=live.runner_service or action.actor_id,
            default_target=target,
            emit_event=emit_event,
            service_surfaces=service_surfaces,
        )
        if emitted:
            return RedActionReduction(
                stdout=f"red advanced on {target}",
                stderr=stderr,
                effects=live.effects,
                emitted_events=emitted,
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
    active_red_targets: set[str] | frozenset[str],
    contained_targets: set[str] | frozenset[str],
    patched_targets: set[str] | frozenset[str],
    blue_contained: bool,
) -> BlueControlTransition:
    next_contained = set(contained_targets)
    next_patched = set(patched_targets)
    path_broken = bool(
        target
        and target in active_red_targets
        and (live.containment_applied or live.patch_applied)
    )
    next_blue_contained = blue_contained or path_broken
    event_spec: BlueActionEventSpec | None = None

    if target and live.containment_applied:
        next_contained.add(target)
        next_patched.discard(target)
        event_spec = BlueActionEventSpec(
            event_type="ContainmentApplied",
            target_entity=target,
        )
    elif target and live.patch_applied:
        next_patched.add(target)
        next_contained.discard(target)
        event_spec = BlueActionEventSpec(
            event_type="PatchApplied",
            target_entity=target,
        )
    elif target and live.recovery_applied:
        next_contained.discard(target)
        next_patched.discard(target)
        event_spec = BlueActionEventSpec(
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
        blue_contained=next_blue_contained,
        path_broken=path_broken,
        event_spec=event_spec,
    )


def reduce_blue_finding(
    *,
    matched_event: RuntimeEvent | None,
    detected_event_ids: set[str] | frozenset[str],
    blue_detected: bool,
) -> BlueFindingTransition:
    next_detected_event_ids = set(detected_event_ids)
    if matched_event is None:
        return BlueFindingTransition(
            stdout="finding rejected as false positive",
            detected_event_ids=next_detected_event_ids,
            blue_detected=blue_detected,
            initial_access_detected=False,
        )
    if matched_event.id in next_detected_event_ids:
        return BlueFindingTransition(
            stdout="finding already recorded",
            detected_event_ids=next_detected_event_ids,
            blue_detected=blue_detected,
            initial_access_detected=False,
        )
    next_detected_event_ids.add(matched_event.id)
    initial_access_detected = matched_event.event_type == "InitialAccess"
    return BlueFindingTransition(
        stdout=f"validated finding for {matched_event.event_type}",
        detected_event_ids=next_detected_event_ids,
        blue_detected=True,
        initial_access_detected=initial_access_detected,
        event_spec=BlueActionEventSpec(
            event_type="DetectionAlertRaised",
            target_entity=matched_event.target_entity,
        ),
    )


def emit_blue_action_event(
    event_spec: BlueActionEventSpec | None,
    *,
    emit_event: EmitEvent,
) -> RuntimeEvent | None:
    if event_spec is None:
        return None
    return emit_event(
        event_type=event_spec.event_type,
        actor="blue",
        source_entity="blue",
        target_entity=event_spec.target_entity,
        malicious=False,
        observability_surfaces=("svc-siem",),
    )


def select_scripted_internal_blue_action(
    *,
    visible_events: tuple[RuntimeEvent, ...] | list[RuntimeEvent],
    detected_event_ids: set[str] | frozenset[str],
    active_red_targets: set[str] | frozenset[str],
    contained_targets: set[str] | frozenset[str],
    blue_detected: bool,
) -> Action:
    for event in visible_events:
        if (
            event.event_type in DETECTABLE_EVENT_TYPES
            and event.id not in detected_event_ids
        ):
            return Action(
                actor_id="blue",
                role="blue",
                kind="submit_finding",
                payload={
                    "event_type": event.event_type,
                    "target": event.target_entity,
                },
            )
    remaining = sorted(set(active_red_targets) - set(contained_targets))
    if remaining and blue_detected:
        return Action(
            actor_id="blue",
            role="blue",
            kind="control",
            payload={"target": remaining[0], "action": "contain"},
        )
    return Action(actor_id="blue", role="blue", kind="sleep", payload={})


def resolved_opponent_mode(
    configured_mode: str,
    *,
    actor: ExternalRole,
    snapshot_seed: int | None,
) -> str:
    if configured_mode != "checkpoint_pool":
        return configured_mode
    if snapshot_seed is None:
        return "scripted"
    if actor == "red":
        return "reference" if snapshot_seed % 2 == 0 else "frozen_policy"
    return "reference" if snapshot_seed % 2 == 0 else "scripted"


def opponent_cadence(actor: ExternalRole, *, mode: str) -> float:
    if actor == "red":
        if mode == "replay":
            return 0.75
        if mode == "frozen_policy":
            return 1.5
        if mode == "scripted":
            return 1.25
        return 1.0
    if mode == "replay":
        return 0.5
    if mode == "reference":
        return 0.75
    if mode == "frozen_policy":
        return 1.25
    return 1.0


def select_internal_opponent_action(
    actor: ExternalRole,
    *,
    mode: str,
    snapshot: RuntimeSnapshot | None,
    reference_step: object | None,
    visible_events: tuple[RuntimeEvent, ...] | list[RuntimeEvent] = (),
    detected_event_ids: set[str] | frozenset[str] = frozenset(),
    active_red_targets: set[str] | frozenset[str] = frozenset(),
    contained_targets: set[str] | frozenset[str] = frozenset(),
    blue_detected: bool = False,
) -> Action:
    if mode == "none":
        return Action(actor_id=actor, role=actor, kind="sleep", payload={})
    if actor == "red":
        if snapshot is None:
            return Action(actor_id="red", role="red", kind="sleep", payload={})
        return action_for_reference_step(snapshot, "red", reference_step)
    if mode in {"reference", "replay"}:
        if snapshot is None:
            return Action(actor_id="blue", role="blue", kind="sleep", payload={})
        return action_for_reference_step(snapshot, "blue", reference_step)
    return select_scripted_internal_blue_action(
        visible_events=visible_events,
        detected_event_ids=detected_event_ids,
        active_red_targets=active_red_targets,
        contained_targets=contained_targets,
        blue_detected=blue_detected,
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
            if event.event_type in DETECTABLE_EVENT_TYPES
            or event.event_type in OBSERVATION_ALERT_EVENT_TYPES
        ),
        reward_delta=previous_reward_delta,
        observed_event_ids=set(observed_event_ids)
        | {event.id for event in visible_events},
        next_observation_count=(
            observation_count + 1 if observation_count is not None else None
        ),
        first_observation=observation_count == 0,
    )


def update_continuity_state(
    service_health: Mapping[str, float],
) -> float:
    return continuity_for_service_health(service_health)


def evaluate_terminal_state(
    predicates: PredicateEngine | None,
    *,
    snapshot: RuntimeSnapshot | None,
    events: tuple[RuntimeEvent, ...],
    service_health: Mapping[str, float],
    red_objectives_satisfied: set[str] | frozenset[str],
    blue_objectives_satisfied: set[str] | frozenset[str],
    sim_time: float,
    episode_horizon: float,
) -> tuple[set[str], str, str]:
    objectives = set(red_objectives_satisfied)
    if snapshot is not None and predicates is not None:
        objectives = predicates.evaluate_red_objectives(
            snapshot=snapshot,
            events=events,
            service_health=service_health,
        )
        if predicates.red_terminal_satisfied(objectives):
            return objectives, "red", "red_terminal"
        if predicates.blue_terminal_satisfied(
            satisfied_predicates=blue_objectives_satisfied
        ):
            return objectives, "blue", "blue_terminal"
    if sim_time >= episode_horizon:
        return objectives, "timeout", "timeout"
    return objectives, "", ""


def _reference_effects(
    reference_step: object,
    action: Action,
    *,
    live: ActionExecution,
) -> tuple[ActionEffect, ...]:
    step_action = str(getattr(reference_step, "payload", {}).get("action", ""))
    target = str(getattr(reference_step, "target", "")) or str(
        action.payload.get("target", "")
    )
    asset_id = str(getattr(reference_step, "payload", {}).get("asset", ""))
    objective = str(getattr(reference_step, "payload", {}).get("objective", "")).strip()
    source = live.runner_service or str(action.payload.get("origin", action.actor_id))
    weakness_id = str(
        getattr(reference_step, "payload", {}).get(
            "weakness_id",
            getattr(reference_step, "payload", {}).get("weakness", ""),
        )
    )
    if step_action in {"initial_access", "click_lure"}:
        return (
            ActionEffect(
                kind="InitialAccess",
                source_entity=source,
                target_entity=target,
                weakness_id=weakness_id,
            ),
        )
    if step_action == "traverse":
        return (
            ActionEffect(
                kind="CrossZoneTraversal",
                source_entity=source,
                target_entity=target,
                weakness_id=weakness_id,
            ),
        )
    if objective:
        return (
            _objective_effect(
                objective,
                source=source,
                target=target,
                weakness_id=weakness_id,
                asset_id=asset_id,
            ),
        )
    if step_action == "collect_secret" and asset_id:
        effect_type = (
            "CredentialObtained"
            if "cred" in asset_id or "token" in asset_id
            else "SensitiveAssetRead"
        )
        return (
            ActionEffect(
                kind=effect_type,
                source_entity=source,
                target_entity=target,
                target_ref=asset_id,
                weakness_id=weakness_id,
            ),
        )
    if step_action in {"abuse_identity", "abuse_workflow"}:
        return (
            ActionEffect(
                kind="UnauthorizedCredentialUse",
                source_entity=source,
                target_entity=target,
                target_ref=asset_id,
                weakness_id=weakness_id,
            ),
        )
    return ()


def _objective_effect(
    objective: str,
    *,
    source: str,
    target: str,
    weakness_id: str,
    asset_id: str,
) -> ActionEffect:
    from open_range.objectives.expr import predicate_inner
    from open_range.objectives.resolution import objective_event_for_predicate

    event_type, target_ref = objective_event_for_predicate(
        objective,
        target_id=asset_id or predicate_inner(objective),
        default_service=target,
    )
    return ActionEffect(
        kind=event_type or "SensitiveAssetRead",
        source_entity=source,
        target_entity=target,
        target_ref=target_ref or asset_id,
        weakness_id=weakness_id,
    )
