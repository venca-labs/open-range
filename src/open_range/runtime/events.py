"""Shared event-generation helpers for the runtime."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from math import inf
from typing import Callable

from open_range.contracts.runtime import (
    Action,
    ActionEffect,
    ExternalRole,
    RuntimeEvent,
    action_target,
)

__all__ = [
    "EmitEvent",
    "EventEmission",
    "RuntimeEventLog",
    "action_target",
    "blue_visibility_time",
    "emit_runtime_event",
    "events_for_effects",
    "green_events_for_action",
    "service_observability_surfaces",
    "telemetry_blindspots",
    "visible_events_for_actor",
]


@dataclass(frozen=True, slots=True)
class EventEmission:
    event: RuntimeEvent
    visibility: dict[str, float]


EmitEvent = Callable[..., RuntimeEvent]
ServiceSurfaceResolver = Callable[[str], tuple[str, ...]]


def _public_blue_event(event: RuntimeEvent) -> RuntimeEvent:
    if not event.malicious and event.actor != "red":
        return event
    return event.model_copy(
        update={
            "actor": "unknown",
            "source_entity": "unknown",
            "malicious": False,
        }
    )


class RuntimeEventLog:
    """Own runtime event storage, visibility, and export state."""

    def __init__(self) -> None:
        self.reset()

    def reset(self) -> None:
        self._events: list[RuntimeEvent] = []
        self._event_visibility: dict[str, dict[str, float]] = {}
        self._event_seq = 0

    def emit(
        self,
        *,
        sim_time: float,
        event_type: str,
        actor: str,
        source_entity: str,
        target_entity: str,
        malicious: bool,
        observability_surfaces: tuple[str, ...],
        weakness_id: str = "",
        evidence: tuple[str, ...] = (),
        technique_ids: tuple[str, ...] = (),
        suspicious: bool = False,
        suspicious_reasons: tuple[str, ...] = (),
        telemetry_delay: float,
        blindspots: set[str] | frozenset[str],
        green_reactive: bool,
        publish_event: Callable[..., None],
    ) -> RuntimeEvent:
        self._event_seq += 1
        emission = emit_runtime_event(
            event_id=f"evt-{self._event_seq}",
            sim_time=sim_time,
            event_type=event_type,
            actor=actor,
            source_entity=source_entity,
            target_entity=target_entity,
            malicious=malicious,
            observability_surfaces=observability_surfaces,
            weakness_id=weakness_id,
            evidence=evidence,
            technique_ids=technique_ids,
            suspicious=suspicious,
            suspicious_reasons=suspicious_reasons,
            telemetry_delay=telemetry_delay,
            blindspots=blindspots,
        )
        event = emission.event
        self._events.append(event)
        self._event_visibility[event.id] = emission.visibility
        publish_event(event, green_reactive=green_reactive)
        return event

    def visible_events(
        self,
        actor: ExternalRole,
        *,
        observed_event_ids: set[str] | frozenset[str],
        sim_time: float,
    ) -> tuple[RuntimeEvent, ...]:
        return visible_events_for_actor(
            actor,
            events=self._events,
            observed_event_ids=observed_event_ids,
            event_visibility=self._event_visibility,
            sim_time=sim_time,
        )

    def find_detectable_event(
        self,
        event_type: str,
        target: str,
        *,
        sim_time: float,
        visible_only: bool,
    ) -> RuntimeEvent | None:
        for event in self._events:
            if not event.malicious:
                continue
            if event.event_type != event_type:
                continue
            if target and event.target_entity != target:
                continue
            visible_at = self._event_visibility.get(event.id, {}).get(
                "blue", float("inf")
            )
            if visible_only and visible_at > sim_time:
                continue
            return event
        return None

    def export(self) -> tuple[RuntimeEvent, ...]:
        return tuple(self._events)

    def __len__(self) -> int:
        return len(self._events)


def telemetry_blindspots(
    active_weaknesses: Iterable[object],
    *,
    patched_targets: set[str] | frozenset[str],
) -> set[str]:
    return {
        str(getattr(weakness, "target", ""))
        for weakness in active_weaknesses
        if getattr(weakness, "family", "") == "telemetry_blindspot"
        and str(getattr(weakness, "target", "")) not in patched_targets
    }


def blue_visibility_time(
    event: RuntimeEvent,
    observability_surfaces: tuple[str, ...],
    *,
    sim_time: float,
    telemetry_delay: float,
    blindspots: set[str] | frozenset[str],
) -> float:
    if not observability_surfaces:
        return inf
    if event.malicious and {event.source_entity, event.target_entity} & blindspots:
        return inf
    return sim_time + telemetry_delay


def emit_runtime_event(
    *,
    event_id: str,
    sim_time: float,
    event_type: str,
    actor: str,
    source_entity: str,
    target_entity: str,
    malicious: bool,
    observability_surfaces: tuple[str, ...],
    weakness_id: str = "",
    evidence: tuple[str, ...] = (),
    technique_ids: tuple[str, ...] = (),
    suspicious: bool = False,
    suspicious_reasons: tuple[str, ...] = (),
    telemetry_delay: float,
    blindspots: set[str] | frozenset[str],
) -> EventEmission:
    event = RuntimeEvent(
        id=event_id,
        event_type=event_type,
        actor=actor,
        time=round(sim_time, 4),
        source_entity=source_entity,
        target_entity=target_entity,
        malicious=malicious,
        observability_surfaces=observability_surfaces,
        weakness_id=weakness_id,
        evidence=evidence,
        technique_ids=technique_ids,
        suspicious=suspicious,
        suspicious_reasons=suspicious_reasons,
    )
    return EventEmission(
        event=event,
        visibility={
            "red": sim_time if actor == "red" else inf,
            "blue": blue_visibility_time(
                event,
                observability_surfaces,
                sim_time=sim_time,
                telemetry_delay=telemetry_delay,
                blindspots=blindspots,
            ),
        },
    )


def visible_events_for_actor(
    actor: ExternalRole,
    *,
    events: tuple[RuntimeEvent, ...] | list[RuntimeEvent],
    observed_event_ids: set[str] | frozenset[str],
    event_visibility: Mapping[str, Mapping[str, float]],
    sim_time: float,
) -> tuple[RuntimeEvent, ...]:
    if actor == "red":
        return ()
    visible: list[RuntimeEvent] = []
    for event in events:
        if event.id in observed_event_ids:
            continue
        visible_at = event_visibility.get(event.id, {}).get(actor, inf)
        if visible_at > sim_time:
            continue
        if event.event_type == "SuspiciousActionObserved":
            continue
        if actor == "blue":
            if event.observability_surfaces:
                visible.append(_public_blue_event(event))
            continue
        if event.actor == "red":
            visible.append(event)
    return tuple(visible)


def service_observability_surfaces(
    services: Iterable[object],
    target: str,
) -> tuple[str, ...]:
    for service in services:
        if getattr(service, "id", "") == target:
            return tuple(getattr(service, "telemetry_surfaces", ())) + ("svc-siem",)
    return ("svc-siem",)


def green_events_for_action(
    action: Action,
    *,
    live_recovery_applied: bool,
    target: str,
    emit_event: EmitEvent,
    service_surfaces: ServiceSurfaceResolver,
) -> tuple[RuntimeEvent, ...]:
    branch = str(action.payload.get("branch", "")).lower()
    reported_target = str(action.payload.get("reported_target", target)) or target
    if branch == "report_suspicious_activity":
        return (
            emit_event(
                event_type="DetectionAlertRaised",
                actor="green",
                source_entity=action.actor_id,
                target_entity=reported_target,
                malicious=False,
                observability_surfaces=("svc-siem",),
            ),
        )
    if branch == "reset_password" and live_recovery_applied:
        return (
            emit_event(
                event_type="RecoveryCompleted",
                actor="green",
                source_entity=action.actor_id,
                target_entity=reported_target,
                malicious=False,
                observability_surfaces=service_surfaces(target),
            ),
        )
    if branch == "open_it_ticket":
        return (
            emit_event(
                event_type="DetectionAlertRaised",
                actor="green",
                source_entity=action.actor_id,
                target_entity=reported_target,
                malicious=False,
                observability_surfaces=("svc-siem",),
            ),
        )
    return (
        emit_event(
            event_type="BenignUserAction",
            actor="green",
            source_entity=action.actor_id,
            target_entity=target,
            malicious=False,
            observability_surfaces=service_surfaces(target),
        ),
    )


def events_for_effects(
    effects: tuple[ActionEffect, ...],
    *,
    actor: str,
    malicious: bool,
    default_source: str,
    default_target: str,
    emit_event: EmitEvent,
    service_surfaces: ServiceSurfaceResolver,
) -> tuple[RuntimeEvent, ...]:
    events: list[RuntimeEvent] = []
    for effect in effects:
        if not effect.kind:
            continue
        surface_target = effect.target_entity or default_target
        events.append(
            emit_event(
                event_type=effect.kind,
                actor=actor,
                source_entity=effect.source_entity or default_source,
                target_entity=effect.target_ref
                or effect.target_entity
                or default_target,
                malicious=malicious,
                observability_surfaces=service_surfaces(surface_target),
                weakness_id=effect.weakness_id,
                evidence=effect.evidence,
                technique_ids=effect.technique_ids,
            )
        )
    return tuple(events)
