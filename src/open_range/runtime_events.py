"""Shared event-generation helpers for the runtime."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from open_range.predicate_expr import predicate_inner, predicate_name
from open_range.runtime_types import Action, RuntimeEvent


@dataclass(frozen=True, slots=True)
class RedEventBatch:
    events: tuple[RuntimeEvent, ...]
    satisfied_objectives: tuple[str, ...]
    last_red_target: str


EmitEvent = Callable[..., RuntimeEvent]
ServiceSurfaceResolver = Callable[[str], tuple[str, ...]]


def action_target(action: Action) -> str:
    target = action.payload.get("target")
    if isinstance(target, str) and target:
        return target
    service = action.payload.get("service")
    if isinstance(service, str) and service:
        return service
    return ""


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
    # Multimodal routine events
    if action.kind == "chat":
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
    if action.kind == "document_share":
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
    if action.kind == "voice":
        return (
            emit_event(
                event_type="BenignUserAction",
                actor="green",
                source_entity=action.actor_id,
                target_entity=target,
                malicious=False,
                observability_surfaces=(),
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


def red_events_for_step(
    expected,
    action: Action,
    *,
    last_red_target: str,
    emit_event: EmitEvent,
    service_surfaces: ServiceSurfaceResolver,
) -> RedEventBatch:
    target = expected.target
    step_action = str(expected.payload.get("action", ""))
    asset_id = str(expected.payload.get("asset", ""))
    objective = str(expected.payload.get("objective", "")).strip()

    if step_action in {"initial_access", "click_lure"}:
        return RedEventBatch(
            events=(
                emit_event(
                    event_type="InitialAccess",
                    actor="red",
                    source_entity=action.actor_id,
                    target_entity=target,
                    malicious=True,
                    observability_surfaces=service_surfaces(target),
                ),
            ),
            satisfied_objectives=(),
            last_red_target=target,
        )
    if step_action == "traverse":
        return RedEventBatch(
            events=(
                emit_event(
                    event_type="CrossZoneTraversal",
                    actor="red",
                    source_entity=last_red_target or action.actor_id,
                    target_entity=target,
                    malicious=True,
                    observability_surfaces=service_surfaces(target),
                ),
            ),
            satisfied_objectives=(),
            last_red_target=target,
        )
    if step_action == "collect_secret":
        return _secret_collection_events(
            target=target,
            asset_id=asset_id,
            objective=objective,
            emit_event=emit_event,
            service_surfaces=service_surfaces,
        )
    if step_action == "abuse_identity":
        return _identity_abuse_events(
            target=target,
            objective=objective,
            emit_event=emit_event,
            service_surfaces=service_surfaces,
        )
    if step_action == "abuse_workflow":
        return _workflow_abuse_events(
            target=target,
            objective=objective,
            emit_event=emit_event,
            service_surfaces=service_surfaces,
        )
    if step_action == "satisfy_objective":
        return objective_events(
            target=target,
            objective=objective,
            asset_id=asset_id,
            emit_event=emit_event,
            service_surfaces=service_surfaces,
        )
    return RedEventBatch(events=(), satisfied_objectives=(), last_red_target=target)


def objective_events(
    *,
    target: str,
    objective: str,
    asset_id: str,
    emit_event: EmitEvent,
    service_surfaces: ServiceSurfaceResolver,
) -> RedEventBatch:
    if not objective and not asset_id:
        return RedEventBatch(events=(), satisfied_objectives=(), last_red_target=target)
    resolved_objective = objective or (
        f"credential_obtained({asset_id})"
        if "cred" in asset_id
        else f"asset_read({asset_id})"
    )
    target_ref = predicate_inner(resolved_objective) or asset_id or target
    name = predicate_name(resolved_objective)
    surfaces = service_surfaces(target)
    if name in {"credential_obtained", "unauthorized_admin_login"}:
        event_type = (
            "CredentialObtained"
            if name == "credential_obtained"
            else "UnauthorizedCredentialUse"
        )
    elif name in {"asset_read", "file_access", "db_access"}:
        event_type = "SensitiveAssetRead"
    elif name in {"file_creation", "outbound_service"}:
        event_type = "PersistenceEstablished"
    elif name in {"db_modification", "privilege_escalation"}:
        event_type = "PrivilegeEscalation"
    elif name == "dos":
        event_type = "ServiceDegraded"
    else:
        event_type = "SensitiveAssetRead"
    event = emit_event(
        event_type=event_type,
        actor="red",
        source_entity=target,
        target_entity=target_ref,
        malicious=True,
        observability_surfaces=surfaces,
        linked_objective_predicates=(resolved_objective,),
    )
    return RedEventBatch(
        events=(event,),
        satisfied_objectives=(resolved_objective,),
        last_red_target=target,
    )


def _secret_collection_events(
    *,
    target: str,
    asset_id: str,
    objective: str,
    emit_event: EmitEvent,
    service_surfaces: ServiceSurfaceResolver,
) -> RedEventBatch:
    if objective:
        return objective_events(
            target=target,
            objective=objective,
            asset_id=asset_id,
            emit_event=emit_event,
            service_surfaces=service_surfaces,
        )
    if not asset_id:
        event = emit_event(
            event_type="SensitiveAssetRead",
            actor="red",
            source_entity=target,
            target_entity=target,
            malicious=True,
            observability_surfaces=service_surfaces(target),
        )
        return RedEventBatch(
            events=(event,), satisfied_objectives=(), last_red_target=target
        )
    if "cred" in asset_id or "token" in asset_id:
        objective = f"credential_obtained({asset_id})"
        event = emit_event(
            event_type="CredentialObtained",
            actor="red",
            source_entity=target,
            target_entity=asset_id,
            malicious=True,
            observability_surfaces=service_surfaces(target),
            linked_objective_predicates=(objective,),
        )
        return RedEventBatch(
            events=(event,), satisfied_objectives=(objective,), last_red_target=target
        )
    objective = f"asset_read({asset_id})"
    event = emit_event(
        event_type="SensitiveAssetRead",
        actor="red",
        source_entity=target,
        target_entity=asset_id,
        malicious=True,
        observability_surfaces=service_surfaces(target),
        linked_objective_predicates=(objective,),
    )
    return RedEventBatch(
        events=(event,), satisfied_objectives=(objective,), last_red_target=target
    )


def _identity_abuse_events(
    *,
    target: str,
    objective: str,
    emit_event: EmitEvent,
    service_surfaces: ServiceSurfaceResolver,
) -> RedEventBatch:
    if objective:
        return objective_events(
            target=target,
            objective=objective,
            asset_id="",
            emit_event=emit_event,
            service_surfaces=service_surfaces,
        )
    events = (
        emit_event(
            event_type="CredentialObtained",
            actor="red",
            source_entity=target,
            target_entity=target,
            malicious=True,
            observability_surfaces=service_surfaces(target),
        ),
        emit_event(
            event_type="UnauthorizedCredentialUse",
            actor="red",
            source_entity=target,
            target_entity=target,
            malicious=True,
            observability_surfaces=service_surfaces(target),
        ),
    )
    return RedEventBatch(events=events, satisfied_objectives=(), last_red_target=target)


def _workflow_abuse_events(
    *,
    target: str,
    objective: str,
    emit_event: EmitEvent,
    service_surfaces: ServiceSurfaceResolver,
) -> RedEventBatch:
    if objective:
        return objective_events(
            target=target,
            objective=objective,
            asset_id="",
            emit_event=emit_event,
            service_surfaces=service_surfaces,
        )
    event = emit_event(
        event_type="UnauthorizedCredentialUse",
        actor="red",
        source_entity=target,
        target_entity=target,
        malicious=True,
        observability_surfaces=service_surfaces(target),
    )
    return RedEventBatch(
        events=(event,), satisfied_objectives=(), last_red_target=target
    )
