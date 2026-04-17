"""Telemetry-blindspot family weakness builder."""

from __future__ import annotations

import json

from open_range.contracts.validation import ReferenceAction
from open_range.contracts.world import WeaknessRealizationSpec, WeaknessSpec, WorldIR
from open_range.objectives.engine import PredicateEngine

from .common import (
    RedReferencePlan,
    WeaknessBuildContext,
    assemble_weakness_spec,
    realization_summary,
    traverse_to_target,
    write_text_command,
)


def mutation_target_service(world: WorldIR) -> str | None:
    return next(
        (service.id for service in world.services if service.kind == "email"),
        next(
            (service.id for service in world.services if service.kind == "web_app"),
            None,
        ),
    )


def mutation_spec(world: WorldIR, target_service: str) -> tuple[str, str, str]:
    del world
    if target_service == "svc-email":
        return ("silent_mail_rule", "telemetry", target_service)
    if target_service == "svc-web":
        return ("missing_web_logs", "telemetry", target_service)
    return ("missing_idp_logs", "telemetry", target_service)


def build_red_reference_plan(
    world: WorldIR,
    engine: PredicateEngine,
    start: str,
    weakness: WeaknessSpec,
) -> RedReferencePlan:
    del world
    return RedReferencePlan(
        steps=traverse_to_target(engine, start, weakness.target)
        + (
            ReferenceAction(
                actor="red",
                kind="api",
                target=weakness.target,
                payload={"action": "initial_access", "weakness_id": weakness.id},
            ),
        ),
        current=weakness.target,
    )


def build(context: WeaknessBuildContext):
    realizations = _telemetry_realizations(context)
    return assemble_weakness_spec(
        context,
        realization=realizations,
        remediation_command=_telemetry_remediation_command(context.kind, realizations),
    )


def _telemetry_realizations(
    context: WeaknessBuildContext,
) -> tuple[WeaknessRealizationSpec, ...]:
    return (
        WeaknessRealizationSpec(
            kind="telemetry",
            service=context.target,
            path=f"/etc/openrange/{context.kind}.json",
            summary=realization_summary("telemetry_blindspot", context.kind),
        ),
    )


def _telemetry_remediation_command(
    kind: str, realizations: tuple[WeaknessRealizationSpec, ...]
) -> str:
    payload = _telemetry_remediation_payload(kind)
    commands = [
        write_text_command(realization.path, payload) for realization in realizations
    ]
    commands.append("touch /tmp/openrange-patched")
    return "\n".join(commands)


def _telemetry_remediation_payload(kind: str) -> str:
    return (
        "{\n"
        f'  "kind": "{kind}",\n'
        '  "siem_ingest": true,\n'
        '  "delay_seconds": 0,\n'
        '  "admin_actions_logged": true,\n'
        '  "mail_rule_logging": true\n'
        "}\n"
    )


def seed_defaults(world: WorldIR) -> tuple[str, str]:
    target = (
        "svc-email"
        if any(service.id == "svc-email" for service in world.services)
        else "svc-web"
    )
    return (target, target)


def default_kind(world: WorldIR, target: str, target_ref: str) -> str:
    del world, target_ref
    if target == "svc-web":
        return "missing_web_logs"
    if target == "svc-idp":
        return "missing_idp_logs"
    if target == "svc-email":
        return "silent_mail_rule"
    return "delayed_siem_ingest"


def normalize_target(
    world: WorldIR,
    kind: str,
    target: str,
    target_kind: str,
    target_ref: str,
) -> tuple[str, str, str]:
    service_ids = {service.id for service in world.services}
    if kind == "missing_web_logs" and "svc-web" in service_ids:
        return ("svc-web", "telemetry", "svc-web")
    if (
        kind in {"missing_idp_logs", "unmonitored_admin_action"}
        and "svc-idp" in service_ids
    ):
        return ("svc-idp", "telemetry", "svc-idp")
    if kind == "silent_mail_rule" and "svc-email" in service_ids:
        return ("svc-email", "telemetry", "svc-email")
    return (target, target_kind, target_ref)


def render_realization_content(
    world: WorldIR,
    weakness: WeaknessSpec,
    realization: WeaknessRealizationSpec,
) -> str:
    del realization
    payload = {
        "world_id": world.world_id,
        "target": weakness.target,
        "ship_to_siem": False,
    }
    if weakness.kind == "missing_web_logs":
        payload.update({"access_logs_enabled": False, "error_logs_enabled": False})
    elif weakness.kind == "missing_idp_logs":
        payload.update({"auth_logs_enabled": False, "audit_logs_enabled": False})
    elif weakness.kind == "delayed_siem_ingest":
        payload.update({"delay_seconds": 180})
    elif weakness.kind == "unmonitored_admin_action":
        payload.update({"admin_actions_logged": False})
    elif weakness.kind == "silent_mail_rule":
        payload.update(
            {"mail_rule_logging": False, "mailbox_auto_forward_alerting": False}
        )
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"
