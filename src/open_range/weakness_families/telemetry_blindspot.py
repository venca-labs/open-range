"""Telemetry-blindspot family weakness builder."""

from __future__ import annotations

from open_range.weakness_families.common import (
    WeaknessBuildContext,
    assemble_weakness_spec,
    realization_summary,
    write_text_command,
)
from open_range.world_ir import WeaknessRealizationSpec, WorldIR


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
