"""Workflow-abuse family weakness builder."""

from __future__ import annotations

from open_range.weakness_families.common import (
    WeaknessBuildContext,
    assemble_weakness_spec,
    mailbox_for_ref,
    mailbox_remediated_message,
    mailbox_slug,
    realization_summary,
    write_text_command,
)
from open_range.world_ir import WeaknessRealizationSpec, WorldIR


def mutation_target_service(world: WorldIR) -> str | None:
    return next(
        (service.id for service in world.services if service.kind == "web_app"), None
    )


def mutation_spec(world: WorldIR, target_service: str) -> tuple[str, str, str]:
    del target_service
    workflow = next(
        (item for item in world.workflows if item.name == "document_sharing"),
        None,
    )
    if workflow is not None:
        return ("document_share_abuse", "workflow", workflow.id)
    workflow = next(
        (item for item in world.workflows if item.name == "internal_email"),
        None,
    )
    if workflow is not None:
        return ("phishing_credential_capture", "workflow", workflow.id)
    workflow = world.workflows[0] if world.workflows else None
    return (
        "helpdesk_reset_bypass",
        "workflow",
        workflow.id if workflow is not None else "wf-generic",
    )


def build(context: WeaknessBuildContext):
    realizations = _workflow_realizations(context)
    return assemble_weakness_spec(
        context,
        realization=realizations,
        remediation_command=_workflow_remediation_command(context.kind, realizations),
    )


def _workflow_realizations(
    context: WeaknessBuildContext,
) -> tuple[WeaknessRealizationSpec, ...]:
    primary_path = (
        f"/srv/shared/.openrange/workflows/{context.kind}.json"
        if context.target == "svc-fileshare"
        else f"/etc/openrange/workflows/{context.kind}.json"
        if context.target == "svc-email"
        else f"/var/www/html/.openrange/weaknesses/{context.kind}.json"
    )
    realizations = [
        WeaknessRealizationSpec(
            kind="workflow",
            service=context.target,
            path=primary_path,
            summary=realization_summary("workflow_abuse", context.kind),
        )
    ]
    if context.kind in {
        "phishing_credential_capture",
        "internal_request_impersonation",
    }:
        mailbox = mailbox_for_ref(context.world, context.target_ref)
        realizations.append(
            WeaknessRealizationSpec(
                kind="mailbox",
                service="svc-email",
                path=(
                    "/var/spool/openrange/mailboxes/"
                    f"{mailbox_slug(mailbox)}/{context.kind}.eml"
                ),
                summary=realization_summary("workflow_abuse", context.kind),
            )
        )
    return tuple(realizations)


def _workflow_remediation_command(
    kind: str, realizations: tuple[WeaknessRealizationSpec, ...]
) -> str:
    payload = _workflow_remediation_payload(kind)
    commands = [
        write_text_command(realization.path, payload)
        for realization in realizations
        if realization.kind == "workflow"
    ]
    for realization in realizations:
        if realization.kind == "mailbox":
            commands.append(
                write_text_command(realization.path, mailbox_remediated_message(kind))
            )
    commands.append("touch /tmp/openrange-patched")
    return "\n".join(commands)


def _workflow_remediation_payload(kind: str) -> str:
    return (
        "{\n"
        f'  "kind": "{kind}",\n'
        '  "approval_guard": "enabled",\n'
        '  "identity_verification": "required",\n'
        '  "mail_confirmation_required": true\n'
        "}\n"
    )


def seed_defaults(world: WorldIR) -> tuple[str, str]:
    target_ref = world.workflows[0].id if world.workflows else "wf-generic"
    return ("svc-web", target_ref)


def default_kind(world: WorldIR, target: str, target_ref: str) -> str:
    del target, target_ref
    if any(workflow.name == "helpdesk_ticketing" for workflow in world.workflows):
        return "helpdesk_reset_bypass"
    if any(workflow.name == "document_sharing" for workflow in world.workflows):
        return "document_share_abuse"
    return "approval_chain_bypass"


def normalize_target(
    world: WorldIR,
    kind: str,
    target: str,
    target_kind: str,
    target_ref: str,
) -> tuple[str, str, str]:
    service_ids = {service.id for service in world.services}
    if (
        kind in {"phishing_credential_capture", "internal_request_impersonation"}
        and "svc-email" in service_ids
    ):
        return ("svc-email", target_kind, target_ref)
    if kind == "document_share_abuse" and "svc-fileshare" in service_ids:
        return ("svc-fileshare", target_kind, target_ref)
    if (
        kind in {"helpdesk_reset_bypass", "approval_chain_bypass"}
        and "svc-web" in service_ids
    ):
        return ("svc-web", target_kind, target_ref)
    return (target, target_kind, target_ref)
