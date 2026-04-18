"""Workflow-abuse family weakness builder."""

from __future__ import annotations

import json
import textwrap

from open_range.catalog.probes import (
    reference_action_for_weakness_family,
    workflow_effect_markers_for_kind,
    workflow_kind_uses_email_delivery,
)
from open_range.contracts.validation import ReferenceAction
from open_range.contracts.world import WeaknessRealizationSpec, WeaknessSpec, WorldIR
from open_range.objectives.effects import (
    effect_marker_content,
    effect_marker_path,
    effect_marker_token,
)
from open_range.objectives.engine import PredicateEngine

from .common import (
    RedReferencePlan,
    WeaknessBuildContext,
    assemble_weakness_spec,
    effect_marker_command,
    first_realization_path,
    mailbox_for_ref,
    mailbox_from_path,
    mailbox_remediated_message,
    mailbox_slug,
    realization_summary,
    shell_payload,
    target_ref_objective,
    write_text_command,
)


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


def build_red_reference_plan(
    world: WorldIR,
    engine: PredicateEngine,
    start: str,
    weakness: WeaknessSpec,
) -> RedReferencePlan:
    steps: list[ReferenceAction] = []
    current = start
    if workflow_kind_uses_email_delivery(weakness.kind):
        mailbox_path = first_realization_path(weakness, kind="mailbox")
        mailbox = mailbox_from_path(mailbox_path) if mailbox_path else "user@corp.local"
        steps.append(
            ReferenceAction(
                actor="red",
                kind="mail",
                target="svc-email",
                payload={
                    "action": "deliver_phish",
                    "weakness_id": weakness.id,
                    "target": "svc-email",
                    "to": mailbox,
                    "subject": weakness.kind,
                    "expect_contains": weakness.kind,
                },
            )
        )
        if mailbox_path:
            steps.append(
                ReferenceAction(
                    actor="red",
                    kind="shell",
                    target="svc-email",
                    payload=shell_payload(
                        action="click_lure",
                        weakness_id=weakness.id,
                        target="svc-email",
                        path=mailbox_path,
                        expect_contains=weakness.kind,
                    ),
                )
            )
        current = "svc-email"
    else:
        current = weakness.target

    realization_path = first_realization_path(
        weakness, kind="workflow"
    ) or first_realization_path(weakness)
    effect_token = effect_marker_token(weakness)
    payload = shell_payload(
        action=reference_action_for_weakness_family(weakness.family),
        weakness_id=weakness.id,
        target=weakness.target,
        path=realization_path,
        expect_contains=effect_token or weakness.kind,
    )
    if effect_token:
        live_command = effect_marker_command(
            realization_path=realization_path or "",
            effect_path=effect_marker_path(weakness),
            effect_content=effect_marker_content(weakness),
            markers=workflow_effect_markers_for_kind(weakness.kind),
        )
        payload["command"] = live_command
        payload["service_command"] = live_command
    satisfied: list[str] = []
    objective = target_ref_objective(world, weakness.target_ref)
    if objective is not None:
        payload["objective"] = objective
        satisfied.append(objective)
    steps.append(
        ReferenceAction(
            actor="red",
            kind="shell",
            target=weakness.target,
            payload=payload,
        )
    )
    return RedReferencePlan(
        steps=tuple(steps),
        current=current,
        satisfied_predicates=tuple(satisfied),
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


def render_realization_content(
    world: WorldIR,
    weakness: WeaknessSpec,
    realization: WeaknessRealizationSpec,
) -> str:
    if realization.kind == "mailbox":
        subject = "Password reset verification"
        body = "Confirm your account details to complete the request."
        if weakness.kind == "internal_request_impersonation":
            subject = "Urgent internal request"
            body = "Please share the requested file and credentials for the finance review."
        return textwrap.dedent(
            f"""\
            Subject: {subject}

            OpenRange workflow message for {world.world_id}
            mailbox_path={realization.path}
            action={body}
            """
        )

    payload = {
        "world_id": world.world_id,
        "approval_guard": "disabled",
    }
    if weakness.kind == "helpdesk_reset_bypass":
        payload.update(
            {"identity_verification": "none", "reset_without_ticket_owner": True}
        )
    elif weakness.kind == "approval_chain_bypass":
        payload.update({"required_approvals": 1, "secondary_approval_skipped": True})
    elif weakness.kind == "document_share_abuse":
        payload.update(
            {"share_visibility": "public_link", "expiration_required": False}
        )
    elif weakness.kind == "phishing_credential_capture":
        payload.update(
            {"mail_filtering": "allow", "credential_capture_landing": "/login"}
        )
    elif weakness.kind == "internal_request_impersonation":
        payload.update(
            {"sender_verification": "disabled", "internal_alias_trust": True}
        )
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"
