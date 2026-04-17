"""Catalog-backed workflow templates for enterprise business flows."""

from __future__ import annotations

from open_range.catalog.contracts import WorkflowTemplateSpec, WorkflowTemplateStepSpec

WORKFLOW_TEMPLATE_SPECS: tuple[WorkflowTemplateSpec, ...] = (
    WorkflowTemplateSpec(
        name="helpdesk_ticketing",
        steps=(
            WorkflowTemplateStepSpec(
                id="open-ticket",
                actor_role="sales",
                action="open_ticket",
                service="svc-web",
            ),
            WorkflowTemplateStepSpec(
                id="mail-update",
                actor_role="sales",
                action="send_update",
                service="svc-email",
            ),
        ),
    ),
    WorkflowTemplateSpec(
        name="payroll_approval",
        steps=(
            WorkflowTemplateStepSpec(
                id="view-payroll",
                actor_role="finance",
                action="view_payroll",
                service="svc-web",
                asset="payroll_db",
            ),
            WorkflowTemplateStepSpec(
                id="approve-payroll",
                actor_role="finance",
                action="approve_payroll",
                service="svc-db",
                asset="payroll_db",
            ),
        ),
    ),
    WorkflowTemplateSpec(
        name="document_sharing",
        steps=(
            WorkflowTemplateStepSpec(
                id="share-doc",
                actor_role="sales",
                action="share_document",
                service="svc-fileshare",
                asset="finance_docs",
            ),
        ),
    ),
    WorkflowTemplateSpec(
        name="internal_email",
        steps=(
            WorkflowTemplateStepSpec(
                id="check-mail",
                actor_role="sales",
                action="check_mail",
                service="svc-email",
            ),
        ),
    ),
)

_WORKFLOW_TEMPLATES_BY_NAME = {entry.name: entry for entry in WORKFLOW_TEMPLATE_SPECS}


def workflow_template_for_name(name: str) -> WorkflowTemplateSpec | None:
    return _WORKFLOW_TEMPLATES_BY_NAME.get(name)


def workflow_step_templates_for_name(name: str) -> tuple[WorkflowTemplateStepSpec, ...]:
    template = workflow_template_for_name(name)
    if template is not None:
        return template.steps
    return (
        WorkflowTemplateStepSpec(
            id=f"{name}-step-1",
            actor_role="sales",
            action=name,
            service="svc-web",
        ),
    )
