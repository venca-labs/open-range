"""Workflow compilation helpers."""

from __future__ import annotations

from open_range.catalog.workflows import workflow_step_templates_for_name
from open_range.contracts.world import EdgeSpec, WorkflowSpec, WorkflowStepSpec


def compile_workflows(
    workflow_names: tuple[str, ...],
    *,
    available_service_ids: frozenset[str] = frozenset(),
) -> tuple[tuple[WorkflowSpec, ...], tuple[EdgeSpec, ...]]:
    workflows: list[WorkflowSpec] = []
    workflow_edges: list[EdgeSpec] = []

    for workflow_name in workflow_names:
        steps = tuple(
            WorkflowStepSpec(
                id=step.id,
                actor_role=step.actor_role,
                action=step.action,
                service=step.service,
                asset=step.asset,
            )
            for step in workflow_step_templates_for_name(workflow_name)
            if not available_service_ids
            or not step.service
            or step.service in available_service_ids
        )
        if not steps:
            continue
        workflows.append(
            WorkflowSpec(
                id=f"wf-{workflow_name}",
                name=workflow_name,
                steps=steps,
            )
        )
        for idx, step in enumerate(steps, start=1):
            if step.service:
                workflow_edges.append(
                    EdgeSpec(
                        id=f"workflow-{workflow_name}-{idx}",
                        kind="workflow",
                        source=step.actor_role,
                        target=step.service,
                        label=step.action,
                    )
                )
            if step.asset:
                workflow_edges.append(
                    EdgeSpec(
                        id=f"data-{workflow_name}-{idx}",
                        kind="data",
                        source=step.service or step.actor_role,
                        target=step.asset,
                        label=step.action,
                    )
                )

    return tuple(workflows), tuple(workflow_edges)
