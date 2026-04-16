"""Workflow compilation helpers."""

from __future__ import annotations

from open_range.catalog.workflows import workflow_step_templates_for_name
from open_range.world_ir import EdgeSpec, WorkflowSpec, WorkflowStepSpec


def compile_workflows(
    workflow_names: tuple[str, ...],
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
        )
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
