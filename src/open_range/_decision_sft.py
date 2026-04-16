"""Internal SFT formatting for action-first trace exports."""

from __future__ import annotations

import json
from typing import Any, Literal

from open_range.runtime_types import Action, Observation, RuntimeEvent
from open_range.training_data import (
    ActionSource,
    TraceDecisionRow,
    TraceLineage,
    TraceSource,
    TraceSplit,
    TraceWeakness,
    public_trace_action,
)


def render_action_completion(action: Action) -> str:
    public_action = public_trace_action(action)
    return json.dumps(public_action.model_dump(mode="json"), sort_keys=True)


def row_to_sft_record(row: TraceDecisionRow) -> dict[str, Any]:
    return {
        "messages": [
            {"role": "system", "content": system_prompt_for_role(row.role)},
            {"role": "user", "content": render_decision_prompt(row)},
            {
                "role": "assistant",
                "content": render_action_completion(row.chosen_action),
            },
        ],
        "split": row.split,
        "snapshot_id": row.snapshot_id,
        "world_id": row.world_id,
        "world_hash": row.world_hash,
        "lineage_root_world_id": row.lineage.root_world_id,
        "lineage_generation": row.lineage.generation,
        "lineage_parent_world_id": row.lineage.parent_world_id,
        "lineage_mutation_ops": list(row.lineage.mutation_ops),
        "mode": row.mode,
        "start_state": row.start_state,
        "prompt_mode": row.episode_config.prompt_mode,
        "role": row.role,
        "trace_source": row.trace_source,
        "action_source": row.action_source,
        "benchmark_tags": list(row.benchmark_tags),
        "weaknesses": [weak.model_dump(mode="json") for weak in row.weaknesses],
        "chosen_action": row.chosen_action.model_dump(mode="json"),
        "chosen_action_text": row.chosen_action_text,
        "winner": row.winner,
        "terminal_reason": row.terminal_reason,
        "grounded_effects": list(row.grounded_effects),
        "mitigation_effects": list(row.mitigation_effects),
    }


def render_decision_prompt(row: TraceDecisionRow) -> str:
    return build_decision_prompt(
        snapshot_id=row.snapshot_id,
        world_id=row.world_id,
        world_hash=row.world_hash,
        lineage=row.lineage,
        mode=row.mode,
        start_state=row.start_state,
        role=row.role,
        decision_index=row.decision_index,
        observation=row.observation,
        weaknesses=row.weaknesses,
        benchmark_tags=row.benchmark_tags,
        trace_source=row.trace_source,
        action_source=row.action_source,
        split=row.split,
        prompt_mode=row.episode_config.prompt_mode,
        include_hidden_context=False,
    )


def build_decision_prompt(
    *,
    snapshot_id: str,
    world_id: str,
    world_hash: str,
    lineage: TraceLineage,
    mode: str,
    start_state: str,
    role: Literal["red", "blue"],
    decision_index: int,
    observation: Observation,
    weaknesses: tuple[TraceWeakness, ...],
    benchmark_tags: tuple[str, ...],
    trace_source: TraceSource,
    action_source: ActionSource,
    split: TraceSplit,
    prompt_mode: str,
    include_hidden_context: bool = False,
) -> str:
    visible = _visible_event_lines(observation.visible_events)
    lines = [
        f"sim_time={observation.sim_time:.2f}\n"
        f"last_stdout={observation.stdout or 'none'}\n"
        f"alerts_delta={len(observation.alerts_delta)}\n"
        f"service_health={_service_health_text(observation)}\n"
        f"visible_events:\n{visible}\n"
    ]
    if include_hidden_context:
        lines.insert(
            0,
            f"trace_source={trace_source}\n"
            f"action_source={action_source}\n"
            f"split={split}\n"
            f"snapshot_id={snapshot_id}\n"
            f"world_id={world_id}\n"
            f"world_hash={world_hash}\n"
            f"lineage_root_world_id={lineage.root_world_id}\n"
            f"lineage_generation={lineage.generation}\n"
            f"lineage_mutation_ops={','.join(lineage.mutation_ops) or 'none'}\n"
            f"mode={mode}\n"
            f"start_state={start_state}\n"
            f"prompt_mode={prompt_mode}\n"
            f"role={role}\n"
            f"decision_index={decision_index}\n",
        )
        weaknesses_text = "\n".join(
            f"- {weak.family}:{weak.kind}@{weak.target} tags={','.join(weak.benchmark_tags) or 'none'} objectives={','.join(weak.objective_tags) or 'none'}"
            for weak in weaknesses
        )
        lines.append(f"benchmark_tags={','.join(benchmark_tags) or 'none'}\n")
        lines.append(f"weaknesses:\n{weaknesses_text or '- none'}\n")
    return "".join(lines)


def system_prompt_for_role(role: Literal["red", "blue"]) -> str:
    contract = (
        "Respond with exactly one OpenRange Action JSON object with keys "
        "actor_id, role, kind, payload, and timeout_s. Do not add prose."
    )
    if role == "red":
        return (
            "You are the red operator in OpenRange. "
            "Choose the next concrete runtime action that best advances the current path. "
            + contract
        )
    return (
        "You are the blue operator in OpenRange. "
        "Choose the next concrete runtime action that best detects or mitigates the attack while preserving continuity. "
        + contract
    )


def _service_health_text(observation: Observation) -> str:
    if not observation.service_health:
        return "unknown"
    return ", ".join(
        f"{entry.service_id}={entry.health:.2f}" for entry in observation.service_health
    )


def _visible_event_lines(events: tuple[RuntimeEvent, ...]) -> str:
    if not events:
        return "- none"
    return "\n".join(
        f"- {event.event_type} src={event.source_entity} dst={event.target_entity} malicious={str(event.malicious).lower()}"
        for event in events[-6:]
    )
