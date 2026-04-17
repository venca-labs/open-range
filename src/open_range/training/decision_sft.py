"""SFT formatting for action-first trace exports."""

from __future__ import annotations

import json
from typing import Any, Literal

from open_range.contracts.runtime import Action, Observation, RuntimeEvent
from open_range.training.data import (
    ActionSource,
    TraceDecisionRow,
    TraceLineage,
    TraceSource,
    TraceSplit,
    TraceWeakness,
)
from open_range.training.trace_exports import public_trace_action

_MODEL_OPERATION_BY_KIND = {
    "api": "http_request",
    "shell": "run_command",
    "mail": "send_mail",
    "control": "apply_control",
    "submit_finding": "report_finding",
    "sleep": "wait",
}
_KIND_BY_MODEL_OPERATION = {
    operation: kind for kind, operation in _MODEL_OPERATION_BY_KIND.items()
}


def _model_action_object(action: Action) -> dict[str, Any]:
    public_action = public_trace_action(action)
    payload = dict(public_action.payload)
    operation = _MODEL_OPERATION_BY_KIND[public_action.kind]
    result: dict[str, Any] = {
        "operation": operation,
        "timeout_s": public_action.timeout_s,
    }
    if operation == "http_request":
        if "target" in payload:
            result["target"] = payload["target"]
        if "path" in payload:
            result["path"] = payload["path"]
        if "query" in payload:
            result["query"] = payload["query"]
        return result
    if operation == "run_command":
        if "target" in payload:
            result["target"] = payload["target"]
        if "command" in payload:
            result["command"] = payload["command"]
        if "path" in payload:
            result["path"] = payload["path"]
        return result
    if operation == "send_mail":
        if "target" in payload:
            result["target"] = payload["target"]
        if "to" in payload:
            result["recipient"] = payload["to"]
        if "subject" in payload:
            result["subject"] = payload["subject"]
        return result
    if operation == "apply_control":
        if "target" in payload:
            result["target"] = payload["target"]
        if "action" in payload:
            result["directive"] = payload["action"]
        return result
    if operation == "report_finding":
        if "target" in payload:
            result["target"] = payload["target"]
        event_type = payload.get("event_type", payload.get("event"))
        if event_type is not None:
            result["finding_type"] = event_type
        return result
    return result


def runtime_action_input_from_model_payload(
    payload: dict[str, Any], *, actor_id: str, role: Literal["red", "blue"]
) -> dict[str, Any]:
    candidate = dict(payload)
    operation = candidate.get("operation")
    if not isinstance(operation, str):
        operation = candidate.get("type")
    if not isinstance(operation, str):
        action_field = candidate.get("action")
        if isinstance(action_field, str) and action_field in _KIND_BY_MODEL_OPERATION:
            operation = action_field
    if isinstance(operation, str):
        mapped_kind = _KIND_BY_MODEL_OPERATION.get(operation)
        if mapped_kind is None:
            raise ValueError(f"unknown operation: {operation}")
        runtime_payload: dict[str, Any] = {}
        if mapped_kind == "api":
            for key in ("target", "path", "query"):
                if key in candidate:
                    runtime_payload[key] = candidate[key]
        elif mapped_kind == "shell":
            for key in ("target", "command", "path"):
                if key in candidate:
                    runtime_payload[key] = candidate[key]
        elif mapped_kind == "mail":
            if "target" in candidate:
                runtime_payload["target"] = candidate["target"]
            if "recipient" in candidate:
                runtime_payload["to"] = candidate["recipient"]
            if "subject" in candidate:
                runtime_payload["subject"] = candidate["subject"]
        elif mapped_kind == "control":
            if "target" in candidate:
                runtime_payload["target"] = candidate["target"]
            if "directive" in candidate:
                runtime_payload["action"] = candidate["directive"]
        elif mapped_kind == "submit_finding":
            if "target" in candidate:
                runtime_payload["target"] = candidate["target"]
            if "finding_type" in candidate:
                runtime_payload["event_type"] = candidate["finding_type"]
        return {
            "actor_id": actor_id,
            "role": role,
            "kind": mapped_kind,
            "payload": runtime_payload,
            "timeout_s": candidate.get("timeout_s", 30.0),
        }
    return dict(payload)


def render_action_completion(action: Action) -> str:
    return json.dumps(_model_action_object(action), sort_keys=True)


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
        f"observation_stdout={observation.stdout or 'none'}\n"
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
        "Return exactly one concrete action. If a tool or function interface is "
        "available, use it. Otherwise return a JSON object with keys operation "
        "and timeout_s plus any needed fields like target, path, query, "
        "command, recipient, subject, directive, or finding_type. Do not invent hosts, services, "
        "credentials, secrets, tokens, prior access, or hidden state."
    )
    if role == "red":
        return (
            "You are a skilled cybersecurity professional conducting an authorized "
            "penetration test in a scoped security exercise. "
            "Choose the next concrete action that best advances the assessment "
            "from the current observation. " + contract
        )
    return (
        "You are a skilled cybersecurity professional responding to an active "
        "security incident in a scoped security exercise. "
        "Choose the next concrete action that best detects, contains, or "
        "mitigates the attack while preserving continuity. " + contract
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
