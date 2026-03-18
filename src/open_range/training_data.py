"""Branch-native training data schema and rendering helpers."""

from __future__ import annotations

import json
from typing import Any, Literal
from urllib.parse import urlencode

from pydantic import BaseModel, ConfigDict, Field

from open_range.build_config import BuildConfig
from open_range.episode_config import EpisodeConfig
from open_range.objectives import StandardAttackObjective
from open_range.runtime_types import Action, Observation, RuntimeEvent
from open_range.snapshot import RuntimeSnapshot


TraceSource = Literal["runtime", "sim"]
TraceSplit = Literal["train", "val", "test"]
TeacherSource = Literal["reference_runtime", "reference_sim", "scripted_runtime"]
CounterfactualLabel = Literal[
    "teacher",
    "alternative",
    "probe",
    "false_positive",
    "continuity_damaging",
    "sleep",
    "unknown",
]
_HIDDEN_ACTION_PAYLOAD_KEYS = frozenset({"service_command"})


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class TraceLineage(_StrictModel):
    root_world_id: str = Field(min_length=1)
    generation: int = Field(ge=0)
    parent_world_id: str | None = None
    mutation_ops: tuple[str, ...] = Field(default_factory=tuple)


class TraceWeakness(_StrictModel):
    weakness_id: str = Field(min_length=1)
    family: str = Field(min_length=1)
    kind: str = Field(min_length=1)
    target: str = Field(min_length=1)
    benchmark_tags: tuple[str, ...] = Field(default_factory=tuple)
    objective_tags: tuple[StandardAttackObjective, ...] = Field(default_factory=tuple)


class TraceCandidate(_StrictModel):
    label: str = Field(min_length=1)
    action: Action
    text: str
    selected: bool = False
    counterfactual_label: CounterfactualLabel = "unknown"


class TraceDecisionRow(_StrictModel):
    trace_source: TraceSource
    teacher_source: TeacherSource
    split: TraceSplit
    snapshot_id: str = Field(min_length=1)
    world_id: str = Field(min_length=1)
    world_hash: str = Field(min_length=1)
    lineage: TraceLineage
    episode_id: str = Field(min_length=1)
    mode: str = Field(min_length=1)
    start_state: str = Field(min_length=1)
    role: Literal["red", "blue"]
    decision_index: int = Field(ge=0)
    observation: Observation
    candidate_actions: tuple[TraceCandidate, ...] = Field(default_factory=tuple)
    chosen_action: Action
    chosen_action_text: str
    result_stdout: str = ""
    result_stderr: str = ""
    emitted_events: tuple[RuntimeEvent, ...] = Field(default_factory=tuple)
    grounded_effects: tuple[str, ...] = Field(default_factory=tuple)
    mitigation_effects: tuple[str, ...] = Field(default_factory=tuple)
    reward_delta: float = 0.0
    winner: str = ""
    terminal_reason: str = ""
    done: bool = False
    build_config: BuildConfig
    episode_config: EpisodeConfig
    weaknesses: tuple[TraceWeakness, ...] = Field(default_factory=tuple)
    benchmark_tags: tuple[str, ...] = Field(default_factory=tuple)


class TraceDatasetReport(_StrictModel):
    manifest_source: str = Field(min_length=1)
    raw_path: str = Field(min_length=1)
    decision_sft_path: str = Field(min_length=1)
    shard_paths: dict[str, str] = Field(default_factory=dict)
    roots: int = Field(ge=1)
    mutations_per_root: int = Field(ge=0)
    rows: int = Field(ge=0)
    counts_by_source: dict[str, int] = Field(default_factory=dict)
    counts_by_role: dict[str, int] = Field(default_factory=dict)
    counts_by_mode: dict[str, int] = Field(default_factory=dict)
    counts_by_split: dict[str, int] = Field(default_factory=dict)
    lineage_roots: tuple[str, ...] = Field(default_factory=tuple)


def normalize_trace_action(snapshot: RuntimeSnapshot, action: Action) -> Action:
    """Keep exported control semantics honest for non-service-native mitigations."""

    if action.kind != "control":
        return action
    directive = str(action.payload.get("action", "")).lower()
    target = str(action.payload.get("target", ""))
    if directive != "patch":
        return action
    if _supports_service_native_patch(snapshot, target):
        return action
    payload = dict(action.payload)
    payload["action"] = "mitigate"
    return action.model_copy(update={"payload": payload})


def public_trace_action(action: Action) -> Action:
    payload = {
        key: value
        for key, value in action.payload.items()
        if key not in _HIDDEN_ACTION_PAYLOAD_KEYS
    }
    return action.model_copy(update={"payload": payload})


def render_action_text(action: Action) -> str:
    target = str(action.payload.get("target", ""))
    if action.kind == "api":
        path = str(action.payload.get("path", "/") or "/")
        if not path.startswith("/"):
            path = f"/{path}"
        query = action.payload.get("query")
        query_text = ""
        if isinstance(query, dict) and query:
            query_text = "?" + urlencode(
                [(str(key), str(value)) for key, value in query.items()], doseq=True
            )
        return f"curl -s http://{target}{path}{query_text}"
    if action.kind == "shell":
        command = str(action.payload.get("command", "")).strip()
        if command:
            return command
        path = str(action.payload.get("path", "")).strip()
        return f"cat {path}" if path else f"sh -lc 'echo probe {target}'"
    if action.kind == "mail":
        to = str(action.payload.get("to", target or "user@corp.local"))
        subject = str(action.payload.get("subject", "openrange"))
        return f"send mail to {to} subject={subject}"
    if action.kind == "control":
        directive = str(action.payload.get("action", "contain")).lower()
        return f"{directive} {target}".strip()
    if action.kind == "submit_finding":
        event_type = str(
            action.payload.get(
                "event_type", action.payload.get("event", "InitialAccess")
            )
        )
        return f"submit_finding event={event_type} target={target}".strip()
    if action.kind == "sleep":
        return "sleep 1"
    return json.dumps({"kind": action.kind, "payload": action.payload}, sort_keys=True)


def render_candidate_completion(candidate: TraceCandidate) -> str:
    payload = json.dumps(candidate.action.model_dump(mode="json"), sort_keys=True)
    return (
        f"<choice>{candidate.label}</choice>\n"
        f"<action_text>{candidate.text}</action_text>\n"
        f"<action_json>{payload}</action_json>"
    )


def row_to_sft_record(row: TraceDecisionRow) -> dict[str, Any]:
    selected = next(
        (candidate for candidate in row.candidate_actions if candidate.selected), None
    )
    if selected is None:
        raise ValueError("trace row must contain exactly one selected candidate")
    return {
        "messages": [
            {"role": "system", "content": system_prompt_for_role(row.role)},
            {"role": "user", "content": render_decision_prompt(row)},
            {"role": "assistant", "content": render_candidate_completion(selected)},
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
        "teacher_source": row.teacher_source,
        "benchmark_tags": list(row.benchmark_tags),
        "weaknesses": [weak.model_dump(mode="json") for weak in row.weaknesses],
        "chosen_label": selected.label,
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
        candidate_actions=row.candidate_actions,
        weaknesses=row.weaknesses,
        benchmark_tags=row.benchmark_tags,
        trace_source=row.trace_source,
        teacher_source=row.teacher_source,
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
    candidate_actions: tuple[TraceCandidate, ...],
    weaknesses: tuple[TraceWeakness, ...],
    benchmark_tags: tuple[str, ...],
    trace_source: TraceSource,
    teacher_source: TeacherSource,
    split: TraceSplit,
    prompt_mode: str,
    include_hidden_context: bool = False,
) -> str:
    visible = _visible_event_lines(observation.visible_events)
    candidates = "\n".join(
        f"- [{candidate.label}] {candidate.text}" for candidate in candidate_actions
    )
    lines = [
        f"sim_time={observation.sim_time:.2f}\n"
        f"last_stdout={observation.stdout or 'none'}\n"
        f"alerts_delta={len(observation.alerts_delta)}\n"
        f"service_health={_service_health_text(observation)}\n"
        f"visible_events:\n{visible}\n"
        "candidate_actions:\n"
        f"{candidates}"
    ]
    if include_hidden_context:
        lines.insert(
            0,
            f"trace_source={trace_source}\n"
            f"teacher_source={teacher_source}\n"
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
    if role == "red":
        return (
            "You are the red operator in OpenRange. "
            "Choose exactly one candidate action that best advances the validated attack path."
        )
    return (
        "You are the blue operator in OpenRange. "
        "Choose exactly one candidate action that best detects or mitigates the attack while preserving continuity."
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


def trace_weaknesses(snapshot: RuntimeSnapshot) -> tuple[TraceWeakness, ...]:
    return tuple(
        TraceWeakness(
            weakness_id=weakness.id,
            family=weakness.family,
            kind=weakness.kind,
            target=weakness.target,
            benchmark_tags=tuple(weakness.benchmark_tags),
            objective_tags=tuple(weakness.objective_tags),
        )
        for weakness in snapshot.world.weaknesses
    )


def trace_benchmark_tags(snapshot: RuntimeSnapshot) -> tuple[str, ...]:
    tags = {
        tag for weakness in snapshot.world.weaknesses for tag in weakness.benchmark_tags
    }
    return tuple(sorted(tags))


def grounded_effects_for_result(
    *,
    stdout: str,
    emitted_events: tuple[RuntimeEvent, ...],
) -> tuple[str, ...]:
    labels = {
        event.event_type
        for event in emitted_events
        if event.event_type
        in {
            "CredentialObtained",
            "UnauthorizedCredentialUse",
            "PrivilegeEscalation",
            "SensitiveAssetRead",
            "PersistenceEstablished",
            "ServiceDegraded",
        }
    }
    labels.update(
        token
        for token in stdout.split()
        if token.startswith("OPENRANGE-EFFECT:")
        or token.startswith("OPENRANGE-FOOTHOLD:")
    )
    return tuple(sorted(labels))


def mitigation_effects_for_result(
    *,
    action: Action,
    stdout: str,
    emitted_events: tuple[RuntimeEvent, ...],
) -> tuple[str, ...]:
    labels = {
        event.event_type
        for event in emitted_events
        if event.event_type
        in {"ContainmentApplied", "PatchApplied", "RecoveryCompleted"}
    }
    if action.kind == "control":
        directive = str(action.payload.get("action", "")).lower()
        target = str(action.payload.get("target", ""))
        if (
            directive in {"contain", "patch", "mitigate", "recover", "restore"}
            and target
        ):
            labels.add(f"{directive}:{target}")
    if "mitigation applied to " in stdout:
        labels.add("mitigation_applied")
    if "patch applied to " in stdout:
        labels.add("patch_applied")
    if "containment applied to " in stdout:
        labels.add("containment_applied")
    return tuple(sorted(labels))


def _supports_service_native_patch(snapshot: RuntimeSnapshot, target: str) -> bool:
    return any(
        weakness.target == target
        and (
            weakness.family == "code_web"
            or (
                weakness.remediation_kind == "shell"
                and bool(weakness.remediation_command.strip())
            )
        )
        for weakness in snapshot.world.weaknesses
    )
