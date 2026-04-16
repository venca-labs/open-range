"""Branch-native trace row schema and export helpers."""

from __future__ import annotations

import json
from typing import Literal
from urllib.parse import urlencode

from pydantic import BaseModel, ConfigDict, Field

from open_range.build_config import BuildConfig
from open_range.episode_config import EpisodeConfig
from open_range.objectives import StandardAttackObjective
from open_range.runtime_types import Action, Observation, RuntimeEvent
from open_range.snapshot import RuntimeSnapshot

TraceSource = Literal["runtime", "sim"]
TraceSplit = Literal["train", "val", "test"]
ActionSource = Literal["reference_runtime", "reference_sim"]
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


class TraceDecisionRow(_StrictModel):
    trace_source: TraceSource
    action_source: ActionSource
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
