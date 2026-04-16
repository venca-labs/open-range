"""Internal helpers for replaying reference traces through the runtime."""

from __future__ import annotations

from typing import Any

from open_range.probe_planner import runtime_action
from open_range.runtime_events import (
    action_target,
    control_directive,
    control_directive_from_payload,
    finding_event_type,
    finding_event_type_from_payload,
)
from open_range.runtime_types import Action
from open_range.snapshot import RuntimeSnapshot
from open_range.training.trace_exports import normalize_trace_action


def action_for_reference_step(
    snapshot: RuntimeSnapshot, actor: str, step: Any | None
) -> Action:
    if step is None:
        return Action(actor_id=actor, role=actor, kind="sleep", payload={})
    return normalize_trace_action(snapshot, runtime_action(actor, step))


def matches_reference_step(action: Action, expected: Any, live_stdout: str) -> bool:
    if action.kind != expected.kind or action_target(action) != expected.target:
        return False
    if action.kind == "api":
        expected_path = expected.payload.get("path")
        actual_path = action.payload.get("path")
        if (expected_path or actual_path) and actual_path != expected_path:
            return False
        expected_query = expected.payload.get("query")
        actual_query = action.payload.get("query")
        if (expected_query or actual_query) and actual_query != expected_query:
            return False
        expected_contains = str(expected.payload.get("expect_contains", "")).strip()
        if expected_contains and expected_contains not in live_stdout:
            return False
    if action.kind in {"shell", "mail"}:
        expected_path = expected.payload.get("path")
        actual_path = action.payload.get("path")
        if (expected_path or actual_path) and actual_path != expected_path:
            return False
        expected_contains = str(expected.payload.get("expect_contains", "")).strip()
        if expected_contains and expected_contains not in live_stdout:
            return False
    if action.kind == "control":
        expected_directive = control_directive_from_payload(expected.payload)
        if expected_directive and control_directive(action) != expected_directive:
            return False
    if action.kind == "submit_finding":
        expected_event = finding_event_type_from_payload(expected.payload)
        actual_event = finding_event_type(action)
        if expected_event and actual_event != expected_event:
            return False
    return True


def reference_trace_pairs(
    snapshot: RuntimeSnapshot, mode: str
) -> tuple[tuple[int, int], ...]:
    attack_count = max(1, len(snapshot.reference_bundle.reference_attack_traces))
    defense_count = max(1, len(snapshot.reference_bundle.reference_defense_traces))
    if mode == "red_only":
        return tuple((idx, idx % defense_count) for idx in range(attack_count))
    if mode in {"blue_only_live", "blue_only_from_prefix"}:
        return tuple((idx % attack_count, idx) for idx in range(defense_count))
    count = max(attack_count, defense_count)
    return tuple((idx % attack_count, idx % defense_count) for idx in range(count))
