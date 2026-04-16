"""Internal helpers for replaying reference traces through the runtime."""

from __future__ import annotations

from typing import Any

from open_range.probe_planner import runtime_action
from open_range.runtime_types import Action
from open_range.snapshot import RuntimeSnapshot
from open_range.training_data import normalize_trace_action


def action_for_reference_step(
    snapshot: RuntimeSnapshot, actor: str, step: Any | None
) -> Action:
    if step is None:
        return Action(actor_id=actor, role=actor, kind="sleep", payload={})
    return normalize_trace_action(snapshot, runtime_action(actor, step))


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
