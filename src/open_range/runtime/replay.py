"""Runtime-owned helpers for replaying reference traces."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from open_range.catalog.probes import runtime_payload_for_reference_action
from open_range.config import EpisodeConfig
from open_range.runtime.execution import PodActionBackend
from open_range.runtime_types import (
    Action,
    RuntimeEvent,
    action_target,
    control_directive,
    control_directive_from_payload,
    finding_event_type,
    finding_event_type_from_payload,
)
from open_range.snapshot import RuntimeSnapshot
from open_range.training.trace_exports import normalize_trace_action


@dataclass(frozen=True, slots=True)
class ReferencePlayback:
    snapshot: RuntimeSnapshot
    attack_index: int
    defense_index: int

    @classmethod
    def resolve(
        cls,
        snapshot: RuntimeSnapshot,
        *,
        reset_seq: int,
        requested_attack_index: int | None,
        requested_defense_index: int | None,
    ) -> ReferencePlayback:
        attack_count = len(snapshot.reference_bundle.reference_attack_traces)
        attack_index = cls._resolve_index(
            requested_attack_index,
            attack_count,
            fallback=0,
            reset_seq=reset_seq,
        )
        defense_count = len(snapshot.reference_bundle.reference_defense_traces)
        defense_index = cls._resolve_index(
            requested_defense_index,
            defense_count,
            fallback=attack_index,
            reset_seq=reset_seq,
        )
        return cls(
            snapshot=snapshot,
            attack_index=attack_index,
            defense_index=defense_index,
        )

    def attack_trace(self):
        traces = self.snapshot.reference_bundle.reference_attack_traces
        return traces[self.attack_index % len(traces)]

    def defense_trace(self):
        traces = self.snapshot.reference_bundle.reference_defense_traces
        return traces[self.defense_index % len(traces)]

    def next_step(self, actor: str, progress: int):
        trace = self.attack_trace() if actor == "red" else self.defense_trace()
        if progress >= len(trace.steps):
            return None
        return trace.steps[progress]

    @staticmethod
    def _resolve_index(
        requested: int | None,
        count: int,
        *,
        fallback: int,
        reset_seq: int,
    ) -> int:
        if count < 1:
            return 0
        if requested is not None:
            return requested % count
        return (fallback + reset_seq - 1) % count


def action_for_reference_step(
    snapshot: RuntimeSnapshot, actor: str, step: Any | None
) -> Action:
    if step is None:
        return Action(actor_id=actor, role=actor, kind="sleep", payload={})
    return normalize_trace_action(snapshot, runtime_action(actor, step))


def runtime_action(actor: str, step: Any) -> Action:
    payload = runtime_payload_for_reference_action(
        actor,
        getattr(step, "kind", ""),
        target=getattr(step, "target", ""),
        payload=dict(getattr(step, "payload", {})),
    )
    return Action(
        actor_id=actor,
        role=actor,
        kind=getattr(step, "kind", ""),
        payload=payload,
    )


def run_red_reference(
    snapshot: RuntimeSnapshot,
    backend: PodActionBackend | None = None,
    trace_index: int = 0,
):
    from open_range.runtime import OpenRangeRuntime

    trace = snapshot.reference_bundle.reference_attack_traces[trace_index]
    runtime = OpenRangeRuntime(action_backend=backend)
    runtime.reset(
        snapshot,
        EpisodeConfig(
            mode="red_only",
            opponent_blue="none",
            episode_horizon_minutes=max(5, len(trace.steps) + 2),
        ),
        reference_attack_index=trace_index,
    )
    outputs: list[str] = []
    for step in trace.steps:
        try:
            decision = runtime.next_decision()
        except RuntimeError:
            if runtime.state().done:
                break
            raise
        if decision.actor != "red":
            break
        result = runtime.act("red", runtime_action("red", step))
        outputs.append(result.stdout or result.stderr)
    score = runtime.score()
    events = tuple(event.model_dump(mode="json") for event in runtime.export_events())
    health = tuple(sorted(runtime.state().service_health.items()))
    return score, events, health, outputs


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


def prefix_satisfied(
    start_state: str,
    *,
    step_action: str,
    emitted: tuple[RuntimeEvent, ...],
    red_progress: int,
) -> bool:
    event_types = {event.event_type for event in emitted}
    if start_state == "prefix_delivery":
        return step_action in {"deliver_phish", "deliver_lure"}
    if start_state == "prefix_click":
        return step_action == "click_lure" or "InitialAccess" in event_types
    if start_state == "prefix_foothold":
        return "InitialAccess" in event_types
    if start_state == "prefix_credential_theft":
        return "CredentialObtained" in event_types
    if start_state == "prefix_lateral_movement":
        return "CrossZoneTraversal" in event_types or red_progress >= 2
    return False
