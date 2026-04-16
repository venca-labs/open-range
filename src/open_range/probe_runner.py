"""Reference-trace execution helpers for admission."""

from __future__ import annotations

from open_range.episode_config import EpisodeConfig
from open_range.execution import PodActionBackend
from open_range.probe_planner import runtime_action
from open_range.runtime import OpenRangeRuntime
from open_range.runtime_types import Action
from open_range.snapshot import RuntimeSnapshot


def run_red_reference(
    snapshot: RuntimeSnapshot,
    backend: PodActionBackend | None = None,
    *,
    episode_seed: int,
    trace_index: int = 0,
):
    del episode_seed
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
    red_steps = list(trace.steps)
    step_idx = 0
    while not runtime.state().done and step_idx < len(red_steps):
        try:
            decision = runtime.next_decision()
        except RuntimeError:
            if runtime.state().done:
                break
            raise
        if decision.actor != "red":
            break
        step = red_steps[step_idx]
        result = runtime.act("red", runtime_action("red", step))
        outputs.append(result.stdout or result.stderr)
        step_idx += 1
    score = runtime.score()
    events = tuple(event.model_dump(mode="json") for event in runtime.export_events())
    health = tuple(sorted(runtime.state().service_health.items()))
    return score, events, health, outputs


def run_blue_reference(
    snapshot: RuntimeSnapshot,
    backend: PodActionBackend | None = None,
    *,
    trace_index: int = 0,
):
    trace = snapshot.reference_bundle.reference_defense_traces[trace_index]
    attack_index = trace_index % max(
        1, len(snapshot.reference_bundle.reference_attack_traces)
    )
    runtime = OpenRangeRuntime(action_backend=backend)
    runtime.reset(
        snapshot,
        EpisodeConfig(
            mode="blue_only_live",
            opponent_red="reference",
            episode_horizon_minutes=max(6, len(trace.steps) + 3),
        ),
        reference_attack_index=attack_index,
        reference_defense_index=trace_index,
    )
    outputs: list[str] = []
    blue_steps = list(trace.steps)
    step_idx = 0
    while not runtime.state().done:
        try:
            decision = runtime.next_decision()
        except RuntimeError:
            if runtime.state().done:
                break
            raise
        step = blue_steps[step_idx] if step_idx < len(blue_steps) else None
        action = (
            runtime_action("blue", step)
            if step is not None
            else Action(actor_id="blue", role="blue", kind="sleep", payload={})
        )
        result = runtime.act("blue", action)
        outputs.append(result.stdout or result.stderr)
        if decision.actor != "blue":
            break
        if step is not None:
            step_idx += 1
    return runtime.score(), outputs
