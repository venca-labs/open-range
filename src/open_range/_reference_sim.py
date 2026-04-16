"""Internal deterministic sim-plane for cheap bootstrap traces."""

from __future__ import annotations

from typing import Protocol

from pydantic import BaseModel, ConfigDict, Field

from open_range._reference_replay import action_for_reference_step
from open_range.episode_config import EpisodeConfig
from open_range.runtime import OpenRangeRuntime
from open_range.runtime_types import Action
from open_range.snapshot import RuntimeSnapshot


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class SimTurn(_StrictModel):
    role: str
    sim_time: float
    action: Action
    stdout: str = ""
    reward_delta: float = 0.0


class SimTrace(_StrictModel):
    snapshot_id: str
    episode_seed: int
    winner: str = ""
    turns: tuple[SimTurn, ...] = Field(default_factory=tuple)


class SimPlane(Protocol):
    def generate_bootstrap_trace(
        self, snapshot: RuntimeSnapshot, *, episode_seed: int
    ) -> SimTrace: ...


class ReferenceSimPlane:
    """Replay hidden reference traces through the public decision loop."""

    def generate_bootstrap_trace(
        self, snapshot: RuntimeSnapshot, *, episode_seed: int
    ) -> SimTrace:
        attack_index = episode_seed % max(
            1, len(snapshot.reference_bundle.reference_attack_traces)
        )
        defense_index = episode_seed % max(
            1, len(snapshot.reference_bundle.reference_defense_traces)
        )
        attack_trace = snapshot.reference_bundle.reference_attack_traces[attack_index]
        defense_trace = snapshot.reference_bundle.reference_defense_traces[
            defense_index
        ]
        runtime = OpenRangeRuntime()
        runtime.reset(
            snapshot,
            EpisodeConfig(
                mode="joint_pool",
                scheduler_mode="strict_turns",
                episode_horizon_minutes=max(6, len(attack_trace.steps) + 3),
            ),
            reference_attack_index=attack_index,
            reference_defense_index=defense_index,
        )
        turns: list[SimTurn] = []
        red_idx = 0
        blue_idx = 0
        red_steps = attack_trace.steps
        blue_steps = defense_trace.steps

        while not runtime.state().done:
            decision = runtime.next_decision()
            if decision.actor == "red":
                step = red_steps[min(red_idx, len(red_steps) - 1)]
                red_idx += 1
            else:
                step = blue_steps[min(blue_idx, len(blue_steps) - 1)]
                blue_idx += 1
            action = action_for_reference_step(snapshot, decision.actor, step)
            result = runtime.act(decision.actor, action)
            turns.append(
                SimTurn(
                    role=decision.actor,
                    sim_time=result.sim_time,
                    action=action,
                    stdout=result.stdout,
                    reward_delta=result.reward_delta,
                )
            )

        score = runtime.score()
        return SimTrace(
            snapshot_id=snapshot.snapshot_id,
            episode_seed=episode_seed,
            winner=score.winner,
            turns=tuple(turns),
        )
