"""Optional deterministic sim-plane for cheap bootstrap traces."""

from __future__ import annotations

from typing import Protocol

from pydantic import BaseModel, ConfigDict, Field

from open_range.episode_config import EpisodeConfig
from open_range.runtime import ReferenceDrivenRuntime
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
        runtime = ReferenceDrivenRuntime()
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
                action = self._red_step(red_steps, red_idx)
                red_idx += 1
            else:
                action = self._blue_step(blue_steps, blue_idx)
                blue_idx += 1
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

    @staticmethod
    def _red_step(red_steps, idx: int) -> Action:
        step = red_steps[min(idx, len(red_steps) - 1)]
        payload = dict(step.payload)
        if step.target:
            payload.setdefault("target", step.target)
        return Action(actor_id="red", role="red", kind=step.kind, payload=payload)

    @staticmethod
    def _blue_step(blue_steps, idx: int) -> Action:
        step = blue_steps[min(idx, len(blue_steps) - 1)]
        payload = dict(step.payload)
        if step.target:
            payload.setdefault("target", step.target)
        if step.kind == "submit_finding":
            payload["event_type"] = str(
                payload.get("event", payload.get("event_type", "InitialAccess"))
            )
        return Action(actor_id="blue", role="blue", kind=step.kind, payload=payload)
