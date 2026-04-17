"""Internal episode driver helpers built on the public decision loop."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol

from open_range.config import DEFAULT_EPISODE_CONFIG, EpisodeConfig
from open_range.contracts.runtime import Action, Observation
from open_range.contracts.snapshot import RuntimeSnapshot
from open_range.runtime import OpenRangeRuntime


class SessionAgent(Protocol):
    def reset(self, briefing: str, role: str) -> None: ...
    def act(self, observation: Observation) -> Action: ...


@dataclass
class TurnRecord:
    role: str
    sim_time: float
    observation: Observation
    action: Action
    stdout: str
    reward_delta: float


@dataclass
class EpisodeTrace:
    snapshot_id: str
    episode_id: str
    turns: list[TurnRecord] = field(default_factory=list)
    winner: str = ""
    done: bool = False


class TandemEpisodeDriver:
    """Drive a full episode against separate red and blue sessions."""

    def __init__(self, runtime: OpenRangeRuntime) -> None:
        self.runtime = runtime

    def run_episode(
        self,
        snapshot: RuntimeSnapshot,
        *,
        red_agent: SessionAgent,
        blue_agent: SessionAgent,
        episode_config: EpisodeConfig = DEFAULT_EPISODE_CONFIG,
    ) -> EpisodeTrace:
        state = self.runtime.reset(snapshot, episode_config)
        briefing = f"snapshot={snapshot.snapshot_id} sim_time={state.sim_time:.2f}"
        if state.controls_red:
            red_agent.reset(briefing, "red")
        if state.controls_blue:
            blue_agent.reset(briefing, "blue")

        trace = EpisodeTrace(
            snapshot_id=snapshot.snapshot_id, episode_id=state.episode_id
        )

        while True:
            if self.runtime.state().done:
                break
            try:
                decision = self.runtime.next_decision()
            except RuntimeError:
                if self.runtime.state().done:
                    break
                raise
            agent = red_agent if decision.actor == "red" else blue_agent
            action = agent.act(decision.obs)
            result = self.runtime.act(decision.actor, action)
            trace.turns.append(
                TurnRecord(
                    role=decision.actor,
                    sim_time=result.sim_time,
                    observation=decision.obs,
                    action=action,
                    stdout=result.stdout,
                    reward_delta=result.reward_delta,
                )
            )

        score = self.runtime.score()
        trace.winner = score.winner
        trace.done = score.done
        return trace


class ScriptedRuntimeAgent:
    """Small deterministic agent for internal driver tests."""

    def __init__(self, actions: list[Action]) -> None:
        self._actions = list(actions)
        self._idx = 0

    def reset(self, briefing: str, role: str) -> None:
        del briefing, role
        self._idx = 0

    def act(self, observation: Observation) -> Action:
        del observation
        action = self._actions[self._idx % len(self._actions)]
        self._idx += 1
        return action
