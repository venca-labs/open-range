"""Episode service: the agent harness's seam into running worlds.

The agent acts on the world through whatever entrypoints the world
exposes (HTTP, shell, file, MCP, browser). OpenRange does not own the
agent action; ``record_turn`` is observational only. ``tick`` and
``advance`` move the world (NPCs, timers, state machines). ``checkpoint``
/ ``restore`` / ``fork`` enable counterfactual training.

The cyber pack today has no scheduler, so ``tick`` is a no-op and
``advance(until="terminal")`` polls until the agent writes its result file
or a timeout fires. The shape of the API is what matters for future
hybrid packs.
"""

from __future__ import annotations

import shutil
import threading
import uuid
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, Literal

from openrange.core.errors import OpenRangeError
from openrange.core.pack import Entrypoint, Task
from openrange.core.runtime_backing import RUNTIME_BACKINGS, RunningArtifact
from openrange.core.turn import ActorTurn

if TYPE_CHECKING:
    from openrange.core.snapshot import Snapshot
    from openrange.dashboard import DashboardView


class EpisodeError(OpenRangeError):
    """Raised when an episode operation cannot proceed."""


# ---------------------------------------------------------------------------
# Public data shapes
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class EpisodeHandle:
    id: str
    snapshot_id: str
    task_id: str

    @property
    def running_world_id(self) -> str:
        # Phase 5: one running world per episode. Will diverge once
        # episodes can attach to a shared pre-warmed world.
        return self.id


@dataclass(frozen=True, slots=True)
class Observation:
    visible_state: Mapping[str, Any] = field(default_factory=dict)
    events: tuple[Mapping[str, Any], ...] = ()
    metadata: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class AgentTurn:
    message: str | None = None
    tool_calls: tuple[Mapping[str, Any], ...] = ()
    tool_results: tuple[Mapping[str, Any], ...] = ()
    metadata: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class TickRequest:
    max_events: int | None = None
    process_npcs: bool = True
    process_timers: bool = True


@dataclass(frozen=True, slots=True)
class TickResult:
    events: tuple[Mapping[str, Any], ...] = ()
    done: bool = False
    terminal_reason: str | None = None


@dataclass(frozen=True, slots=True)
class AdvanceRequest:
    until: Literal["observation", "event", "terminal", "idle"] = "observation"
    max_ticks: int = 16
    timeout_seconds: float | None = None


@dataclass(frozen=True, slots=True)
class EpisodeUpdate:
    observation: Observation | None = None
    events: tuple[Mapping[str, Any], ...] = ()
    done: bool = False
    terminal_reason: str | None = None


@dataclass(frozen=True, slots=True)
class EpisodeReport:
    snapshot_id: str
    task_id: str
    final_state: Mapping[str, object]
    verifier_result: Mapping[str, object] | None = None
    agent_summary: str = ""

    def as_dict(self) -> dict[str, object]:
        return {
            "snapshot_id": self.snapshot_id,
            "task_id": self.task_id,
            "final_state": dict(self.final_state),
            "verifier_result": (
                None
                if self.verifier_result is None
                else dict(self.verifier_result)
            ),
            "agent_summary": self.agent_summary,
        }


@dataclass(frozen=True, slots=True)
class EpisodeCheckpoint:
    """Captured state for a running episode.

    Cheap for stateless backings (process: just record the log offset);
    expensive for stateful ones (pickle the state machine). v0 captures
    enough to restart the cyber pack's HTTP server fresh while preserving
    the agent_root contents.
    """

    id: str
    episode_id: str
    snapshot_id: str
    task_id: str
    request_log_offset: int
    agent_root_snapshot: Path
    metadata: Mapping[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Internal per-episode state
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class _RunningEpisode:
    """Per-episode state owned by EpisodeService."""

    handle: EpisodeHandle
    snapshot: Snapshot
    task: Task
    entrypoint: Entrypoint
    run_root: Path
    env_root: Path
    agent_root: Path
    base_url: str
    running_artifact: RunningArtifact | None = None
    request_log: Path | None = None
    request_count: int = 0
    request_lock: threading.Lock = field(default_factory=threading.Lock)
    dashboard: DashboardView | None = None
    agent_summary: str = ""
    final_state: Mapping[str, object] | None = None
    verifier_result: Mapping[str, object] | None = None
    tick_thread: threading.Thread | None = None
    tick_stop: threading.Event | None = None


# ---------------------------------------------------------------------------
# EpisodeService
# ---------------------------------------------------------------------------


class EpisodeService:
    """Owns running worlds; provides start, observe, advance, checkpoint, fork."""

    def __init__(
        self,
        run_root: str | Path,
        *,
        dashboard: DashboardView | None = None,
    ) -> None:
        self.run_root = Path(run_root)
        self.run_root.mkdir(parents=True, exist_ok=True)
        self.dashboard = dashboard
        self._episodes: dict[str, _RunningEpisode] = {}

    # -- lifecycle ----------------------------------------------------------

    def start_episode(
        self,
        snapshot: Snapshot,
        task_id: str | None = None,
    ) -> EpisodeHandle:
        from openrange.core.runtime_backing import RUNTIME_BACKINGS, BackingContext
        from openrange.core.runtime_helpers import write_task_file

        task = (
            snapshot.task(task_id) if task_id is not None else snapshot.get_tasks()[0]
        )
        if not task.entrypoints:
            raise EpisodeError(f"task {task.id!r} has no entrypoints")
        entrypoint = task.entrypoints[0]
        backing = RUNTIME_BACKINGS.require(entrypoint.kind)

        episode_id = uuid.uuid4().hex[:12]
        # First episode for this task in this run uses the bare task.id;
        # forks / restores / parallel episodes append the id.
        candidate = self.run_root / task.id
        episode_root = (
            candidate
            if not candidate.exists()
            else self.run_root / f"{task.id}-{episode_id}"
        )
        env_root = episode_root / "env"
        agent_root = episode_root / "agent"
        env_root.mkdir(parents=True)
        agent_root.mkdir()

        running_artifact = backing.start(
            entrypoint,
            snapshot.artifacts,
            snapshot.world,
            BackingContext(episode_id=episode_id, workdir=env_root),
        )
        base_url = str(running_artifact.metadata["base_url"])
        request_log = Path(str(running_artifact.metadata["request_log"]))
        write_task_file(agent_root, task, entrypoint, base_url)

        handle = EpisodeHandle(episode_id, snapshot.id, task.id)
        running = _RunningEpisode(
            handle=handle,
            snapshot=snapshot,
            task=task,
            entrypoint=entrypoint,
            run_root=episode_root,
            env_root=env_root,
            agent_root=agent_root,
            base_url=base_url,
            running_artifact=running_artifact,
            request_log=request_log,
            dashboard=self.dashboard,
        )
        self._episodes[handle.id] = running
        self._record_system(
            running,
            {"reset": True},
            state={"env_root": str(env_root), "agent_root": str(agent_root)},
        )
        self._record_system(
            running,
            {"start": "http_server"},
            observation={"base_url": base_url},
        )
        if snapshot.manifest.runtime.tick.mode == "auto":
            self._start_auto_tick(running, snapshot.manifest.runtime.tick.rate_hz)
        return handle

    def stop_episode(
        self,
        episode: EpisodeHandle,
        reason: str = "completed",
    ) -> EpisodeReport:
        from openrange.core.runtime_helpers import (
            final_state_from_episode,
            read_requests,
            validate_public_interface_interaction,
        )

        del reason
        running = self._require(episode)
        if running.running_artifact is not None:
            backing = RUNTIME_BACKINGS.require(running.running_artifact.kind)
            backing.stop(running.running_artifact)
            running.running_artifact = None
        self._stop_auto_tick(running)
        # Drain any remaining log entries to the dashboard, then read the
        # full request history for validation + final-state assembly.
        self._sync_request_log(running)
        requests = (
            read_requests(running.request_log)
            if running.request_log is not None
            else ()
        )
        validate_public_interface_interaction(running.entrypoint, requests)
        final_state = final_state_from_episode(
            running.agent_root,
            running.entrypoint,
            running.snapshot.world,
            requests,
        )
        running.final_state = final_state
        verifier = running.snapshot.verifier(running.task.id)
        verifier_result = MappingProxyType(dict(verifier(final_state)))
        running.verifier_result = verifier_result
        self._record_system(running, {"finish": True}, state=final_state)
        return EpisodeReport(
            snapshot_id=running.snapshot.id,
            task_id=running.task.id,
            final_state=final_state,
            verifier_result=verifier_result,
            agent_summary=running.agent_summary,
        )

    def check_episode(self, episode: EpisodeHandle) -> EpisodeReport:
        """Idempotent: returns the report from a stopped episode."""
        running = self._require(episode)
        if running.final_state is None:
            return self.stop_episode(episode, reason="checked")
        return EpisodeReport(
            snapshot_id=running.snapshot.id,
            task_id=running.task.id,
            final_state=running.final_state,
            verifier_result=running.verifier_result,
            agent_summary=running.agent_summary,
        )

    def base_url(self, episode: EpisodeHandle) -> str:
        return self._require(episode).base_url

    def agent_root(self, episode: EpisodeHandle) -> Path:
        return self._require(episode).agent_root

    # -- agent / world flow -------------------------------------------------

    def observe(self, episode: EpisodeHandle) -> Observation:
        running = self._require(episode)
        events = self._sync_request_log(running)
        return Observation(
            visible_state=MappingProxyType({"base_url": running.base_url}),
            events=events,
            metadata=MappingProxyType({"agent_root": str(running.agent_root)}),
        )

    def record_turn(self, episode: EpisodeHandle, turn: AgentTurn) -> None:
        running = self._require(episode)
        if turn.message:
            running.agent_summary = turn.message
        # Future: forward to dashboard as ActorTurn. For Phase 5 we keep it
        # observational; dashboard wiring lives outside the public API.

    def tick(
        self,
        episode: EpisodeHandle,
        request: TickRequest | None = None,
    ) -> TickResult:
        del request  # cyber pack has no scheduler; future packs read this
        running = self._require(episode)
        events = self._sync_request_log(running)
        done, reason = self._terminal_state(running)
        return TickResult(events=events, done=done, terminal_reason=reason)

    def advance(
        self,
        episode: EpisodeHandle,
        request: AdvanceRequest | None = None,
    ) -> EpisodeUpdate:
        request = request or AdvanceRequest()
        running = self._require(episode)
        all_events: list[Mapping[str, Any]] = []
        for _ in range(request.max_ticks):
            events = self._sync_request_log(running)
            all_events.extend(events)
            done, reason = self._terminal_state(running)
            if done:
                return EpisodeUpdate(
                    observation=Observation(events=tuple(events)),
                    events=tuple(all_events),
                    done=True,
                    terminal_reason=reason,
                )
            if request.until == "observation" and events:
                return EpisodeUpdate(
                    observation=Observation(events=tuple(events)),
                    events=tuple(all_events),
                    done=False,
                )
        return EpisodeUpdate(
            events=tuple(all_events),
            done=False,
            terminal_reason="max_ticks",
        )

    # -- counterfactual support --------------------------------------------

    def checkpoint(self, episode: EpisodeHandle) -> EpisodeCheckpoint:
        """Capture enough state to spin up a sibling episode at this point.

        v0 captures the request log offset and a copy of the agent_root.
        Restoring kills the process and starts a fresh one — the cyber
        pack's HTTP server is stateless modulo the log + flag arg, so
        a fresh start at the same flag value yields a comparable world.
        """
        running = self._require(episode)
        offset = running.request_count
        snapshot_id = f"{episode.id}-{uuid.uuid4().hex[:8]}"
        snapshot_root = self.run_root / "checkpoints" / snapshot_id
        snapshot_root.mkdir(parents=True)
        agent_snapshot = snapshot_root / "agent"
        if running.agent_root.exists():
            shutil.copytree(running.agent_root, agent_snapshot)
        return EpisodeCheckpoint(
            id=uuid.uuid4().hex[:12],
            episode_id=episode.id,
            snapshot_id=running.snapshot.id,
            task_id=running.task.id,
            request_log_offset=offset,
            agent_root_snapshot=agent_snapshot,
        )

    def restore(self, checkpoint: EpisodeCheckpoint) -> EpisodeHandle:
        """Spin up a fresh episode from the checkpoint.

        v0: starts the world fresh with the same snapshot+task and copies
        agent-written files from the captured agent_root, giving the
        agent the same workspace contents it had at checkpoint time. The
        env-supplied task file is preserved from the new episode so the
        agent talks to the new world. Process state itself is not
        preserved — packs that need that ship a stateful backing.
        """
        running = self._episodes.get(checkpoint.episode_id)
        if running is None:
            raise EpisodeError(
                f"original episode {checkpoint.episode_id!r} not active",
            )
        new_handle = self.start_episode(running.snapshot, running.task.id)
        new_running = self._require(new_handle)
        self._copy_agent_workspace(
            checkpoint.agent_root_snapshot,
            new_running,
        )
        return new_handle

    def fork(self, episode: EpisodeHandle) -> EpisodeHandle:
        """Spin up a sibling episode from the current point.

        Equivalent to checkpoint+restore in v0; differs only in not
        leaving a checkpoint artifact on disk.
        """
        running = self._require(episode)
        new_handle = self.start_episode(running.snapshot, running.task.id)
        new_running = self._require(new_handle)
        self._copy_agent_workspace(running.agent_root, new_running)
        return new_handle

    def _copy_agent_workspace(
        self,
        source: Path,
        target_running: _RunningEpisode,
    ) -> None:
        """Copy agent-written files into the new episode's agent_root.

        Skips env-supplied files (the task file) so the agent always sees
        the fresh world's URL.
        """
        if not source.exists():
            return
        task_file_name = target_running.entrypoint.metadata.get(
            "task_file",
            "OPENRANGE_TASK.json",
        )
        env_supplied = {str(task_file_name)}
        for item in source.iterdir():
            if item.name in env_supplied:
                continue
            destination = target_running.agent_root / item.name
            if item.is_dir():
                shutil.copytree(item, destination, dirs_exist_ok=True)
            else:
                shutil.copy2(item, destination)

    # -- internals ----------------------------------------------------------

    def _require(self, episode: EpisodeHandle) -> _RunningEpisode:
        running = self._episodes.get(episode.id)
        if running is None:
            raise EpisodeError(f"unknown episode {episode.id!r}")
        return running

    def _terminal_state(
        self,
        running: _RunningEpisode,
    ) -> tuple[bool, str | None]:
        result_file = str(running.entrypoint.metadata.get("result_file", ""))
        if result_file and (running.agent_root / result_file).exists():
            return True, "result_written"
        if running.running_artifact is None:
            return True, "stopped"
        return False, None

    def _sync_request_log(
        self,
        running: _RunningEpisode,
    ) -> tuple[Mapping[str, Any], ...]:
        from openrange.core.runtime_helpers import read_requests

        if running.request_log is None:
            return ()
        with running.request_lock:
            requests = read_requests(running.request_log)
            new = tuple(requests[running.request_count :])
            running.request_count = len(requests)
        for row in new:
            self._record_agent_request(running, row)
        return new

    def _record_system(
        self,
        running: _RunningEpisode,
        action: Mapping[str, object],
        *,
        observation: Mapping[str, object] | None = None,
        state: Mapping[str, object] | None = None,
    ) -> None:
        if running.dashboard is None:
            return
        running.dashboard.record_turn(
            ActorTurn(
                running.task.id,
                "runtime",
                "system",
                "environment",
                action,
                observation=observation,
                state=state,
            ),
        )

    def _record_agent_request(
        self,
        running: _RunningEpisode,
        row: Mapping[str, Any],
    ) -> None:
        if running.dashboard is None:
            return
        running.dashboard.record_turn(
            ActorTurn(
                running.task.id,
                "agent",
                "agent",
                running.entrypoint.target,
                {
                    "method": str(row.get("method", "")),
                    "path": str(row.get("path", "")),
                },
                observation={"status": row.get("status", 0)},
                metadata={"source": "http_access_log"},
            ),
        )

    def _start_auto_tick(self, running: _RunningEpisode, rate_hz: float) -> None:
        """Run ``tick`` in the background at ``rate_hz`` while the episode is alive.

        The auto-tick keeps NPCs / timers moving without harness intervention.
        For packs without a scheduler (cyber today) this is essentially a
        cheap polling loop; that's intentional — the *contract* is what
        future packs depend on.
        """
        running.tick_stop = threading.Event()
        running.tick_thread = threading.Thread(
            target=_auto_tick_loop,
            args=(self, running, rate_hz),
            daemon=True,
        )
        running.tick_thread.start()

    def _stop_auto_tick(self, running: _RunningEpisode) -> None:
        if running.tick_thread is None or running.tick_stop is None:
            return
        running.tick_stop.set()
        running.tick_thread.join(timeout=5)
        running.tick_thread = None
        running.tick_stop = None

    def close(self) -> None:
        """Stop all live episodes."""
        for running in list(self._episodes.values()):
            if running.running_artifact is not None:
                backing = RUNTIME_BACKINGS.require(running.running_artifact.kind)
                backing.stop(running.running_artifact)
                running.running_artifact = None
            self._stop_auto_tick(running)
        self._episodes.clear()


def _auto_tick_loop(
    service: EpisodeService,
    running: _RunningEpisode,
    rate_hz: float,
) -> None:
    if running.tick_stop is None:
        return
    interval = 1.0 / rate_hz
    while not running.tick_stop.wait(interval):
        try:
            service.tick(running.handle)
        except EpisodeError:
            return  # episode was stopped


# Re-export for convenience
__all__ = [
    "AdvanceRequest",
    "AgentTurn",
    "EpisodeCheckpoint",
    "EpisodeError",
    "EpisodeHandle",
    "EpisodeReport",
    "EpisodeService",
    "EpisodeUpdate",
    "Observation",
    "TickRequest",
    "TickResult",
]
