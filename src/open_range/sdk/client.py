"""Thin store-backed decision-loop facade for admitted snapshots."""

from __future__ import annotations

from pathlib import Path

from open_range.config import DEFAULT_EPISODE_CONFIG, EpisodeConfig
from open_range.contracts.runtime import (
    Action,
    ActionResult,
    Decision,
    EpisodeScore,
    EpisodeState,
)
from open_range.render.live import BootedRelease, LiveBackend
from open_range.runtime import OpenRangeRuntime
from open_range.runtime.execution import ActionBackend, PodActionBackend
from open_range.store import FileSnapshotStore, load_runtime_snapshot
from open_range.store.core import PoolSplit, sample_runtime_snapshot


class OpenRange:
    """Load admitted snapshots from the store and run episodes by snapshot id."""

    def __init__(
        self,
        *,
        store: FileSnapshotStore | None = None,
        runtime: OpenRangeRuntime | None = None,
        live_backend: LiveBackend | None = None,
        action_backend: ActionBackend | None = None,
    ) -> None:
        self.store = store or FileSnapshotStore()
        self.runtime = runtime or OpenRangeRuntime()
        self.live_backend = live_backend
        self.action_backend = action_backend or PodActionBackend()
        self._active_snapshot_id = ""
        self._live_release: BootedRelease | None = None

    def reset(
        self,
        snapshot_id: str | None = None,
        episode_config: EpisodeConfig = DEFAULT_EPISODE_CONFIG,
        *,
        split: PoolSplit = "train",
        strategy: str = "random",
        sample_seed: int | None = None,
        require_live: bool = False,
    ) -> EpisodeState:
        if require_live and self.live_backend is None:
            raise RuntimeError(
                "live runtime required, but no live_backend is configured"
            )
        snapshot = (
            load_runtime_snapshot(self.store, snapshot_id)
            if snapshot_id is not None
            else sample_runtime_snapshot(
                self.store,
                split=split,
                seed=0 if sample_seed is None else sample_seed,
                strategy=strategy,
            )
        )
        if self._live_release is not None and self.live_backend is not None:
            self.live_backend.teardown(self._live_release)
            self._live_release = None
        if self.live_backend is not None:
            self._live_release = self.live_backend.boot(
                snapshot_id=snapshot.snapshot_id,
                artifacts_dir=Path(snapshot.artifacts.render_dir),
            )
            self.action_backend.bind(snapshot, self._live_release)
            self.runtime.set_action_backend(self.action_backend)
        else:
            self.action_backend.clear()
            self.runtime.set_action_backend(None)
        self._active_snapshot_id = snapshot.snapshot_id
        return self.runtime.reset(snapshot, episode_config)

    def next_decision(self) -> Decision:
        return self.runtime.next_decision()

    def act(self, actor: str, action: Action) -> ActionResult:
        return self.runtime.act(actor, action)

    def state(self) -> EpisodeState:
        return self.runtime.state()

    def score(self) -> EpisodeScore:
        return self.runtime.score()

    def close(self) -> None:
        if self._live_release is not None and self.live_backend is not None:
            self.live_backend.teardown(self._live_release)
            self._live_release = None
        self.action_backend.clear()
        self.runtime.set_action_backend(None)
        self.runtime.close()
        self._active_snapshot_id = ""

    @property
    def active_snapshot_id(self) -> str:
        return self._active_snapshot_id

    @property
    def live_release(self) -> BootedRelease | None:
        return self._live_release

    @property
    def execution_mode(self) -> str:
        return "live" if self._live_release is not None else "offline"
