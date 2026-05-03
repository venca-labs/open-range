"""Runtime backing contract.

A ``RuntimeBacking`` knows how to start, stop, and (optionally) checkpoint
one ``RuntimeArtifact.kind``. Packs that emit a new artifact kind ship
their own backing through ``Pack.runtime_backings()``; built-in backings
for common kinds (``file``, ``process``) live next to ``EpisodeService``.

Phase 5 ships the protocol and a registry. Built-in backings are sketched
but ``EpisodeService`` currently uses module-level helpers in
``openrange.runtime`` for the cyber pack's process-spawning needs;
fleshing out the per-kind backing dispatch lands when the first hybrid
pack ships an artifact kind that isn't ``file`` or ``process``.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, Protocol

if TYPE_CHECKING:
    from openrange.core.graph import RuntimeArtifact


@dataclass(frozen=True, slots=True)
class BackingContext:
    """Per-episode context passed to backings when starting an artifact."""

    episode_id: str
    workdir: Path
    metadata: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class RunningArtifact:
    """A started artifact tracked by the episode runtime.

    ``handle`` is opaque to core: the backing that started this artifact
    is the only thing that interprets it (subprocess.Popen for processes,
    file path for files, state-machine instance for mocks, etc.).
    """

    id: str
    kind: str
    handle: Any
    metadata: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class ArtifactCheckpoint:
    """Captured state for one artifact, opaque to core."""

    artifact_id: str
    kind: str
    payload: Any


class RuntimeBacking(Protocol):
    """Knows how to manage one artifact ``kind`` through its lifecycle.

    ``checkpoint`` may return ``None`` if the backing cannot capture
    state cheaply; in that case the runtime falls back to stop+restart
    on ``restore``. ``fork`` defaults to start-fresh — a backing whose
    state is mutable should override.
    """

    kind: str

    def start(
        self,
        artifact: RuntimeArtifact,
        ctx: BackingContext,
    ) -> RunningArtifact: ...

    def stop(self, instance: RunningArtifact) -> None: ...

    def checkpoint(self, instance: RunningArtifact) -> ArtifactCheckpoint | None:
        return None

    def restore(
        self,
        checkpoint: ArtifactCheckpoint,
        ctx: BackingContext,
    ) -> RunningArtifact:
        raise NotImplementedError(
            f"backing {self.kind!r} does not support restore",
        )


class RuntimeRegistry:
    """Lookup of backings by artifact kind."""

    def __init__(self) -> None:
        self._backings: dict[str, RuntimeBacking] = {}

    def register(self, backing: RuntimeBacking) -> None:
        self._backings[backing.kind] = backing

    def resolve(self, kind: str) -> RuntimeBacking | None:
        return self._backings.get(kind)

    def kinds(self) -> tuple[str, ...]:
        return tuple(sorted(self._backings))


RUNTIME_BACKINGS = RuntimeRegistry()
