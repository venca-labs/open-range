"""Runtime backing contract.

A ``RuntimeBacking`` knows how to run one ``Entrypoint.kind``: start the
underlying artifacts (containers, processes, mocks), expose the
domain-specific interface that checks consume, and tear it all down.
Built-in backings (HTTP) live in ``openrange.core.backings``; packs
introducing a new entrypoint kind ship their own backing through
``Pack.runtime_backings()``.

This is the seam that lets Core stay domain-agnostic. Core never knows
what HTTP, MCP, shell, or simulator means — backings translate between
the agent's interaction surface and the underlying runtime.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

from openrange.core.pack import admission_state_from_source

if TYPE_CHECKING:
    from openrange.core.pack import Entrypoint


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


class RuntimeBacking:
    """Manages one ``Entrypoint.kind`` through its lifecycle.

    A backing knows how to:
    - ``start`` an artifact set into a running instance
    - ``stop`` a running instance
    - expose the ``interface`` (callables + state) that checks consume
    - ``run_check`` a Python source-defined check against the interface
    - optionally ``checkpoint`` and ``restore`` for counterfactual training

    Subclasses must set ``kind`` and implement ``start`` and ``stop``.
    Default ``interface`` returns empty; default ``run_check`` exec's the
    source as ``admission_state(interface)`` and passes ``self.interface``.
    """

    kind: str = ""

    def start(
        self,
        entrypoint: Entrypoint,
        artifacts: Mapping[str, str],
        world: Mapping[str, Any],
        ctx: BackingContext,
    ) -> RunningArtifact:
        raise NotImplementedError

    def stop(self, instance: RunningArtifact) -> None:
        raise NotImplementedError

    def interface(self, instance: RunningArtifact) -> Mapping[str, Any]:
        """Return the interface dict checks consume.

        Default: empty mapping. Backings whose checks need callables
        (``http_get``, ``shell_run``, ...) override this.
        """
        del instance
        return {}

    def run_check(
        self,
        instance: RunningArtifact,
        source: str,
    ) -> Mapping[str, Any]:
        """Run a check function against the running artifact.

        Default: load ``source`` as ``def admission_state(interface)``,
        call it with ``self.interface(instance)``. Backings override if
        their checks need a different signature.
        """
        return admission_state_from_source(source)(self.interface(instance))

    def checkpoint(self, instance: RunningArtifact) -> ArtifactCheckpoint | None:
        del instance
        return None

    def restore(
        self,
        checkpoint: ArtifactCheckpoint,
        ctx: BackingContext,
    ) -> RunningArtifact:
        del checkpoint, ctx
        raise NotImplementedError(
            f"backing {self.kind!r} does not support restore",
        )


class RuntimeRegistry:
    """Lookup of backings by entrypoint kind."""

    def __init__(self) -> None:
        self._backings: dict[str, RuntimeBacking] = {}

    def register(self, backing: RuntimeBacking) -> None:
        self._backings[backing.kind] = backing

    def resolve(self, kind: str) -> RuntimeBacking | None:
        return self._backings.get(kind)

    def require(self, kind: str) -> RuntimeBacking:
        backing = self._backings.get(kind)
        if backing is None:
            known = ", ".join(self.kinds()) or "<none registered>"
            raise KeyError(
                f"no runtime backing registered for kind {kind!r} (known: {known})",
            )
        return backing

    def kinds(self) -> tuple[str, ...]:
        return tuple(sorted(self._backings))


RUNTIME_BACKINGS = RuntimeRegistry()


# Re-export for convenience; concrete backings register themselves in
# ``openrange.core.backings`` on import.
__all__ = [
    "RUNTIME_BACKINGS",
    "ArtifactCheckpoint",
    "BackingContext",
    "RunningArtifact",
    "RuntimeBacking",
    "RuntimeRegistry",
]
