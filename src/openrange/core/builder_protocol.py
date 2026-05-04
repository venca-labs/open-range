"""Builder contract and registry.

A Builder generates the concrete content of one world: the typed graph
that conforms to a pack's ontology, the tasks an agent can attempt, and
the feasibility / episode checks Core uses to admit the world and grade
agent runs.

Builders are domain-agnostic in their **protocol** — every builder takes
and returns a ``BuildState`` — but typically domain-specific in their
**implementation**. Two builders for the same pack are interchangeable
because both speak the pack's ontology; a pack may ship a default builder
for convenience, but any conforming Builder works.

Construction is the Builder's choice — Core does not impose an
``__init__`` signature. The pack's ``default_builder(context)`` factory
constructs the builder however it likes, reading whatever it needs from
the BuildContext (LLM, prompt, curriculum, ...).

The ``BuilderRegistry`` discovers external builders via Python entry
points in the ``openrange.builders`` group. Manifests can opt into a
custom builder via ``manifest.builder = "<id>"``; the orchestrator
resolves it through the registry, taking precedence over the pack's
default builder.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Callable
from typing import TYPE_CHECKING

from openrange.core.errors import OpenRangeError

if TYPE_CHECKING:
    from openrange.core.admission import AdmissionFailure
    from openrange.core.builder import BuildContext, BuildState


BUILDER_ENTRY_POINT_GROUP = "openrange.builders"

BuilderFactory = Callable[["BuildContext"], "Builder"]


class BuilderError(OpenRangeError):
    """Raised when a builder cannot be resolved or constructed."""


class Builder(ABC):
    """Generates one concrete world from a manifest + pack.

    Subclasses implement the four ``generate_*`` methods. ``repair`` has
    a default no-op implementation; builders that learn from admission
    failure (e.g. an LLM-driven builder using feedback) override it.

    Each method takes a ``BuildState`` and returns a new ``BuildState``
    with one more field populated. Use ``dataclasses.replace`` to update.
    """

    @abstractmethod
    def generate_world_graph(self, state: BuildState) -> BuildState: ...

    @abstractmethod
    def generate_tasks(self, state: BuildState) -> BuildState: ...

    @abstractmethod
    def generate_feasibility_checks(self, state: BuildState) -> BuildState: ...

    @abstractmethod
    def generate_episode_checks(self, state: BuildState) -> BuildState: ...

    def repair(
        self,
        state: BuildState,
        failures: tuple[AdmissionFailure, ...],
    ) -> BuildState:
        """Adjust state in response to admission failures and try again.

        Default: return state unchanged. Builders that can react to
        feedback (LLM-backed ones, autotopology mutators, etc.) override
        this to consume ``failures`` and produce a state with at least
        one field re-generated. The orchestrator always re-runs the
        pipeline after ``repair`` returns; updating ``state.context.feedback``
        is one common repair tactic for LLM builders.
        """
        return state


class BuilderRegistry:
    """Registry of Builder factories by id.

    Builders are registered explicitly via ``register()`` or, on the
    global ``BUILDERS`` instance, discovered via Python entry points in
    the ``openrange.builders`` group. Entry-point values must resolve
    to a callable ``(BuildContext) -> Builder``.

    ``autodiscover=False`` (the default) gives a clean slate suitable
    for tests. The global ``BUILDERS = BuilderRegistry(autodiscover=True)``
    pulls in installed builders on first access.
    """

    def __init__(self, *, autodiscover: bool = False) -> None:
        self._factories: dict[str, BuilderFactory] = {}
        self._autodiscover = autodiscover
        self._discovered = False

    def register(self, builder_id: str, factory: BuilderFactory) -> None:
        self._factories[builder_id] = factory

    def resolve(self, builder_id: str, context: BuildContext) -> Builder:
        self._ensure_discovered()
        try:
            factory = self._factories[builder_id]
        except KeyError as exc:
            raise BuilderError(f"unknown builder {builder_id!r}") from exc
        return factory(context)

    def ids(self) -> tuple[str, ...]:
        self._ensure_discovered()
        return tuple(sorted(self._factories))

    def discover(self) -> None:
        self._ensure_discovered(force=True)

    def _ensure_discovered(self, *, force: bool = False) -> None:
        if not self._autodiscover and not force:
            return
        if self._discovered and not force:
            return
        self._discovered = True
        from openrange.core._registry import iter_entry_points

        for name, value in iter_entry_points(
            BUILDER_ENTRY_POINT_GROUP,
            error_cls=BuilderError,
            kind="builder",
        ):
            if name in self._factories and not force:
                continue
            if not callable(value):
                raise BuilderError(
                    f"entry point {name!r} did not yield a callable",
                )
            self._factories[name] = value


BUILDERS = BuilderRegistry(autodiscover=True)
