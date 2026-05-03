"""Builder contract.

A Builder generates the concrete content of one world: the typed graph
that conforms to a pack's ontology, the tasks an agent can attempt, and
the feasibility / episode checks Core uses to admit the world and grade
agent runs.

Builders are domain-agnostic in their **protocol** — every builder takes
and returns a ``BuildState`` — but typically domain-specific in their
**implementation**. Two builders for the same pack are interchangeable
because both speak the pack's ontology; a pack may ship a default builder
for convenience, but any conforming Builder works.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from openrange.core.builder import BuildState


class Builder(ABC):
    """Generates one concrete world from a manifest + pack.

    Subclasses implement the four ``generate_*`` methods. ``repair`` has
    a default no-op implementation; builders that learn from admission
    failure (e.g. an LLM-driven builder using feedback) override it.

    Each method takes a ``BuildState`` and returns a new ``BuildState``
    with one more field populated. Use ``dataclasses.replace`` to update.

    Convention: builders accept an ``llm`` argument at construction (may
    be ``None``). Non-LLM builders ignore it. The orchestrator
    instantiates the pack's default builder via ``builder_cls(llm)``.
    """

    def __init__(self, llm: Any | None = None) -> None:
        self.llm = llm

    @abstractmethod
    def generate_world_graph(self, state: BuildState) -> BuildState: ...

    @abstractmethod
    def generate_tasks(self, state: BuildState) -> BuildState: ...

    @abstractmethod
    def generate_feasibility_checks(self, state: BuildState) -> BuildState: ...

    @abstractmethod
    def generate_episode_checks(self, state: BuildState) -> BuildState: ...

    def repair(self, state: BuildState, failures: tuple[str, ...]) -> BuildState:
        """Adjust state in response to admission failures and try again.

        Default: return state unchanged. Builders that can react to
        feedback (LLM-backed ones, autotopology mutators, etc.) override
        this to consume ``failures`` and produce a state with at least
        one field re-generated.
        """
        return state
