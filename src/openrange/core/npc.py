"""NPC contract and registry.

An NPC is an autonomous actor that runs alongside the agent during an
episode. Cyber NPCs make HTTP requests; a hypothetical trading NPC
would place orders. The contract is domain-agnostic — NPCs receive the
same ``interface`` dict the verifier and admission probe see, so they
speak whatever the runtime backing exposes.

Lifecycle:
  - ``start(context)`` — once, when the episode starts (after the
    runtime is up). NPCs typically capture the interface here.
  - ``step(interface)`` — once per tick. NPCs decide whether to act
    based on their own internal cadence (a cadence-2 NPC acts every
    other tick).
  - ``stop()`` — once, when the episode ends. NPCs should release any
    resources they captured.

Registration is via the ``openrange.npcs`` entry-point group (mirrors
packs / builders). Entry-point values must resolve to a callable
``(config: Mapping[str, object]) -> NPC`` — the registry constructs
each NPC fresh per episode by calling the factory with the manifest
entry's ``config`` mapping.

Manifest schema:

    npc:
      - type: cyber.browsing_user      # NPCRegistry id
        count: 3                        # spawn N independent instances
        config:
          cadence_ticks: 2
          paths: ["/search?q=alpha"]

``count`` defaults to 1; ``config`` defaults to ``{}``.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Callable, Mapping
from typing import Any

from openrange.core.errors import OpenRangeError

NPC_ENTRY_POINT_GROUP = "openrange.npcs"

NPCFactory = Callable[[Mapping[str, object]], "NPC"]


class NPCError(OpenRangeError):
    """Raised when an NPC cannot be resolved or constructed."""


class NPC(ABC):
    """An autonomous actor that runs alongside the agent during an episode.

    Subclasses implement ``step``. Default ``start`` and ``stop`` are
    no-ops; override them when the NPC needs setup / teardown that
    can't happen in ``__init__``.
    """

    @abstractmethod
    def step(self, interface: Mapping[str, Any]) -> None:
        """One tick of action.

        ``interface`` is the same mapping the verifier and admission
        probe receive (e.g. ``{base_url, http_get, http_get_json}`` for
        the HTTP backing). Implementations decide whether to act on
        this tick based on their own internal cadence; failures should
        be swallowed to keep the episode running.
        """

    def start(self, context: Mapping[str, Any]) -> None:
        """Optional setup hook, called once when the episode starts.

        ``context`` carries metadata about the running world — at
        minimum ``{episode_id, snapshot_id, task_id}``. Default: no-op.
        """
        del context

    def stop(self) -> None:  # noqa: B027 — intentional default no-op
        """Optional teardown hook, called once when the episode ends.

        Default: no-op. Subclasses release resources here (close
        connections, flush state, etc.).
        """


class NPCRegistry:
    """Registry of NPC factories by id.

    Factories are registered explicitly via ``register()`` or, on the
    global ``NPCS`` instance, discovered via Python entry points in
    the ``openrange.npcs`` group. Entry-point values must resolve to
    a callable ``(config) -> NPC``.

    ``autodiscover=False`` (the default) gives a clean slate suitable
    for tests. The global ``NPCS = NPCRegistry(autodiscover=True)``
    pulls in installed NPCs on first access.
    """

    def __init__(self, *, autodiscover: bool = False) -> None:
        self._factories: dict[str, NPCFactory] = {}
        self._autodiscover = autodiscover
        self._discovered = False

    def register(self, npc_id: str, factory: NPCFactory) -> None:
        self._factories[npc_id] = factory

    def resolve(self, npc_id: str, config: Mapping[str, object]) -> NPC:
        self._ensure_discovered()
        try:
            factory = self._factories[npc_id]
        except KeyError as exc:
            raise NPCError(f"unknown NPC {npc_id!r}") from exc
        npc = factory(config)
        if not isinstance(npc, NPC):
            raise NPCError(
                f"NPC factory {npc_id!r} did not return an NPC instance",
            )
        return npc

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
        from importlib.metadata import entry_points

        for entry_point in entry_points(group=NPC_ENTRY_POINT_GROUP):
            if entry_point.name in self._factories and not force:
                continue
            try:
                factory = entry_point.load()
            except Exception as exc:  # noqa: BLE001
                raise NPCError(
                    f"failed to load NPC entry point {entry_point.name!r}: {exc}",
                ) from exc
            if not callable(factory):
                raise NPCError(
                    f"entry point {entry_point.name!r} did not yield a callable",
                )
            self._factories[entry_point.name] = factory


NPCS = NPCRegistry(autodiscover=True)


def resolve_manifest_npcs(
    npc_entries: tuple[Mapping[str, object], ...],
    *,
    registry: NPCRegistry | None = None,
) -> list[NPC]:
    """Construct NPC instances from manifest entries.

    Each entry is a mapping with ``type`` (required), ``count`` (default
    1), and ``config`` (default empty). Returns a flat list of NPCs —
    one per spawn slot, so the caller can iterate and step uniformly.
    """
    reg = registry if registry is not None else NPCS
    npcs: list[NPC] = []
    for entry in npc_entries:
        npc_type = entry.get("type")
        if not isinstance(npc_type, str) or not npc_type:
            raise NPCError("manifest npc entry must carry a non-empty 'type'")
        count_raw = entry.get("count", 1)
        if not isinstance(count_raw, int) or count_raw < 0:
            raise NPCError(
                f"manifest npc entry 'count' must be a non-negative int "
                f"(got {count_raw!r})",
            )
        config_raw = entry.get("config", {})
        if not isinstance(config_raw, Mapping):
            raise NPCError(
                f"manifest npc entry 'config' must be a mapping for {npc_type!r}",
            )
        for _ in range(count_raw):
            npcs.append(reg.resolve(npc_type, config_raw))
    return npcs


__all__ = [
    "NPC",
    "NPCS",
    "NPCError",
    "NPCFactory",
    "NPCRegistry",
    "NPC_ENTRY_POINT_GROUP",
    "resolve_manifest_npcs",
]
