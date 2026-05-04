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

Two NPC shapes ship in core:

* ``NPC`` — the bare ABC. Subclasses implement ``step`` against the
  backing's interface. Use this for scripted NPCs (cron-job style:
  cadence + a fixed action).
* ``AgentNPC`` — an LLM-backed agent loop with a tool surface and a
  persona. Subclasses define ``_build_tools(interface)`` and a system
  prompt; the runtime supplies the model. The agent loop itself is
  delegated to the optional ``strands-agents`` SDK so we don't
  re-invent tool dispatch / streaming / cancellation.

NPCs that opt into LLM access set ``requires_llm = True``. The
episode runtime then injects an ``llm`` key (a model id string, or
``None`` if the runtime wasn't configured with one) into the
``context`` mapping passed to ``start()``.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Callable, Mapping, Sequence
from typing import Any, ClassVar

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

    Set ``requires_llm = True`` (class attribute) to opt into LLM
    access — the episode runtime then includes an ``llm`` key in the
    ``context`` mapping passed to ``start()``. NPCs that don't opt in
    pay nothing; the runtime never builds or charges for a model on
    their behalf.
    """

    requires_llm: ClassVar[bool] = False

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
        minimum ``{episode_id, snapshot_id, task_id, base_url}``. NPCs
        with ``requires_llm = True`` additionally receive an ``llm``
        key (a model id string, or ``None``). Default: no-op.
        """
        del context

    def stop(self) -> None:  # noqa: B027 — intentional default no-op
        """Optional teardown hook, called once when the episode ends.

        Default: no-op. Subclasses release resources here (close
        connections, flush state, etc.).
        """


class AgentNPC(NPC):
    """An NPC backed by an LLM agent loop with a tool surface.

    Subclasses provide a persona (``system_prompt``) and a
    ``_build_tools(interface)`` hook that returns tool callables bound
    over the runtime backing's interface. The agent loop itself is
    delegated to the optional ``strands-agents`` SDK — we let it own
    tool dispatch, retries, and streaming rather than re-inventing
    those pieces.

    Cadence: like scripted NPCs, an ``AgentNPC`` does not invoke its
    LLM every tick — it acts once every ``cadence_ticks`` ticks. The
    LLM call is the expensive part; cadence is the budget knob.

    Failure model: per-NPC failures stay silent (the episode
    contract). If strands isn't installed or the model can't be
    constructed, the NPC marks itself broken on the first acting tick
    and stops trying — no per-tick retries.

    Subclasses override:

    * ``_build_tools(interface)`` — required. Return a list of
      ``@strands.tool``-decorated callables that close over the
      interface. The base class doesn't import strands itself; the
      decoration happens in the subclass so test doubles can skip it.
    * ``_user_prompt(interface)`` — optional. The message handed to
      the agent on each acting tick. Default: a generic "act
      consistently with your role" prompt.
    """

    requires_llm: ClassVar[bool] = True

    def __init__(
        self,
        *,
        system_prompt: str,
        cadence_ticks: int = 5,
        model: str | None = None,
    ) -> None:
        if not system_prompt:
            raise ValueError("system_prompt must be non-empty")
        if cadence_ticks < 1:
            raise ValueError("cadence_ticks must be >= 1")
        self._system_prompt = system_prompt
        self._cadence_ticks = cadence_ticks
        self._model_override = model
        self._runtime_model: str | None = None
        self._cooldown = 0
        self._agent: Any = None
        self._broken = False

    def start(self, context: Mapping[str, Any]) -> None:
        llm = context.get("llm")
        if llm is None or isinstance(llm, str):
            self._runtime_model = llm
        else:  # defensive — runtime contract is str | None
            self._runtime_model = None

    def step(self, interface: Mapping[str, Any]) -> None:
        if self._broken:
            return
        if self._cooldown > 0:
            self._cooldown -= 1
            return
        self._cooldown = self._cadence_ticks - 1
        if self._agent is None:
            try:
                tools = list(self._build_tools(interface))
                self._agent = self._build_agent(tools)
            except Exception:  # noqa: BLE001 — silent broken state
                self._broken = True
                self._agent = None
                return
        try:
            self._invoke_agent(self._user_prompt(interface))
        except Exception:  # noqa: BLE001 — per-tick LLM failures are silent
            return

    def stop(self) -> None:
        self._agent = None

    # -- subclass extension points ----------------------------------------

    @abstractmethod
    def _build_tools(
        self,
        interface: Mapping[str, Any],
    ) -> Sequence[Callable[..., Any]]:
        """Return tool callables bound over ``interface``.

        Subclasses typically wrap interface methods (``http_get``,
        ``http_get_json``, ...) with ``@strands.tool`` decorators so
        the agent loop can call them. The base class does not import
        strands itself — keep the decoration in the subclass.
        """

    def _user_prompt(self, interface: Mapping[str, Any]) -> str:
        """The prompt handed to the agent on each acting tick."""
        del interface
        return (
            "Take one realistic action consistent with your role. "
            "Use the available tools. Keep it short."
        )

    # -- overridable seams (tests inject fakes here) ----------------------

    def _build_agent(self, tools: Sequence[Callable[..., Any]]) -> Any:
        """Construct the underlying agent. Default: ``strands.Agent``.

        Override in tests to inject a fake without installing strands.
        """
        try:
            from strands import Agent
        except ImportError as exc:
            raise NPCError(
                "AgentNPC requires the optional 'strands-agents' package. "
                "Install with `pip install openrange[strands]`.",
            ) from exc
        kwargs: dict[str, Any] = {
            "tools": list(tools),
            "system_prompt": self._system_prompt,
            "callback_handler": None,
        }
        model = self._model_override or self._runtime_model
        if model is not None:
            kwargs["model"] = model
        return Agent(**kwargs)

    def _invoke_agent(self, prompt: str) -> None:
        """Run one agent turn with ``prompt``. Override for testing."""
        if self._agent is None:
            return
        self._agent(prompt)


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
        from openrange.core._registry import iter_entry_points

        for name, value in iter_entry_points(
            NPC_ENTRY_POINT_GROUP,
            error_cls=NPCError,
            kind="NPC",
        ):
            if name in self._factories and not force:
                continue
            if not callable(value):
                raise NPCError(
                    f"entry point {name!r} did not yield a callable",
                )
            self._factories[name] = value


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
