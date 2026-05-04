"""Agent backend protocol — drives an agent loop with optional tools.

Used by ``AgentNPC`` at runtime. The protocol is intentionally
narrow: a backend is a factory that returns *something callable* —
a session that takes a prompt, runs one agent turn (with whatever
tool dispatch the backend natively supports), and returns. Anything
beyond that is provider-specific and lives behind the backend.

Two implementations ship:

* :class:`StrandsAgentBackend` — canonical, wraps ``strands.Agent``.
  Lazy-imports strands so the optional ``strands-agents`` extra is
  only required if this backend is actually instantiated. Supports
  tool dispatch.
* :class:`CodexAgentBackend` — wraps the existing
  :class:`openrange.llm.CodexBackend`. Single-shot, no tool
  injection — Codex's own tool surface (its sandboxed shell) isn't
  exposed for arbitrary callable injection. Useful for tool-less
  agent NPCs and for tests that want to exercise the agent path
  without an Anthropic key.

The two implementations are siblings, not adapter-and-adaptee — you
don't need strands installed to use Codex, and you don't need Codex
to use strands. ``AgentBackend`` is the seam that lets the runtime
plug either in without re-tooling its callers.

Future: the builder will likely accept an ``AgentBackend`` too,
collapsing build-time and runtime LLM configuration onto one
protocol. For now they remain separate (the builder uses the
:class:`openrange.llm.LLMBackend` single-shot protocol directly).
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from typing import Any, Protocol

from openrange.core.errors import OpenRangeError
from openrange.llm import (
    CODEX_DEFAULT_MODEL,
    CodexBackend,
    LLMBackend,
    LLMBackendError,
    LLMRequest,
)

AgentSession = Callable[[str], Any]
"""A live agent ready to receive prompts.

Calling it runs one agent turn. Tool dispatch (if the backend
supports it) happens inside the call as side effects on the tools
the backend was built with. The return value is provider-specific
and most callers can ignore it — NPCs care about the *side effects*
of tool calls, not the agent's text response.
"""


class AgentBackendError(OpenRangeError):
    """Raised when an agent backend cannot fulfill a request."""


class AgentBackend(Protocol):
    """Builds agent sessions, optionally with a tool surface.

    Implementations wrap a provider SDK (strands, codex, ...) into a
    consistent factory. Callers (NPCs, in the future the builder)
    don't bind to a specific provider — they configure one
    ``AgentBackend`` and pass it down.
    """

    def preflight(self) -> None:
        """Raise :class:`AgentBackendError` if this backend cannot run.

        Cheap checks only — verify imports, binaries, configuration.
        Don't make API calls. Called at NPC construction (when the
        backend is supplied directly) and at episode start (when the
        backend is supplied by the runtime), so a missing optional
        dep is detectable before the first acting tick.
        """
        ...

    def build_agent(
        self,
        *,
        system_prompt: str,
        tools: Sequence[Callable[..., Any]] = (),
    ) -> AgentSession:
        """Return a callable session for the configured provider.

        Backends that don't support tool dispatch must raise
        :class:`AgentBackendError` when ``tools`` is non-empty —
        silent dropping of tools would produce subtly broken
        agents.
        """
        ...


class StrandsAgentBackend:
    """Drive ``strands.Agent``. Lazy-imports the optional SDK.

    Tool dispatch, multi-turn loops, retries, and streaming are
    delegated to strands. This is the canonical backend for NPCs
    that need to call tools.
    """

    def __init__(self, *, model: str | None = None) -> None:
        self._model = model

    def preflight(self) -> None:
        try:
            import strands  # noqa: F401
        except ImportError as exc:
            raise AgentBackendError(
                "StrandsAgentBackend requires the optional 'strands-agents' "
                "package. Install with `pip install openrange[strands]`.",
            ) from exc

    def build_agent(
        self,
        *,
        system_prompt: str,
        tools: Sequence[Callable[..., Any]] = (),
    ) -> AgentSession:
        try:
            from strands import Agent
        except ImportError as exc:
            raise AgentBackendError(
                "StrandsAgentBackend requires the optional 'strands-agents' "
                "package. Install with `pip install openrange[strands]`.",
            ) from exc
        kwargs: dict[str, Any] = {
            "tools": list(tools),
            "system_prompt": system_prompt,
            "callback_handler": None,
        }
        if self._model is not None:
            kwargs["model"] = self._model
        agent: AgentSession = Agent(**kwargs)
        return agent


class CodexAgentBackend:
    """Drive the Codex CLI for tool-less agent prompts.

    Wraps :class:`openrange.llm.CodexBackend` (or any
    :class:`openrange.llm.LLMBackend`) — the same Codex binary,
    sandbox, and model the builder uses. Each ``AgentSession``
    invocation is a single ``LLMBackend.complete`` call; there is no
    multi-turn loop and no per-tool dispatch.

    Rejects ``tools`` loudly: Codex's tool surface (its sandboxed
    shell + edits) is fixed and not exposed for arbitrary callable
    injection. Pass an empty ``tools`` for chatter-only NPCs, or use
    :class:`StrandsAgentBackend` when you need real tool dispatch.
    """

    def __init__(
        self,
        *,
        backend: LLMBackend | None = None,
        model: str | None = None,
    ) -> None:
        if backend is not None and model is not None:
            raise AgentBackendError(
                "CodexAgentBackend: pass either 'backend' or 'model', not both",
            )
        self._backend: LLMBackend = (
            backend
            if backend is not None
            else CodexBackend(
                model=model if model is not None else CODEX_DEFAULT_MODEL,
            )
        )

    def preflight(self) -> None:
        # Delegate to the wrapped LLMBackend's own preflight — every
        # LLMBackend declares one (default no-op), so custom backends
        # can self-describe their checks instead of getting silently
        # skipped here.
        try:
            self._backend.preflight()
        except LLMBackendError as exc:
            raise AgentBackendError(
                f"CodexAgentBackend: backend preflight failed: {exc}",
            ) from exc

    def build_agent(
        self,
        *,
        system_prompt: str,
        tools: Sequence[Callable[..., Any]] = (),
    ) -> AgentSession:
        if tools:
            raise AgentBackendError(
                "CodexAgentBackend does not support tool injection. "
                "Use StrandsAgentBackend for NPCs that need tool dispatch.",
            )
        backend = self._backend

        def session(prompt: str) -> Any:
            return backend.complete(LLMRequest(prompt=prompt, system=system_prompt))

        return session
