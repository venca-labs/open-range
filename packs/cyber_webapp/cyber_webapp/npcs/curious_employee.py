"""``cyber.curious_employee`` — LLM-backed agent NPC.

Reference implementation of the agent-NPC shape: a persona, a tool
surface bound over the HTTP backing's ``interface``, and an
:class:`~openrange.agent_backend.AgentBackend` driving the
loop. Default backend is strands (set centrally via
``RunConfig.npc_agent_backend``); per-NPC ``model`` config still
works as a convenience for picking a strands model id without
constructing a backend by hand.

Roughly: an internal employee poking around the company webapp out
of boredom — a few GETs per turn, no destructive intent.

If the configured backend can't run (e.g. ``strands-agents`` not
installed) the NPC marks itself permanently broken at episode
start, logs a single WARNING to ``openrange.npc`` with the
import error, and the rest of the episode runs without it. See
:class:`AgentNPC` for the full failure model.

Config:
    cadence_ticks: int = 5         — invoke the agent every Nth tick
    model: str | None = None       — convenience override: builds a
                                     ``StrandsAgentBackend(model=...)``
                                     for this NPC (overrides the
                                     runtime-supplied backend). For
                                     non-strands backends, leave this
                                     unset and configure
                                     ``RunConfig.npc_agent_backend``
                                     instead.
    system_prompt: str | None      — override the default persona
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from typing import Any, cast

from openrange.agent_backend import StrandsAgentBackend
from openrange.npc import NPC, AgentNPC

_DEFAULT_SYSTEM_PROMPT = (
    "You are an internal employee at a small company, casually browsing "
    "the company's intranet webapp out of curiosity during a slow "
    "afternoon. On each turn pick one or two pages that sound interesting "
    "and visit them with the visit_url tool. Keep the request paths short "
    "and plausible (e.g. /, /search?q=alpha, /openapi.json). Don't try to "
    "break anything — you're a normal user, not an attacker. Respond with "
    "one short sentence describing what you looked at."
)


class CuriousEmployee(AgentNPC):
    def _build_tools(
        self,
        interface: Mapping[str, Any],
    ) -> Sequence[Callable[..., Any]]:
        from strands import tool

        http_get = interface.get("http_get")
        if http_get is None:
            return ()

        @tool
        def visit_url(path: str) -> str:
            """Visit a path on the company webapp and return a short snippet.

            Args:
                path: URL path on the webapp (e.g. ``/`` or
                    ``/search?q=alpha``). Must start with ``/``.
            """
            try:
                body = cast(Any, http_get)(path)
            except Exception as exc:  # noqa: BLE001 — surface to the LLM
                return f"request failed: {exc}"
            if isinstance(body, bytes):
                text = body.decode(errors="replace")
            else:
                text = str(body)
            return text[:1500]

        return [visit_url]


def factory(config: Mapping[str, object]) -> NPC:
    cadence_raw = config.get("cadence_ticks", 5)
    model_raw = config.get("model")
    prompt_raw = config.get("system_prompt", _DEFAULT_SYSTEM_PROMPT)
    if not isinstance(cadence_raw, int):
        raise ValueError("cadence_ticks must be an int")
    if model_raw is not None and not isinstance(model_raw, str):
        raise ValueError("model must be a string or unset")
    if not isinstance(prompt_raw, str) or not prompt_raw:
        raise ValueError("system_prompt must be a non-empty string")
    backend = StrandsAgentBackend(model=model_raw) if model_raw is not None else None
    return CuriousEmployee(
        system_prompt=prompt_raw,
        cadence_ticks=cadence_raw,
        agent_backend=backend,
    )
