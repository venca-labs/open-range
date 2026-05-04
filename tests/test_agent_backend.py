"""AgentBackend protocol + StrandsAgentBackend / CodexAgentBackend tests."""

from __future__ import annotations

from typing import Any

import pytest

from openrange.agent_backend import (
    AgentBackendError,
    CodexAgentBackend,
    StrandsAgentBackend,
)
from openrange.llm import LLMRequest, LLMResult

# ---------------------------------------------------------------------------
# StrandsAgentBackend
# ---------------------------------------------------------------------------


def test_strands_backend_preflight_raises_when_strands_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Without ``strands-agents``, preflight fails with a clear install hint."""
    import builtins

    real_import = builtins.__import__

    def fake_import(name: str, *args: object, **kwargs: object) -> Any:
        if name == "strands" or name.startswith("strands."):
            raise ImportError(f"No module named {name!r}")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)

    backend = StrandsAgentBackend()
    with pytest.raises(AgentBackendError, match="strands-agents"):
        backend.preflight()


def test_strands_backend_build_agent_raises_when_strands_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import builtins

    real_import = builtins.__import__

    def fake_import(name: str, *args: object, **kwargs: object) -> Any:
        if name == "strands" or name.startswith("strands."):
            raise ImportError(f"No module named {name!r}")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)

    backend = StrandsAgentBackend()
    with pytest.raises(AgentBackendError, match="strands-agents"):
        backend.build_agent(system_prompt="x", tools=())


def test_strands_backend_preflight_passes_when_strands_installed() -> None:
    """When strands IS importable, preflight is a no-op."""
    pytest.importorskip("strands")
    StrandsAgentBackend().preflight()


def test_strands_backend_builds_agent_when_installed() -> None:
    """End-to-end: construct a real strands.Agent (no API call)."""
    pytest.importorskip("strands")
    backend = StrandsAgentBackend()

    def my_tool(x: str) -> str:
        """Echo the input.

        Args:
            x: Anything.
        """
        return x

    agent = backend.build_agent(system_prompt="be terse", tools=[my_tool])
    # The returned object is callable (strands.Agent.__call__).
    assert callable(agent)


# ---------------------------------------------------------------------------
# CodexAgentBackend
# ---------------------------------------------------------------------------


class _FakeLLMBackend:
    """Test double for :class:`openrange.llm.LLMBackend`."""

    def __init__(self) -> None:
        self.requests: list[LLMRequest] = []
        self.canned = LLMResult("ok")
        self.preflight_calls = 0

    def complete(self, request: LLMRequest) -> LLMResult:
        self.requests.append(request)
        return self.canned

    def preflight(self) -> None:
        # Default protocol no-op; tests that want a failure raise from
        # a one-off override (see ``test_codex_backend_preflight_*``).
        self.preflight_calls += 1


def test_codex_backend_rejects_tools() -> None:
    """CodexAgentBackend errors loudly if handed any tools."""
    backend = CodexAgentBackend(backend=_FakeLLMBackend())

    def some_tool() -> None:
        return None

    with pytest.raises(AgentBackendError, match="does not support tool injection"):
        backend.build_agent(system_prompt="x", tools=[some_tool])


def test_codex_backend_drives_llm_for_tool_less_prompts() -> None:
    """Without tools, build_agent returns a callable that hits the LLM backend."""
    fake = _FakeLLMBackend()
    backend = CodexAgentBackend(backend=fake)
    session = backend.build_agent(system_prompt="be terse", tools=())
    result = session("hello")
    assert isinstance(result, LLMResult)
    assert result.text == "ok"
    assert len(fake.requests) == 1
    assert fake.requests[0].prompt == "hello"
    assert fake.requests[0].system == "be terse"


def test_codex_backend_rejects_both_backend_and_model_args() -> None:
    with pytest.raises(AgentBackendError, match="not both"):
        CodexAgentBackend(backend=_FakeLLMBackend(), model="some-model")


def test_codex_backend_preflight_delegates_to_custom_llm_backend() -> None:
    """A caller-supplied LLMBackend gets its own preflight called."""
    fake = _FakeLLMBackend()
    backend = CodexAgentBackend(backend=fake)
    backend.preflight()
    assert fake.preflight_calls == 1


def test_codex_backend_preflight_surfaces_custom_llm_backend_failures() -> None:
    """A failing custom backend preflight raises AgentBackendError."""
    from openrange.llm import LLMBackendError

    class _BadBackend(_FakeLLMBackend):
        def preflight(self) -> None:
            raise LLMBackendError("custom probe failed")

    backend = CodexAgentBackend(backend=_BadBackend())
    with pytest.raises(AgentBackendError, match="custom probe failed"):
        backend.preflight()


def test_codex_backend_preflight_errors_if_codex_cli_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Default CodexBackend → preflight checks PATH for the codex binary."""
    import shutil as _shutil

    monkeypatch.setattr(_shutil, "which", lambda _cmd: None)
    backend = CodexAgentBackend()  # constructs default CodexBackend internally
    with pytest.raises(AgentBackendError, match="codex CLI not found"):
        backend.preflight()
