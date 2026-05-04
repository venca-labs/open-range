"""Core NPC contract + registry tests."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from typing import Any

import pytest

from openrange.core.npc import (
    NPC,
    AgentNPC,
    NPCError,
    NPCRegistry,
    resolve_manifest_npcs,
)


class _RecordingNPC(NPC):
    """Test double: records every step + lifecycle call."""

    def __init__(self, label: str = "rec") -> None:
        self.label = label
        self.started_with: Mapping[str, Any] | None = None
        self.steps: list[Mapping[str, Any]] = []
        self.stopped: bool = False

    def start(self, context: Mapping[str, Any]) -> None:
        self.started_with = dict(context)

    def step(self, interface: Mapping[str, Any]) -> None:
        self.steps.append(dict(interface))

    def stop(self) -> None:
        self.stopped = True


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------


def test_registry_resolves_registered_factory() -> None:
    reg = NPCRegistry()
    reg.register("test.rec", lambda config: _RecordingNPC(str(config.get("label", ""))))
    npc = reg.resolve("test.rec", {"label": "alpha"})
    assert isinstance(npc, _RecordingNPC)
    assert npc.label == "alpha"


def test_registry_unknown_npc_raises() -> None:
    reg = NPCRegistry()
    with pytest.raises(NPCError, match="unknown NPC"):
        reg.resolve("does.not.exist", {})


def test_registry_factory_returning_non_npc_raises() -> None:
    reg = NPCRegistry()
    reg.register("bad.factory", lambda config: "not an npc")  # type: ignore[arg-type,return-value]
    with pytest.raises(NPCError, match="did not return an NPC"):
        reg.resolve("bad.factory", {})


def test_registry_default_does_not_autodiscover() -> None:
    """Test instances start empty so tests get a clean slate."""
    reg = NPCRegistry()
    assert reg.ids() == ()


def test_registry_global_autodiscovers_cyber_npcs() -> None:
    """The autodiscover global picks up the entry-point-registered cyber NPCs."""
    from openrange.core.npc import NPCS

    ids = NPCS.ids()
    assert "cyber.browsing_user" in ids
    assert "cyber.admin_audit" in ids


# ---------------------------------------------------------------------------
# Manifest resolution
# ---------------------------------------------------------------------------


def test_resolve_manifest_npcs_spawns_count_instances() -> None:
    reg = NPCRegistry()
    reg.register("test.rec", lambda config: _RecordingNPC())
    npcs = resolve_manifest_npcs(
        ({"type": "test.rec", "count": 3},),
        registry=reg,
    )
    assert len(npcs) == 3
    assert all(isinstance(npc, _RecordingNPC) for npc in npcs)


def test_resolve_manifest_npcs_default_count_is_one() -> None:
    reg = NPCRegistry()
    reg.register("test.rec", lambda config: _RecordingNPC())
    npcs = resolve_manifest_npcs(
        ({"type": "test.rec"},),
        registry=reg,
    )
    assert len(npcs) == 1


def test_resolve_manifest_npcs_passes_config() -> None:
    reg = NPCRegistry()
    captured: dict[str, object] = {}

    def factory(config: Mapping[str, object]) -> NPC:
        captured.update(config)
        return _RecordingNPC()

    reg.register("test.rec", factory)
    resolve_manifest_npcs(
        ({"type": "test.rec", "config": {"foo": "bar", "n": 7}},),
        registry=reg,
    )
    assert captured == {"foo": "bar", "n": 7}


def test_resolve_manifest_npcs_zero_count_skips() -> None:
    reg = NPCRegistry()
    reg.register("test.rec", lambda config: _RecordingNPC())
    npcs = resolve_manifest_npcs(
        ({"type": "test.rec", "count": 0},),
        registry=reg,
    )
    assert npcs == []


def test_resolve_manifest_npcs_rejects_missing_type() -> None:
    reg = NPCRegistry()
    with pytest.raises(NPCError, match="non-empty 'type'"):
        resolve_manifest_npcs(({"count": 1},), registry=reg)


def test_resolve_manifest_npcs_rejects_negative_count() -> None:
    reg = NPCRegistry()
    reg.register("test.rec", lambda config: _RecordingNPC())
    with pytest.raises(NPCError, match="non-negative"):
        resolve_manifest_npcs(
            ({"type": "test.rec", "count": -1},),
            registry=reg,
        )


def test_resolve_manifest_npcs_rejects_non_mapping_config() -> None:
    reg = NPCRegistry()
    reg.register("test.rec", lambda config: _RecordingNPC())
    with pytest.raises(NPCError, match="must be a mapping"):
        resolve_manifest_npcs(
            ({"type": "test.rec", "config": "not-a-map"},),
            registry=reg,
        )


# ---------------------------------------------------------------------------
# ABC defaults
# ---------------------------------------------------------------------------


def test_default_lifecycle_hooks_are_noops() -> None:
    """Subclasses that override only ``step`` can rely on default start/stop."""

    class MinimalNPC(NPC):
        def __init__(self) -> None:
            self.steps = 0

        def step(self, interface: Mapping[str, Any]) -> None:
            self.steps += 1

    npc = MinimalNPC()
    npc.start({"episode_id": "x"})  # default: no-op
    npc.step({})
    npc.stop()  # default: no-op
    assert npc.steps == 1


def test_npc_requires_llm_defaults_false() -> None:
    """Plain NPC subclasses do not opt into LLM injection."""

    class Plain(NPC):
        def step(self, interface: Mapping[str, Any]) -> None: ...

    assert Plain.requires_llm is False
    assert Plain().requires_llm is False


# ---------------------------------------------------------------------------
# AgentNPC
# ---------------------------------------------------------------------------


class _FakeAgent:
    """Records every ``__call__`` it receives (no LLM)."""

    def __init__(self) -> None:
        self.calls: list[str] = []

    def __call__(self, prompt: str) -> object:
        self.calls.append(prompt)
        return {"message": "ok"}


class _StubAgentNPC(AgentNPC):
    """Test double: counts ``_build_agent`` invocations and uses _FakeAgent."""

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.fake = _FakeAgent()
        self.build_count = 0
        self.tool_calls: list[Mapping[str, Any]] = []

    def _build_tools(
        self,
        interface: Mapping[str, Any],
    ) -> Sequence[Callable[..., Any]]:
        self.tool_calls.append(dict(interface))

        def visit(path: str) -> str:
            return path

        return [visit]

    def _build_agent(self, tools: Sequence[Callable[..., Any]]) -> Any:
        self.build_count += 1
        return self.fake


def test_agent_npc_requires_llm_is_true_by_default() -> None:
    assert AgentNPC.requires_llm is True


def test_agent_npc_rejects_invalid_construction() -> None:
    with pytest.raises(ValueError, match="system_prompt"):
        _StubAgentNPC(system_prompt="")
    with pytest.raises(ValueError, match="cadence_ticks"):
        _StubAgentNPC(system_prompt="x", cadence_ticks=0)


def test_agent_npc_acts_on_first_step_then_obeys_cadence() -> None:
    npc = _StubAgentNPC(system_prompt="be curious", cadence_ticks=3)
    iface: dict[str, Any] = {"base_url": "http://x"}

    npc.step(iface)
    assert npc.fake.calls == [npc._user_prompt(iface)]
    assert npc.build_count == 1

    npc.step(iface)
    npc.step(iface)
    assert len(npc.fake.calls) == 1  # cooldown

    npc.step(iface)
    assert len(npc.fake.calls) == 2
    assert npc.build_count == 1  # agent built once, reused


def test_agent_npc_captures_runtime_model_from_context() -> None:
    npc = _StubAgentNPC(system_prompt="x", cadence_ticks=1)
    npc.start({"episode_id": "e", "llm": "claude-sonnet-4-20250514"})
    assert npc._runtime_model == "claude-sonnet-4-20250514"


def test_agent_npc_constructor_model_overrides_runtime() -> None:
    npc = _StubAgentNPC(
        system_prompt="x",
        cadence_ticks=1,
        model="explicit-model",
    )
    npc.start({"episode_id": "e", "llm": "runtime-model"})
    assert npc._model_override == "explicit-model"
    # _build_agent receives the override; we exercise via the seam.

    captured: dict[str, Any] = {}

    class _CaptureNPC(_StubAgentNPC):
        def _build_agent(
            self,
            tools: Sequence[Callable[..., Any]],
        ) -> Any:
            captured["model"] = self._model_override or self._runtime_model
            return self.fake

    over = _CaptureNPC(
        system_prompt="x",
        cadence_ticks=1,
        model="explicit-model",
    )
    over.start({"episode_id": "e", "llm": "runtime-model"})
    over.step({})
    assert captured["model"] == "explicit-model"


def test_agent_npc_handles_none_runtime_model() -> None:
    """No model configured at runtime → start() captures None gracefully."""
    npc = _StubAgentNPC(system_prompt="x", cadence_ticks=1)
    npc.start({"episode_id": "e", "llm": None})
    assert npc._runtime_model is None


def test_agent_npc_marks_broken_on_build_failure() -> None:
    """If _build_agent raises (e.g. strands missing), NPC stays silent."""

    class _BrokenNPC(_StubAgentNPC):
        def _build_agent(
            self,
            tools: Sequence[Callable[..., Any]],
        ) -> Any:
            raise NPCError("strands not installed")

    npc = _BrokenNPC(system_prompt="x", cadence_ticks=1)
    npc.step({})  # tries to build, fails, marks broken
    assert npc._broken is True
    npc.step({})  # would normally build again — but broken short-circuits
    npc.step({})
    assert npc.fake.calls == []


def test_agent_npc_swallows_invocation_errors() -> None:
    """A throwing agent does not sink the episode."""

    class _ThrowingAgent(_FakeAgent):
        def __call__(self, prompt: str) -> object:
            raise RuntimeError("model went poof")

    class _ThrowingNPC(_StubAgentNPC):
        def _build_agent(
            self,
            tools: Sequence[Callable[..., Any]],
        ) -> Any:
            return _ThrowingAgent()

    npc = _ThrowingNPC(system_prompt="x", cadence_ticks=1)
    # Must not raise.
    npc.step({})
    npc.step({})


def test_agent_npc_stop_clears_agent_reference() -> None:
    npc = _StubAgentNPC(system_prompt="x", cadence_ticks=1)
    npc.step({})
    assert npc._agent is not None
    npc.stop()
    assert npc._agent is None


def test_agent_npc_real_build_path_raises_when_strands_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The default ``_build_agent`` surfaces a clear error if strands is absent."""
    import builtins

    real_import = builtins.__import__

    def fake_import(name: str, *args: object, **kwargs: object) -> Any:
        if name == "strands" or name.startswith("strands."):
            raise ImportError(f"No module named {name!r}")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)

    class _RealishAgentNPC(AgentNPC):
        def _build_tools(
            self,
            interface: Mapping[str, Any],
        ) -> Sequence[Callable[..., Any]]:
            return ()

    npc = _RealishAgentNPC(system_prompt="x")
    with pytest.raises(NPCError, match="strands-agents"):
        npc._build_agent(())
