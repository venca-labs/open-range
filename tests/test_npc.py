"""Core NPC contract + registry tests."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import pytest

from openrange.core.npc import (
    NPC,
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
