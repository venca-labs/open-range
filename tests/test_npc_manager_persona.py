"""Tests for NPCManager and default_personas."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest

from open_range.builder.npc.npc_manager import NPCManager
from open_range.builder.npc.persona import default_personas
from open_range.world_ir import GreenPersona


# ---------------------------------------------------------------------------
# default_personas
# ---------------------------------------------------------------------------


class TestDefaultPersonas:
    def test_returns_five_personas(self):
        assert len(default_personas()) == 5

    def test_all_are_green_persona_instances(self):
        assert all(isinstance(p, GreenPersona) for p in default_personas())

    def test_ids_are_unique(self):
        ids = [p.id for p in default_personas()]
        assert len(ids) == len(set(ids))

    def test_awareness_range(self):
        for p in default_personas():
            assert 0.0 <= p.awareness <= 1.0

    def test_susceptibility_keys_present(self):
        for p in default_personas():
            assert "phishing_email" in p.susceptibility
            assert "social_engineering" in p.susceptibility

    def test_each_has_non_empty_routine(self):
        for p in default_personas():
            assert len(p.routine) >= 1

    def test_mailboxes_are_corp_local(self):
        for p in default_personas():
            assert p.mailbox.endswith("@corp.local")

    def test_returns_fresh_list_each_call(self):
        a = default_personas()
        b = default_personas()
        assert a is not b


# ---------------------------------------------------------------------------
# NPCManager — mock mode
# ---------------------------------------------------------------------------


def _snapshot_with(personas=None):
    return SimpleNamespace(
        npc_personas=personas,
        npc_traffic=SimpleNamespace(action_interval_min=2),
        topology={"hosts": [], "users": [], "domain": "corp.local"},
        files={},
    )


class TestNPCManagerMockMode:
    def test_initial_state_not_running(self):
        mgr = NPCManager(mock_mode=True)
        assert not mgr.running

    def test_start_sets_running(self):
        async def _go():
            mgr = NPCManager(mock_mode=True)
            await mgr.start(_snapshot_with())
            assert mgr.running
            await mgr.stop()

        asyncio.run(_go())

    def test_stop_clears_running(self):
        async def _go():
            mgr = NPCManager(mock_mode=True)
            await mgr.start(_snapshot_with())
            await mgr.stop()
            assert not mgr.running

        asyncio.run(_go())

    def test_spawns_one_task_per_persona(self):
        async def _go():
            personas = default_personas()
            mgr = NPCManager(mock_mode=True)
            await mgr.start(_snapshot_with(personas=personas))
            count = len(mgr._tasks)
            await mgr.stop()
            return count

        count = asyncio.run(_go())
        assert count == 5

    def test_uses_default_personas_when_snapshot_has_none(self):
        async def _go():
            snap = _snapshot_with(personas=None)
            # npc_personas is None — should fall back to default_personas()
            mgr = NPCManager(mock_mode=True)
            await mgr.start(snap)
            count = len(mgr._tasks)
            await mgr.stop()
            return count

        assert asyncio.run(_go()) == 5

    def test_stop_cancels_all_tasks(self):
        async def _go():
            mgr = NPCManager(mock_mode=True)
            await mgr.start(_snapshot_with())
            await mgr.stop()
            assert all(t.done() for t in mgr._tasks)

        asyncio.run(_go())

    def test_tasks_list_cleared_after_stop(self):
        async def _go():
            mgr = NPCManager(mock_mode=True)
            await mgr.start(_snapshot_with())
            await mgr.stop()
            return mgr._tasks

        assert asyncio.run(_go()) == []

    def test_double_stop_is_safe(self):
        async def _go():
            mgr = NPCManager(mock_mode=True)
            await mgr.start(_snapshot_with())
            await mgr.stop()
            await mgr.stop()  # second stop should not raise

        asyncio.run(_go())

    def test_custom_persona_list_used(self):
        async def _go():
            custom = default_personas()[:2]
            mgr = NPCManager(mock_mode=True)
            await mgr.start(_snapshot_with(personas=custom))
            count = len(mgr._tasks)
            await mgr.stop()
            return count

        assert asyncio.run(_go()) == 2

    def test_empty_persona_list_falls_back_to_defaults(self):
        """An empty list is falsy — falls back to default_personas() (4 tasks)."""
        async def _go():
            mgr = NPCManager(mock_mode=True)
            await mgr.start(_snapshot_with(personas=[]))
            count = len(mgr._tasks)
            await mgr.stop()
            return count

        assert asyncio.run(_go()) == 5


# ---------------------------------------------------------------------------
# NPCManager — live mode (LLMNPCAgent patched)
# ---------------------------------------------------------------------------


class TestNPCManagerLiveMode:
    def test_live_mode_spawns_llm_agents(self):
        """In live mode, LLMNPCAgent.run_loop is called per persona."""

        async def _go():
            personas = default_personas()[:2]
            snap = _snapshot_with(personas=personas)
            containers = AsyncMock()

            # Patch run_loop to return immediately so the task completes
            async def _noop(*args, **kwargs):
                pass

            with patch(
                "open_range.builder.npc.npc_manager.LLMNPCAgent.run_loop",
                new=_noop,
            ):
                mgr = NPCManager(mock_mode=False)
                await mgr.start(snap, containers=containers)
                assert mgr.running
                assert len(mgr._tasks) == 2
                await mgr.stop()

        asyncio.run(_go())
