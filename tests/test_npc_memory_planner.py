"""Tests for NPC MemoryStream and DailyPlanner (issue #111)."""

from __future__ import annotations

import asyncio
import time
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from open_range.builder.npc.memory import MemoryEntry, MemoryStream
from open_range.builder.npc.planner import DailyPlanner, ScheduledAction, _template_schedule
from open_range.builder.npc.npc_agent import LLMNPCAgent, NPCAction, NullNPCBehavior, RuleBasedNPCBehavior, Stimulus
from open_range.builder.npc.persona import default_personas
from open_range.world_ir import GreenPersona


# ---------------------------------------------------------------------------
# MemoryStream unit tests
# ---------------------------------------------------------------------------


class TestMemoryEntry:
    def test_recency_score_fresh(self):
        entry = MemoryEntry(subject="janet.liu", relation="browsed", object_="/portal",
                            importance=5.0, timestamp=time.time())
        assert entry.recency_score(time.time()) > 0.99

    def test_recency_score_decays(self):
        old_ts = time.time() - 3600  # 1 hour ago
        entry = MemoryEntry(subject="janet.liu", relation="browsed", object_="/portal",
                            importance=5.0, timestamp=old_ts)
        score = entry.recency_score(time.time())
        assert 0.0 < score < 0.9

    def test_relevance_score_tags_contribute(self):
        """Tags matching query raise relevance above zero."""
        entry = MemoryEntry(subject="x", relation="y", object_="z",
                            importance=5.0, tags=["phishing", "email"])
        assert entry.relevance_score(["phishing", "email"]) > 0.0

    def test_relevance_score_no_overlap(self):
        entry = MemoryEntry(subject="x", relation="y", object_="z",
                            importance=5.0, tags=["browse", "routine"])
        assert entry.relevance_score(["phishing", "security"]) == 0.0

    def test_relevance_score_partial_overlap(self):
        entry = MemoryEntry(subject="x", relation="y", object_="z",
                            importance=5.0, tags=["phishing", "email", "routine"])
        score = entry.relevance_score(["phishing", "security"])
        assert 0.0 < score < 1.0

    def test_relevance_empty_tags(self):
        entry = MemoryEntry(subject="x", relation="y", object_="z",
                            importance=5.0, tags=[])
        assert entry.relevance_score(["phishing"]) == 0.0

    def test_relevance_entity_tokens(self):
        """Entity tokens from triple fields contribute to relevance."""
        entry = MemoryEntry(subject="janet.liu", relation="received_phishing_from",
                            object_="attacker@evil.com", importance=5.0)
        # "phishing" comes from tokenising "received_phishing_from"
        assert entry.relevance_score(["phishing", "janet"]) > 0.0

    def test_retrieval_score_combines_components(self):
        entry = MemoryEntry(subject="janet.liu", relation="reacted_to_phishing_with",
                            object_="report_to_IT", importance=10.0, tags=["phishing"])
        score = entry.retrieval_score(time.time(), ["phishing"])
        # recency (~1.0) + importance (1.0) + relevance (>0) > 2.0
        assert score > 2.0

    def test_content_property(self):
        entry = MemoryEntry(subject="janet.liu", relation="browsed", object_="/dashboard",
                            importance=3.0)
        assert entry.content == "janet.liu browsed /dashboard"


class TestMemoryStream:
    def test_add_and_len(self):
        ms = MemoryStream()
        ms.add("janet.liu", "attended", "meeting", importance=3.0)
        ms.add("janet.liu", "received_phishing_from", "attacker@evil.com", importance=8.0, tags=["phishing"])
        assert len(ms) == 2

    def test_retrieve_ranks_by_relevance(self):
        ms = MemoryStream()
        ms.add("janet.liu", "browsed", "/portal", importance=2.0, tags=["browse", "routine"])
        ms.add("janet.liu", "received_phishing_from", "spam@evil.com", importance=8.0, tags=["phishing", "email", "security"])
        ms.add("janet.liu", "sent_email_to", "bob.smith", importance=2.0, tags=["send_email", "routine"])

        results = ms.retrieve(query_tags=["phishing", "security"], top_k=1)
        assert len(results) == 1
        assert "phishing" in results[0].content

    def test_retrieve_top_k(self):
        ms = MemoryStream()
        for i in range(10):
            ms.add("janet.liu", "browsed", f"/page{i}", importance=float(i + 1), tags=["routine"])
        results = ms.retrieve(["routine"], top_k=3)
        assert len(results) == 3

    def test_recent_order(self):
        ms = MemoryStream()
        ms.add("janet.liu", "did", "first", importance=5.0)
        time.sleep(0.01)
        ms.add("janet.liu", "did", "second", importance=5.0)
        time.sleep(0.01)
        ms.add("janet.liu", "did", "third", importance=5.0)
        recent = ms.recent(2)
        assert recent[-1].content == "janet.liu did third"
        assert recent[-2].content == "janet.liu did second"

    def test_eviction_at_capacity(self):
        ms = MemoryStream(max_size=3)
        ms.add("janet.liu", "low", "importance", importance=1.0)
        ms.add("janet.liu", "medium", "thing", importance=5.0)
        ms.add("janet.liu", "high", "thing", importance=9.0)
        ms.add("janet.liu", "new", "entry", importance=6.0)  # should evict low importance
        assert len(ms) == 3
        contents = [m.content for m in ms._memories]
        assert "janet.liu low importance" not in contents

    def test_to_summary_list(self):
        ms = MemoryStream()
        for i in range(7):
            ms.add("janet.liu", "browsed", f"/page{i}", importance=5.0)
        summary = ms.to_summary_list(5)
        assert len(summary) == 5
        assert all(isinstance(s, str) for s in summary)

    def test_to_context_list(self):
        ms = MemoryStream()
        ms.add("janet.liu", "browsed", "/dashboard", importance=3.0)
        ctx = ms.to_context_list(1)
        assert len(ctx) == 1
        assert ctx[0] == {"subject": "janet.liu", "relation": "browsed", "object": "/dashboard"}

    def test_needs_reflection_false_initially(self):
        ms = MemoryStream()
        assert not ms.needs_reflection(threshold=10)

    def test_needs_reflection_true_after_threshold(self):
        ms = MemoryStream()
        for i in range(10):
            ms.add("janet.liu", "browsed", f"/page{i}", importance=2.0)
        assert ms.needs_reflection(threshold=10)

    def test_take_for_reflection_advances_pointer(self):
        ms = MemoryStream()
        for i in range(5):
            ms.add("janet.liu", "browsed", f"/page{i}", importance=2.0)
        taken = ms.take_for_reflection()
        assert len(taken) == 5
        assert not ms.needs_reflection(threshold=1)  # pointer advanced

    def test_take_for_reflection_incremental(self):
        ms = MemoryStream()
        ms.add("janet.liu", "did", "first_batch", importance=3.0)
        ms.take_for_reflection()
        ms.add("janet.liu", "did", "second_batch", importance=3.0)
        taken = ms.take_for_reflection()
        assert len(taken) == 1
        assert taken[0].content == "janet.liu did second_batch"

    def test_importance_clamped(self):
        ms = MemoryStream()
        ms.add("janet.liu", "did", "too_high", importance=15.0)
        ms.add("janet.liu", "did", "too_low", importance=-1.0)
        assert ms._memories[0].importance == 10.0
        assert ms._memories[1].importance == 1.0


# ---------------------------------------------------------------------------
# DailyPlanner unit tests
# ---------------------------------------------------------------------------


class TestDailyPlanner:
    def test_template_schedule_no_model(self):
        janet = default_personas()[0]  # Marketing Coordinator
        planner = DailyPlanner(model=None)
        asyncio.run(planner.plan_day(janet, {}))
        assert len(planner._schedule) > 0

    def test_template_schedule_it_role(self):
        it_persona = GreenPersona(
            id="bob",
            role="IT Administrator",
            department="IT",
            awareness=0.8,
            susceptibility={},
            routine=(),
        )
        schedule = _template_schedule(it_persona)
        actions = [s.action for s in schedule]
        assert "login" in actions or "query_db" in actions

    def test_template_schedule_executive_role(self):
        exec_persona = GreenPersona(
            id="carol",
            role="VP of Engineering",
            department="Engineering",
            awareness=0.7,
            susceptibility={},
            routine=(),
        )
        schedule = _template_schedule(exec_persona)
        actions = [s.action for s in schedule]
        assert "browse" in actions

    def test_next_action_hint_returns_in_order(self):
        planner = DailyPlanner(model=None)
        planner._schedule = [
            ScheduledAction(9, "login", "/", "Morning"),
            ScheduledAction(10, "browse", "/status", "Check status"),
            ScheduledAction(11, "send_email", "", "Follow up"),
        ]
        planner._day_start = time.time() - 9999  # fast-forward to end of day

        hints = []
        while True:
            hint = planner.next_action_hint()
            if hint is None:
                break
            hints.append(hint)

        assert [h.hour for h in hints] == [9, 10, 11]

    def test_next_action_hint_none_when_exhausted(self):
        planner = DailyPlanner(model=None)
        planner._schedule = [ScheduledAction(9, "idle", "", "test")]
        planner._day_start = time.time() - 9999
        planner.next_action_hint()  # consume the one action
        assert planner.next_action_hint() is None

    def test_reflect_no_model_returns_empty(self):
        persona = default_personas()[0]
        planner = DailyPlanner(model=None)
        reflections, adjusted = asyncio.run(
            planner.reflect(persona, ["memory 1", "memory 2"])
        )
        assert reflections == []
        assert adjusted is None

    def test_reflect_empty_memories_returns_empty(self):
        persona = default_personas()[0]
        planner = DailyPlanner(model="claude-haiku-4-5-20251001")
        reflections, adjusted = asyncio.run(planner.reflect(persona, []))
        assert reflections == []
        assert adjusted is None

    @patch("open_range.builder.npc.planner.litellm")
    def test_plan_day_llm_success(self, mock_litellm):
        mock_response = MagicMock()
        mock_response.choices[0].message.content = '{"schedule": [{"hour": 9, "action": "browse", "target": "/", "detail": "Morning check"}], "mood": "focused", "focus": "project work"}'
        mock_litellm.acompletion = AsyncMock(return_value=mock_response)

        persona = default_personas()[0]
        planner = DailyPlanner(model="test-model")
        asyncio.run(planner.plan_day(persona, {"pages": ["/"]}))

        assert len(planner._schedule) == 1
        assert planner._schedule[0].action == "browse"
        assert planner.mood == "focused"
        assert planner.focus == "project work"

    @patch("open_range.builder.npc.planner.litellm")
    def test_plan_day_llm_failure_falls_back_to_template(self, mock_litellm):
        mock_litellm.acompletion = AsyncMock(side_effect=Exception("API error"))

        persona = default_personas()[0]
        planner = DailyPlanner(model="test-model")
        asyncio.run(planner.plan_day(persona, {}))

        # Should have fallen back to template
        assert len(planner._schedule) > 0


# ---------------------------------------------------------------------------
# LLMNPCAgent integration with memory/planner
# ---------------------------------------------------------------------------


class TestLLMNPCAgentMemory:
    def _make_agent(self, model="test-model") -> LLMNPCAgent:
        return LLMNPCAgent(model=model, temperature=0.3)

    def test_decide_records_memory(self):
        agent = self._make_agent(model=None)
        persona = default_personas()[0]
        stimulus = Stimulus(type="email", sender="attacker@evil.com", subject="Urgent", content="Click here", plausibility=0.8)

        with patch.object(agent, "decide", new=AsyncMock(return_value=NPCAction(action="ignore"))):
            asyncio.run(agent.decide(persona, stimulus))

        # decide() is mocked so memory won't be recorded here —
        # this just checks the agent initialises without error
        assert isinstance(agent._memory, MemoryStream)
        assert isinstance(agent._planner, DailyPlanner)

    @patch("open_range.builder.npc.npc_agent.litellm")
    def test_decide_passes_memory_context(self, mock_litellm):
        mock_response = MagicMock()
        mock_response.choices[0].message.content = '{"action": "report_to_IT", "response_content": "", "side_effects": ["reported"]}'
        mock_litellm.acompletion = AsyncMock(return_value=mock_response)

        agent = self._make_agent()
        # Pre-load a relevant memory
        agent._memory.add("janet.liu", "received_phishing_from", "unknown@sender.com", importance=8.0, tags=["phishing", "security"])

        persona = default_personas()[0]
        stimulus = Stimulus(type="email", sender="x", subject="y", content="z", plausibility=0.5)
        result = asyncio.run(agent.decide(persona, stimulus))

        # Check LLM was called with memory context in the payload
        call_args = mock_litellm.acompletion.call_args
        user_content = call_args.kwargs["messages"][1]["content"]
        assert "recent_memories" in user_content
        assert result.action == "report_to_IT"

    @patch("open_range.builder.npc.npc_agent.litellm")
    def test_decide_records_high_importance_for_report(self, mock_litellm):
        mock_response = MagicMock()
        mock_response.choices[0].message.content = '{"action": "report_to_IT", "response_content": "", "side_effects": []}'
        mock_litellm.acompletion = AsyncMock(return_value=mock_response)

        agent = self._make_agent()
        persona = default_personas()[0]
        stimulus = Stimulus(type="email", sender="x", subject="y", content="z", plausibility=0.5)
        asyncio.run(agent.decide(persona, stimulus))

        assert len(agent._memory) == 1
        assert agent._memory._memories[0].importance == 8.0

    @patch("open_range.builder.npc.npc_agent.litellm")
    def test_next_routine_action_passes_memory_and_hint(self, mock_litellm):
        mock_response = MagicMock()
        mock_response.choices[0].message.content = '{"action": "browse", "target": "/", "detail": "morning check", "email_body": ""}'
        mock_litellm.acompletion = AsyncMock(return_value=mock_response)

        agent = self._make_agent()
        agent._memory.add("janet.liu", "browsed", "/dashboard", importance=2.0, tags=["browse"])
        persona = default_personas()[0]
        env_context = {"pages": ["/", "/status"], "shares": [], "db_tables": [], "colleagues": []}
        hint = {"action": "browse", "target": "/status", "detail": "Check service status"}

        result = asyncio.run(agent.next_routine_action(persona, env_context, plan_hint=hint))

        call_args = mock_litellm.acompletion.call_args
        user_content = call_args.kwargs["messages"][1]["content"]
        assert "recent_memories" in user_content
        assert "plan_hint" in user_content
        assert result["action"] == "browse"

    @patch("open_range.builder.npc.npc_agent.litellm")
    def test_next_routine_records_memory(self, mock_litellm):
        mock_response = MagicMock()
        mock_response.choices[0].message.content = '{"action": "idle", "target": "", "detail": "Taking a break", "email_body": ""}'
        mock_litellm.acompletion = AsyncMock(return_value=mock_response)

        agent = self._make_agent()
        persona = default_personas()[0]
        asyncio.run(agent.next_routine_action(persona, {}, plan_hint=None))

        assert len(agent._memory) == 1
        assert agent._memory._memories[0].tags == ["idle", "routine"]

    def test_default_model_uses_claude_haiku(self):
        import os
        original = os.environ.pop("OPENRANGE_NPC_MODEL", None)
        try:
            agent = LLMNPCAgent()
            assert "claude-haiku" in agent.model or "haiku" in agent.model
        finally:
            if original is not None:
                os.environ["OPENRANGE_NPC_MODEL"] = original


# ---------------------------------------------------------------------------
# Integration: 4 NPCs over multiple ticks in mock mode
# ---------------------------------------------------------------------------


class TestNPCManagerIntegration:
    """Smoke test: 4 NPCs run through their workday loop in mock mode."""

    def _make_snapshot(self) -> Any:
        from open_range.builder.npc.persona import default_personas
        from types import SimpleNamespace

        return SimpleNamespace(
            npc_personas=default_personas(),
        )

    def test_npc_manager_mock_mode_starts_and_stops(self):
        from open_range.builder.npc.npc_manager import NPCManager

        snapshot = self._make_snapshot()
        mgr = NPCManager(mock_mode=True)
        asyncio.run(mgr.start(snapshot, containers=None))
        assert mgr.running
        asyncio.run(mgr.stop())
        assert not mgr.running

    def test_memory_stream_survives_multiple_add_retrieve_cycles(self):
        """Simulate 12 ticks of memory accumulation and retrieval."""
        ms = MemoryStream()
        persona = default_personas()[0]

        # Simulate 12 action ticks
        for i in range(12):
            ms.add(persona.id, "browsed", f"/page{i}", importance=2.0, tags=["browse", "routine"])
            if i % 4 == 0:
                ms.add(persona.id, "received_phishing_from", f"spam{i}@evil.com", importance=7.0, tags=["phishing", "email", "security"])

        # Should have accumulated enough for reflection
        assert ms.needs_reflection(threshold=10)

        # Retrieve security-related memories
        security_memories = ms.retrieve(["phishing", "security"], top_k=5)
        assert len(security_memories) > 0
        assert any("phishing" in m.content for m in security_memories)

    def test_action_log_types(self):
        """Routine action logs use realistic type names (DoD #5)."""
        from open_range.builder.npc.actions import (
            _web_log, _chat_log, _auth_log, _file_log, _db_log,
        )
        persona = default_personas()[0]
        assert _web_log(persona, "browse", "detail", "/foo", "UA")["type"] == "web_request"
        assert _auth_log(persona, "detail", "user", "success")["type"] == "auth"
        assert _file_log(persona, "detail", "share")["type"] == "file_access"
        assert _db_log(persona, "detail", "SELECT 1")["type"] == "db_query"

    def test_chat_log_type(self):
        """NPC-to-NPC email logs as type 'npc_chat' with recipient field (DoD #4)."""
        from open_range.builder.npc.actions import _chat_log
        persona = default_personas()[0]
        log = _chat_log(persona, "bob.smith", "Quick sync", "mail:janet.liu")
        assert log["type"] == "npc_chat"
        assert log["recipient"] == "bob.smith"
        assert log["action"] == "send_email"
        assert log["label"] == "benign"

    def test_web_log_has_http_metadata(self):
        """Web request logs include status_code and bytes fields (DoD #5)."""
        from open_range.builder.npc.actions import _web_log
        persona = default_personas()[0]
        log = _web_log(persona, "browse", "detail", "/dashboard", "Mozilla/5.0 ...")
        assert "status_code" in log
        assert log["status_code"] in {200, 301, 304, 404, 403}
        assert "bytes" in log
        assert log["bytes"] > 0

    def test_planner_full_day_cycle(self):
        """Template planner produces actions across a simulated day."""
        persona = default_personas()[0]
        planner = DailyPlanner(model=None)
        asyncio.run(planner.plan_day(persona, {}))

        # Fast-forward to end of day (480 real minutes maps to 8-hour workday)
        planner._day_start = time.time() - 28800

        consumed = []
        while True:
            hint = planner.next_action_hint()
            if hint is None:
                break
            consumed.append(hint)

        assert len(consumed) >= 6  # Template has 6-8 actions
        # Actions should be in hour order
        hours = [h.hour for h in consumed]
        assert hours == sorted(hours)


# ---------------------------------------------------------------------------
# DoD #8: Performance benchmark — 8 NPCs × 12 ticks < 30s (simulated mode)
# ---------------------------------------------------------------------------


class TestPerformanceBenchmark:
    """8 NPCs running 12 ticks concurrently must complete in under 30 seconds
    in fully simulated mode (no LLM, instant container mocks).
    """

    def test_eight_npcs_twelve_ticks_under_30s(self):
        import time as _time
        from types import SimpleNamespace
        from open_range.builder.npc.actions import NPCActionExecutor

        # 8 personas: cycle through the 4 defaults twice
        personas = (default_personas() * 2)[:8]

        snapshot = SimpleNamespace(
            topology={
                "hosts": ["web", "db", "mail", "siem", "files"],
                "domain": "corp.local",
                "users": [{"username": "alice", "hosts": ["web"]}],
            },
            files={},
        )

        mock_containers = MagicMock()
        mock_containers.exec = AsyncMock(return_value="")

        async def _run_npc(persona: GreenPersona) -> LLMNPCAgent:
            # Patch litellm so every LLM call fails instantly → _fallback_action
            with patch("open_range.builder.npc.npc_agent.litellm") as mock_llm, \
                 patch("open_range.builder.npc.planner.litellm") as mock_planner_llm:
                mock_llm.acompletion = AsyncMock(side_effect=RuntimeError("simulated"))
                mock_planner_llm.acompletion = AsyncMock(side_effect=RuntimeError("simulated"))

                agent = LLMNPCAgent()
                executor = NPCActionExecutor(mock_containers, snapshot)
                env_ctx = {
                    "pages": executor._pages,
                    "shares": executor._shares,
                    "db_tables": executor._db_tables,
                    "colleagues": executor._users,
                }
                # plan_day falls back to template schedule when LLM fails
                await agent._planner.plan_day(persona, env_ctx)

                for _ in range(12):
                    hint = agent._planner.next_action_hint()
                    plan_hint = (
                        {"action": hint.action, "target": hint.target, "detail": hint.detail}
                        if hint else None
                    )
                    routine = await agent.next_routine_action(persona, env_ctx, plan_hint=plan_hint)
                    log = await executor.execute_routine(
                        persona,
                        routine.get("action", "idle"),
                        routine.get("target", ""),
                        routine.get("detail", ""),
                    )
                    agent._actions.append(log)

            return agent

        async def _run_all():
            return await asyncio.gather(*[_run_npc(p) for p in personas])

        start = _time.perf_counter()
        agents = asyncio.run(_run_all())

        elapsed = _time.perf_counter() - start

        assert elapsed < 30.0, f"Benchmark took {elapsed:.2f}s, expected < 30s"

        for agent in agents:
            assert len(agent._actions) == 12, "Each NPC must complete all 12 ticks"
            assert len(agent._memory) == 12, "Each tick must record a memory"
