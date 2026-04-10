"""Tests for Phase 3: NPCTask, RuntimeNPCAgent, and NPCManager online mode."""

from __future__ import annotations

import asyncio
from typing import Any

import pytest

from open_range.builder.npc.memory import MemoryStream
from open_range.builder.npc.npc_manager import NPCManager
from open_range.builder.npc.outbox import ActionOutbox, EventInbox, SimClock
from open_range.builder.npc.persona import default_personas
from open_range.builder.npc.runtime_agent import RuntimeNPCAgent
from open_range.builder.npc.tasks import NPCTask, generate_tasks
from open_range.runtime_types import Action, RuntimeEvent
from open_range.world_ir import GreenPersona


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _personas() -> list[GreenPersona]:
    return default_personas()


def _make_agent(
    persona: GreenPersona | None = None,
    tasks: list[NPCTask] | None = None,
    colleagues: list[GreenPersona] | None = None,
) -> tuple[RuntimeNPCAgent, ActionOutbox, EventInbox, SimClock]:
    personas = _personas()
    p = persona or personas[0]
    outbox = ActionOutbox()
    inbox = EventInbox()
    clock = SimClock()
    memory = MemoryStream()
    t = tasks if tasks is not None else generate_tasks(p, personas)
    c = colleagues if colleagues is not None else personas
    agent = RuntimeNPCAgent(
        p, memory=memory, outbox=outbox, inbox=inbox,
        clock=clock, tasks=t, colleagues=c,
    )
    return agent, outbox, inbox, clock


def _event(eid: str = "e1", malicious: bool = True, **kw) -> RuntimeEvent:
    return RuntimeEvent(
        id=eid,
        event_type=kw.get("event_type", "InitialAccess"),
        actor=kw.get("actor", "red"),
        source_entity=kw.get("source_entity", "attacker"),
        target_entity=kw.get("target_entity", "svc-web"),
        time=kw.get("time", 1.0),
        malicious=malicious,
        observability_surfaces=kw.get("observability_surfaces", ("svc-web",)),
    )


# ---------------------------------------------------------------------------
# NPCTask and generate_tasks
# ---------------------------------------------------------------------------


class TestNPCTask:
    def test_task_is_frozen(self):
        t = NPCTask("test", "browse")
        with pytest.raises(Exception):
            t.description = "changed"

    def test_defaults(self):
        t = NPCTask("test", "browse")
        assert t.start_minutes == 0
        assert t.duration_minutes == 15
        assert t.collaborators == ()
        assert not t.needs_llm


class TestGenerateTasks:
    def test_returns_tasks_for_each_role(self):
        personas = _personas()
        for p in personas:
            tasks = generate_tasks(p, personas)
            assert len(tasks) >= 6
            assert all(isinstance(t, NPCTask) for t in tasks)

    def test_tasks_are_time_ordered(self):
        personas = _personas()
        for p in personas:
            tasks = generate_tasks(p, personas)
            starts = [t.start_minutes for t in tasks]
            assert starts == sorted(starts)

    def test_email_tasks_have_collaborators(self):
        personas = _personas()
        tasks = generate_tasks(personas[0], personas)
        email_tasks = [t for t in tasks if t.action == "send_email"]
        assert len(email_tasks) >= 1
        for t in email_tasks:
            assert len(t.collaborators) >= 1
            # Collaborator should not be self
            assert personas[0].id not in t.collaborators

    def test_collaborators_spread_across_colleagues(self):
        """Email tasks should target different colleagues, not always the same one."""
        personas = _personas()
        tasks = generate_tasks(personas[0], personas)
        email_tasks = [t for t in tasks if t.action == "send_email"]
        recipients = {t.collaborators[0] for t in email_tasks if t.collaborators}
        # With 3 colleagues and 2+ email tasks, at least 2 different recipients
        if len(email_tasks) >= 2 and len(personas) > 2:
            assert len(recipients) >= 2

    def test_deterministic_for_same_persona(self):
        personas = _personas()
        a = generate_tasks(personas[0], personas)
        b = generate_tasks(personas[0], personas)
        assert len(a) == len(b)
        for t1, t2 in zip(a, b):
            assert t1.description == t2.description
            assert t1.collaborators == t2.collaborators

    def test_no_colleagues_still_works(self):
        p = _personas()[0]
        tasks = generate_tasks(p, [])
        assert len(tasks) >= 6


# ---------------------------------------------------------------------------
# RuntimeNPCAgent
# ---------------------------------------------------------------------------


class TestRuntimeNPCAgent:
    def test_agent_starts_not_done(self):
        agent, *_ = _make_agent()
        assert not agent.done

    def test_agent_done_with_no_tasks(self):
        agent, *_ = _make_agent(tasks=[])
        assert agent.done

    def test_submit_task_when_clock_reaches_start(self):
        task = NPCTask("Browse portal", "browse", "/", "Checking", 10, 15)
        agent, outbox, _, clock = _make_agent(tasks=[task])

        # Clock at 0 — task not due yet
        agent._maybe_submit_next()
        assert len(outbox) == 0

        # Advance clock past task start
        clock.advance(10.0)
        agent._maybe_submit_next()
        actions = outbox.drain()
        assert len(actions) == 1
        assert actions[0].actor_id == agent.persona.id
        assert actions[0].payload["routine"] == "browse"

    def test_idle_tasks_skipped_no_action_for_loner(self):
        """Idle tasks produce no action for NPCs without friends."""
        from open_range.builder.npc.identity import NPCPersonality, NPCProfile, NPCBackstory
        loner = GreenPersona(
            id="loner", role="Analyst", department="Data",
            home_host="siem", mailbox="loner@corp.local",
            awareness=0.5, susceptibility={},
            profile=NPCProfile(
                backstory=NPCBackstory(friends=()),
                personality=NPCPersonality(chattiness=0.0),
            ),
        )
        task = NPCTask("Lunch", "idle", "", "Break", 0, 60)
        agent, outbox, _, clock = _make_agent(persona=loner, tasks=[task])
        agent._maybe_submit_next()
        assert len(outbox) == 0
        assert agent.done

    def test_idle_chatty_npc_sends_social_message(self):
        """Chatty NPCs with friends send social messages during idle time."""
        personas = _personas()
        # janet.liu has friends=("dan.wu",) and chattiness=0.9
        janet = personas[0]
        task = NPCTask("Lunch", "idle", "", "Break", 0, 60)
        agent, outbox, _, clock = _make_agent(persona=janet, tasks=[task])
        agent._maybe_submit_next()
        # With 0.9 chattiness, very likely to send (but random — check at least processed)
        assert agent.done
        if len(outbox) > 0:
            actions = outbox.drain()
            assert actions[0].kind == "mail"
            assert actions[0].payload.get("recipient") == "dan.wu"

    def test_email_task_includes_recipient_and_content(self):
        personas = _personas()
        task = NPCTask(
            "Send update", "send_email", personas[1].id, "Status",
            0, 20, collaborators=(personas[1].id,),
            email_subject="Update", email_body="Hi, here's the update.",
        )
        agent, outbox, _, clock = _make_agent(persona=personas[0], tasks=[task])
        agent._maybe_submit_next()
        actions = outbox.drain()
        assert len(actions) == 1
        a = actions[0]
        assert a.kind == "mail"
        assert a.payload["recipient"] == personas[1].id
        assert a.payload["branch"] == "npc_chat"
        assert a.payload["email_subject"] == "Update"
        assert a.payload["email_body"] == "Hi, here's the update."

    def test_task_recorded_in_memory(self):
        task = NPCTask("Query logs", "query_db", "", "Checking", 0, 15)
        agent, _, _, _ = _make_agent(tasks=[task])
        agent._maybe_submit_next()
        assert len(agent.memory) == 1
        entry = agent.memory._memories[0]
        assert entry.relation == "queried"
        assert "routine" in entry.tags

    def test_inbox_events_recorded_in_memory(self):
        agent, _, inbox, _ = _make_agent(tasks=[])
        inbox.push(_event("e1", malicious=True))
        agent._process_inbox()
        # Malicious event produces: observation memory + reaction memory
        assert len(agent.memory) >= 1
        obs = agent.memory._memories[0]
        assert "malicious" in obs.tags
        assert obs.importance == 8.0

    def test_own_events_not_recorded(self):
        """Agent should not record events it generated itself."""
        personas = _personas()
        agent, _, inbox, _ = _make_agent(persona=personas[0], tasks=[])
        own_event = _event(
            "e1", malicious=False,
            event_type="BenignUserAction",
            actor="green",
            source_entity=personas[0].id,
        )
        inbox.push(own_event)
        agent._process_inbox()
        assert len(agent.memory) == 0

    def test_full_run_submits_all_non_idle_tasks(self):
        tasks = [
            NPCTask("Browse", "browse", "/", "", 0, 10),
            NPCTask("Lunch", "idle", "", "", 10, 30),
            NPCTask("Query", "query_db", "", "", 40, 15),
        ]
        agent, outbox, _, clock = _make_agent(tasks=tasks)

        async def _run():
            clock.advance(50.0)  # all tasks are due
            run_task = asyncio.create_task(agent.run())
            await asyncio.sleep(1.5)  # 3 tasks × 0.3s poll interval + margin
            run_task.cancel()
            try:
                await run_task
            except asyncio.CancelledError:
                pass

        asyncio.run(_run())
        actions = outbox.drain()
        # browse + optional social message during idle + query_db
        routines = [a.payload["routine"] for a in actions]
        assert routines[0] == "browse"
        assert routines[-1] == "query_db"
        assert len(actions) >= 2


# ---------------------------------------------------------------------------
# Dynamic reactions to stimuli
# ---------------------------------------------------------------------------


class TestDynamicReactions:
    """NPCs deviate from their pre-generated script when stimuli arrive."""

    def test_detection_alert_triggers_report(self):
        """Security persona receiving a detection alert -> report action."""
        personas = _personas()
        riley = next(p for p in personas if p.id == "riley.kim")
        agent, outbox, inbox, clock = _make_agent(
            persona=riley, tasks=[NPCTask("Browse", "browse", "/", "", 100, 15)],
        )
        clock.advance(0.0)

        inbox.push(_event("atk-1", event_type="DetectionAlertRaised",
                          source_entity="svc-siem", target_entity="svc-web"))
        agent._process_inbox()
        agent._maybe_submit_next()

        actions = outbox.drain()
        assert len(actions) == 1
        a = actions[0]
        assert a.actor_id == "riley.kim"
        assert a.payload.get("branch") == "report_suspicious_activity"

    def test_non_security_service_degraded_contacts_helpdesk(self):
        """Non-security NPC receiving ServiceDegraded -> helpdesk or colleague."""
        personas = _personas()
        dan = next(p for p in personas if p.id == "dan.wu")
        agent, outbox, inbox, clock = _make_agent(
            persona=dan, tasks=[NPCTask("Browse", "browse", "/", "", 100, 15)],
        )
        clock.advance(0.0)
        inbox.push(_event("sd-1", event_type="ServiceDegraded",
                          target_entity="svc-web"))
        agent._process_inbox()
        agent._process_pending_observations()
        agent._maybe_submit_next()

        actions = outbox.drain()
        assert len(actions) == 1
        # Dan is chatty (0.8) so he messages a colleague
        assert actions[0].payload.get("routine") in ("send_mail", "contact_helpdesk")

    def test_reaction_overrides_next_scheduled_task(self):
        """A reaction takes priority over the next pre-generated task."""
        personas = _personas()
        riley = next(p for p in personas if p.id == "riley.kim")
        task = NPCTask("Browse portal", "browse", "/", "", 0, 15)
        agent, outbox, inbox, clock = _make_agent(persona=riley, tasks=[task])
        clock.advance(0.0)

        inbox.push(_event("atk-3", event_type="DetectionAlertRaised",
                          source_entity="svc-siem", target_entity="svc-web"))
        agent._process_inbox()
        agent._maybe_submit_next()  # reaction first

        actions = outbox.drain()
        assert len(actions) == 1
        assert actions[0].payload.get("branch") == "report_suspicious_activity"

        # Next call submits the delayed task
        agent._maybe_submit_next()
        actions2 = outbox.drain()
        assert len(actions2) == 1
        assert actions2[0].payload.get("routine") == "browse"

    def test_incoming_mail_triggers_read_reaction(self):
        """NPC receives mail from a colleague -> observation -> read reaction."""
        personas = _personas()
        bob = next(p for p in personas if p.id == "bob.smith")
        agent, outbox, inbox, clock = _make_agent(
            persona=bob, tasks=[NPCTask("Browse", "browse", "/", "", 100, 15)],
        )
        clock.advance(0.0)

        mail_event = _event(
            "mail-1", malicious=False,
            event_type="BenignUserAction",
            actor="green",
            source_entity="janet.liu",
            target_entity="bob.smith",
        )
        inbox.push(mail_event)
        agent._process_inbox()
        assert len(agent._pending_observations) == 1
        # Simulate the NPC deciding to check observations
        agent._process_pending_observations()
        agent._maybe_submit_next()

        actions = outbox.drain()
        assert len(actions) == 1
        a = actions[0]
        assert a.payload.get("routine") == "read_mail"
        assert a.payload.get("recipient") == "janet.liu"

    def test_incoming_mail_triggers_read_then_reply(self):
        """After reading mail, the NPC queues a reply with content."""
        from open_range.builder.npc.outbox import MailStore

        personas = _personas()
        bob = next(p for p in personas if p.id == "bob.smith")
        mail_store = MailStore()
        # Janet sent bob an email
        mail_store.deliver("janet.liu", "bob.smith",
                           "Q1 Report Review", "Hi Bob, please review the Q1 numbers.")

        agent, outbox, inbox, clock = _make_agent(
            persona=bob, tasks=[NPCTask("Browse", "browse", "/", "", 100, 15)],
        )
        agent.mail_store = mail_store
        clock.advance(0.0)

        mail_event = _event(
            "mail-2", malicious=False,
            event_type="BenignUserAction", actor="green",
            source_entity="janet.liu", target_entity="bob.smith",
        )
        inbox.push(mail_event)
        agent._process_inbox()
        # Message is deferred; process observations to trigger read + reply
        agent._process_pending_observations()

        # First action: read mail (with original content from MailStore)
        agent._maybe_submit_next()
        read_actions = outbox.drain()
        assert len(read_actions) == 1
        read = read_actions[0]
        assert read.payload["routine"] == "read_mail"
        assert read.payload["email_subject"] == "Q1 Report Review"
        assert "Q1 numbers" in read.payload["email_body"]

        # Second action: reply
        agent._maybe_submit_next()
        reply_actions = outbox.drain()
        assert len(reply_actions) == 1
        reply = reply_actions[0]
        assert reply.payload["routine"] == "send_mail"
        assert reply.payload["email_subject"].startswith("Re: Q1 Report Review")
        assert reply.payload["recipient"] == "janet.liu"
        # Reply body should be non-empty template content
        assert len(reply.payload["email_body"]) > 10

        # Reply should be deposited in MailStore for janet to pick up
        janet_mail = mail_store.pickup("janet.liu", sender="bob.smith")
        assert janet_mail is not None
        assert janet_mail["subject"].startswith("Re:")

    def test_detection_alert_triggers_reaction(self):
        """A DetectionAlertRaised event triggers immediate reaction for security persona."""
        personas = _personas()
        riley = next(p for p in personas if p.id == "riley.kim")
        agent, outbox, inbox, clock = _make_agent(persona=riley, tasks=[])
        clock.advance(0.0)

        alert = _event(
            "alert-1", malicious=False,
            event_type="DetectionAlertRaised",
            actor="green",
            source_entity="svc-siem",
            target_entity="svc-web",
        )
        inbox.push(alert)
        agent._process_inbox()
        # Detection alerts are fast-path for security personas
        assert len(agent._pending_observations) == 0
        agent._maybe_submit_next()

        actions = outbox.drain()
        assert len(actions) == 1
        assert actions[0].payload.get("branch") == "report_suspicious_activity"

    def test_benign_event_no_reaction(self):
        """Normal benign events (not targeting this NPC) don't trigger reactions."""
        personas = _personas()
        bob = next(p for p in personas if p.id == "bob.smith")
        agent, outbox, inbox, clock = _make_agent(persona=bob, tasks=[])
        clock.advance(0.0)

        benign = _event(
            "b-1", malicious=False,
            event_type="BenignUserAction",
            actor="green",
            source_entity="janet.liu",
            target_entity="svc-web",
        )
        inbox.push(benign)
        agent._process_inbox()
        agent._maybe_submit_next()

        assert len(outbox.drain()) == 0

    def test_no_duplicate_reaction_for_same_event(self):
        """The agent doesn't react to the same event twice."""
        personas = _personas()
        riley = next(p for p in personas if p.id == "riley.kim")
        agent, outbox, inbox, clock = _make_agent(persona=riley, tasks=[])
        clock.advance(0.0)

        evt = _event("dup-1", event_type="DetectionAlertRaised",
                      source_entity="svc-siem", target_entity="svc-web")
        inbox.push(evt)
        agent._process_inbox()
        agent._maybe_submit_next()
        outbox.drain()

        inbox.push(evt)
        agent._process_inbox()
        agent._maybe_submit_next()
        assert len(outbox.drain()) == 0

    def test_reaction_recorded_in_memory(self):
        """Reactive actions are stored in the agent's memory."""
        personas = _personas()
        riley = next(p for p in personas if p.id == "riley.kim")
        agent, outbox, inbox, clock = _make_agent(persona=riley, tasks=[])
        clock.advance(0.0)

        inbox.push(_event("mem-1", event_type="DetectionAlertRaised",
                          source_entity="svc-siem", target_entity="svc-web"))
        agent._process_inbox()
        agent._maybe_submit_next()

        assert len(agent.memory) >= 2
        tags = [t for m in agent.memory._memories for t in m.tags]
        assert "reactive" in tags
        assert "report" in tags

    def test_no_stimuli_replays_identically(self):
        """Without stimuli, two runs produce identical action sequences."""
        personas = _personas()
        janet = personas[0]
        tasks = [
            NPCTask("Browse", "browse", "/", "", 0, 10),
            NPCTask("Query", "query_db", "", "", 20, 15),
        ]

        def _run_once():
            agent, outbox, _, clock = _make_agent(persona=janet, tasks=tasks)
            clock.advance(30.0)
            agent._process_inbox()
            agent._maybe_submit_next()
            agent._maybe_submit_next()
            return [a.payload["routine"] for a in outbox.drain()]

        run1 = _run_once()
        run2 = _run_once()
        assert run1 == run2
        assert run1 == ["browse", "query_db"]

    def test_multiple_stimuli_queued_in_order(self):
        """Multiple detection alerts produce reactions in the order received."""
        personas = _personas()
        riley = next(p for p in personas if p.id == "riley.kim")
        agent, outbox, inbox, clock = _make_agent(persona=riley, tasks=[])
        clock.advance(0.0)

        inbox.push(_event("m1", event_type="DetectionAlertRaised",
                          source_entity="svc-siem", target_entity="svc-web"))
        inbox.push(_event("m2", event_type="DetectionAlertRaised",
                          source_entity="svc-siem", target_entity="svc-db"))
        agent._process_inbox()

        agent._maybe_submit_next()
        agent._maybe_submit_next()
        actions = outbox.drain()
        assert len(actions) == 2
        assert actions[0].payload["reported_target"] == "svc-web"
        assert actions[1].payload["reported_target"] == "svc-db"


# ---------------------------------------------------------------------------
# LLM integration (mocked)
# ---------------------------------------------------------------------------


class TestLLMIntegration:
    """LLM calls are used when model is set, with template fallback."""

    def _make_llm_agent(self, persona=None, tasks=None):
        personas = _personas()
        p = persona or personas[1]  # bob.smith
        outbox = ActionOutbox()
        inbox = EventInbox()
        clock = SimClock()
        memory = MemoryStream()
        from open_range.builder.npc.outbox import MailStore
        mail_store = MailStore()
        t = tasks if tasks is not None else []
        agent = RuntimeNPCAgent(
            p, memory=memory, outbox=outbox, inbox=inbox,
            clock=clock, tasks=t, colleagues=personas,
            model="test-model", mail_store=mail_store,
        )
        return agent, outbox, inbox, clock, mail_store

    @staticmethod
    def _mock_litellm(response_content: str):
        """Create a mock litellm module with a canned acompletion response."""
        from unittest.mock import AsyncMock, MagicMock
        mock_mod = MagicMock()
        mock_response = AsyncMock()
        mock_response.choices = [
            AsyncMock(message=AsyncMock(content=response_content))
        ]
        mock_mod.acompletion = AsyncMock(return_value=mock_response)
        return mock_mod

    @staticmethod
    def _mock_litellm_failing():
        from unittest.mock import AsyncMock, MagicMock
        mock_mod = MagicMock()
        mock_mod.acompletion = AsyncMock(side_effect=RuntimeError("API down"))
        return mock_mod

    def test_llm_email_composition(self):
        """When model is set, email tasks use LLM for content."""
        from unittest.mock import patch

        task = NPCTask("Client outreach", "send_email", "janet.liu", "",
                        0, 20, needs_llm=True)
        agent, outbox, _, clock, _ = self._make_llm_agent(tasks=[task])
        clock.advance(0.0)
        mock_llm = self._mock_litellm(
            '{"subject": "LLM Generated Subject", "body": "LLM generated body about client outreach."}'
        )

        async def _go():
            with patch.dict("sys.modules", {"litellm": mock_llm}):
                await agent._maybe_submit_next_async()

        asyncio.run(_go())
        actions = outbox.drain()
        assert len(actions) == 1
        assert actions[0].payload["email_subject"] == "LLM Generated Subject"
        assert "client outreach" in actions[0].payload["email_body"].lower()

    def test_llm_email_falls_back_on_failure(self):
        """When LLM fails, template content is used."""
        from unittest.mock import patch

        task = NPCTask("Client outreach", "send_email", "janet.liu", "",
                        0, 20, needs_llm=True,
                        email_subject="Template Subject", email_body="Template body.")
        agent, outbox, _, clock, _ = self._make_llm_agent(tasks=[task])
        clock.advance(0.0)
        mock_llm = self._mock_litellm_failing()

        async def _go():
            with patch.dict("sys.modules", {"litellm": mock_llm}):
                await agent._maybe_submit_next_async()

        asyncio.run(_go())
        actions = outbox.drain()
        assert len(actions) == 1
        assert actions[0].payload["email_subject"] == "Template Subject"

    def test_llm_reply_composition(self):
        """When model is set, replies use LLM for content."""
        from unittest.mock import patch

        personas = _personas()
        bob = next(p for p in personas if p.id == "bob.smith")
        agent, outbox, inbox, clock, mail_store = self._make_llm_agent(persona=bob)
        clock.advance(0.0)
        mail_store.deliver("janet.liu", "bob.smith", "Q1 Report", "Please review.")
        mock_llm = self._mock_litellm(
            '{"subject": "Re: Q1 Report", "body": "Reviewed — looks solid. One note on margins."}'
        )
        mail_event = _event("m1", malicious=False, event_type="BenignUserAction",
                             actor="green", source_entity="janet.liu", target_entity="bob.smith")
        inbox.push(mail_event)

        async def _go():
            with patch.dict("sys.modules", {"litellm": mock_llm}):
                await agent._process_inbox_async()
                # Message is deferred; process observations to trigger read + reply
                await agent._process_pending_observations_async()
                await agent._maybe_submit_next_async()  # read
                await agent._maybe_submit_next_async()  # reply

        asyncio.run(_go())
        actions = outbox.drain()
        assert len(actions) == 2
        reply = actions[1]
        assert reply.payload["email_subject"] == "Re: Q1 Report"
        assert "margins" in reply.payload["email_body"]

    def test_llm_security_reaction(self):
        """When model is set, detection alerts use LLM for decisions."""
        from unittest.mock import patch

        personas = _personas()
        riley = next(p for p in personas if p.id == "riley.kim")
        agent, outbox, inbox, clock, _ = self._make_llm_agent(persona=riley)
        clock.advance(0.0)
        mock_llm = self._mock_litellm(
            '{"action": "report_to_IT", "reason": "Suspicious activity detected."}'
        )
        inbox.push(_event("sec1", event_type="DetectionAlertRaised",
                          source_entity="svc-siem", target_entity="svc-web"))

        async def _go():
            with patch.dict("sys.modules", {"litellm": mock_llm}):
                await agent._process_inbox_async()
                await agent._maybe_submit_next_async()

        asyncio.run(_go())
        actions = outbox.drain()
        assert len(actions) == 1
        assert actions[0].payload["branch"] == "report_suspicious_activity"

    def test_no_llm_without_model(self):
        """Without a model, no LLM calls — templates only."""
        task = NPCTask("Send update", "send_email", "janet.liu", "",
                        0, 20, needs_llm=True,
                        email_subject="Template", email_body="Template body.")
        agent, outbox, _, clock = _make_agent(tasks=[task])
        assert not agent._use_llm
        clock.advance(0.0)
        agent._maybe_submit_next()
        actions = outbox.drain()
        assert len(actions) == 1
        assert actions[0].payload["email_subject"] == "Template"


# ---------------------------------------------------------------------------
# NPCManager online mode
# ---------------------------------------------------------------------------


class TestNPCManagerOnlineMode:
    def test_online_mode_creates_runtime_agents(self):
        async def _go():
            personas = _personas()
            from types import SimpleNamespace
            snap = SimpleNamespace(
                world=SimpleNamespace(green_personas=personas),
                npc_personas=None,
            )
            outbox = ActionOutbox()
            clock = SimClock()
            inboxes = {p.id: EventInbox() for p in personas}
            memories = {p.id: MemoryStream() for p in personas}

            mgr = NPCManager()
            await mgr.start(
                snap,
                action_outbox=outbox,
                event_inboxes=inboxes,
                sim_clock=clock,
                memory_streams=memories,
            )
            assert mgr.running
            assert len(mgr.agents) == len(personas)
            assert all(isinstance(a, RuntimeNPCAgent) for a in mgr.agents)
            await mgr.stop()

        asyncio.run(_go())

    def test_online_agents_submit_actions_on_clock_advance(self):
        async def _go():
            personas = _personas()[:2]  # just 2 for speed
            from types import SimpleNamespace
            snap = SimpleNamespace(
                world=SimpleNamespace(green_personas=personas),
                npc_personas=None,
            )
            outbox = ActionOutbox(max_size=500)
            clock = SimClock()
            inboxes = {p.id: EventInbox() for p in personas}
            memories = {p.id: MemoryStream() for p in personas}

            mgr = NPCManager()
            await mgr.start(
                snap,
                action_outbox=outbox,
                event_inboxes=inboxes,
                sim_clock=clock,
                memory_streams=memories,
            )
            # Advance clock so first tasks are due
            clock.advance(5.0)
            await asyncio.sleep(0.8)  # let agents poll
            await mgr.stop()

            actions = outbox.drain()
            assert len(actions) >= 1
            assert all(a.role == "green" for a in actions)

        asyncio.run(_go())

    def test_mock_mode_unchanged(self):
        """Mock mode still works without bridge components."""
        async def _go():
            mgr = NPCManager(mock_mode=True)
            from types import SimpleNamespace
            snap = SimpleNamespace(npc_personas=_personas())
            await mgr.start(snap)
            assert mgr.running
            assert len(mgr.agents) == 0  # mock mode doesn't create RuntimeNPCAgents
            await mgr.stop()

        asyncio.run(_go())

    def test_legacy_mode_without_bridge(self):
        """Without bridge components, falls back to LLMNPCAgent path."""
        async def _go():
            mgr = NPCManager()
            from types import SimpleNamespace
            snap = SimpleNamespace(npc_personas=_personas())
            # No outbox/inboxes/clock → legacy path (would try LLM, but we cancel fast)
            await mgr.start(snap)
            assert mgr.running
            assert len(mgr.agents) == 0  # RuntimeNPCAgents only in online mode
            await mgr.stop()

        asyncio.run(_go())
