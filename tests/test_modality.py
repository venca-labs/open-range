"""Tests for communication modality (email vs chat).

Covers: MessageStore modality filtering, _modality_service helper,
subject stripping on chat, reply-on-same-medium, task generation
modality assignment, social message chat preference, and read-action
memory differentiation.
"""

from __future__ import annotations

import asyncio
from unittest.mock import patch

import pytest

from open_range.builder.npc.identity import NPCBackstory, NPCPersonality, NPCProfile
from open_range.builder.npc.memory import MemoryStream
from open_range.builder.npc.outbox import ActionOutbox, EventInbox, MailStore, MessageStore, SimClock
from open_range.builder.npc.persona import default_personas
from open_range.builder.npc.runtime_agent import RuntimeNPCAgent, _modality_service
from open_range.builder.npc.tasks import NPCTask, generate_tasks
from open_range.runtime_types import Action, RuntimeEvent
from open_range.world_ir import GreenPersona


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _personas() -> list[GreenPersona]:
    return default_personas()


def _make_agent(
    persona: GreenPersona | None = None,
    tasks: list[NPCTask] | None = None,
    colleagues: list[GreenPersona] | None = None,
    mail_store: MessageStore | None = None,
) -> tuple[RuntimeNPCAgent, ActionOutbox, EventInbox, SimClock, MessageStore]:
    personas = _personas()
    p = persona or personas[0]
    outbox = ActionOutbox()
    inbox = EventInbox()
    clock = SimClock()
    memory = MemoryStream()
    ms = mail_store or MessageStore()
    t = tasks if tasks is not None else generate_tasks(p, personas)
    c = colleagues if colleagues is not None else personas
    agent = RuntimeNPCAgent(
        p, memory=memory, outbox=outbox, inbox=inbox,
        clock=clock, tasks=t, colleagues=c, mail_store=ms,
    )
    return agent, outbox, inbox, clock, ms


def _event(eid: str = "e1", **kw) -> RuntimeEvent:
    return RuntimeEvent(
        id=eid,
        event_type=kw.get("event_type", "BenignUserAction"),
        actor=kw.get("actor", "green"),
        source_entity=kw.get("source_entity", "attacker"),
        target_entity=kw.get("target_entity", "svc-web"),
        time=kw.get("time", 1.0),
        malicious=kw.get("malicious", False),
        observability_surfaces=kw.get("observability_surfaces", ("svc-web",)),
    )


def _chat_persona() -> GreenPersona:
    """A persona that prefers chat."""
    personas = _personas()
    # dan.wu prefers chat
    return next(p for p in personas if p.id == "dan.wu")


def _email_persona() -> GreenPersona:
    """A persona that prefers email."""
    personas = _personas()
    # bob.smith prefers email
    return next(p for p in personas if p.id == "bob.smith")


# ---------------------------------------------------------------------------
# _modality_service helper
# ---------------------------------------------------------------------------


class TestModalityService:
    def test_email_maps_to_svc_email(self):
        assert _modality_service("email") == "svc-email"

    def test_chat_maps_to_svc_chat(self):
        assert _modality_service("chat") == "svc-chat"

    def test_unknown_falls_back_to_svc_email(self):
        assert _modality_service("smoke_signal") == "svc-email"

    def test_empty_falls_back_to_svc_email(self):
        assert _modality_service("") == "svc-email"


# ---------------------------------------------------------------------------
# MessageStore modality filtering
# ---------------------------------------------------------------------------


class TestMessageStoreModality:
    def test_deliver_stores_modality(self):
        ms = MessageStore()
        ms.deliver("alice", "bob", "Hi", "Hello", modality="chat")
        msg = ms.pickup("bob")
        assert msg is not None
        assert msg["modality"] == "chat"

    def test_deliver_defaults_to_email(self):
        ms = MessageStore()
        ms.deliver("alice", "bob", "Hi", "Hello")
        msg = ms.pickup("bob")
        assert msg["modality"] == "email"

    def test_pickup_filters_by_modality(self):
        ms = MessageStore()
        ms.deliver("alice", "bob", "Email msg", "body1", modality="email")
        ms.deliver("carol", "bob", "Chat msg", "body2", modality="chat")
        # Only pick up chat
        msg = ms.pickup("bob", modality="chat")
        assert msg is not None
        assert msg["sender"] == "carol"
        assert msg["modality"] == "chat"
        # Email still waiting
        msg2 = ms.pickup("bob", modality="email")
        assert msg2 is not None
        assert msg2["sender"] == "alice"

    def test_pickup_returns_none_when_modality_mismatch(self):
        ms = MessageStore()
        ms.deliver("alice", "bob", "Hi", "body", modality="email")
        assert ms.pickup("bob", modality="chat") is None

    def test_pending_count_filters_by_modality(self):
        ms = MessageStore()
        ms.deliver("a", "bob", "s1", "b1", modality="email")
        ms.deliver("b", "bob", "s2", "b2", modality="chat")
        ms.deliver("c", "bob", "s3", "b3", modality="chat")
        assert ms.pending_count("bob") == 3
        assert ms.pending_count("bob", modality="email") == 1
        assert ms.pending_count("bob", modality="chat") == 2

    def test_mail_store_alias(self):
        """MailStore is a backward-compatible alias for MessageStore."""
        assert MailStore is MessageStore
        ms = MailStore()
        ms.deliver("alice", "bob", "", "chat body", modality="chat")
        assert ms.pending_count("bob") == 1

    def test_chat_message_with_empty_subject(self):
        """Chat messages typically have no subject."""
        ms = MessageStore()
        ms.deliver("alice", "bob", "", "Hey, quick question", modality="chat")
        msg = ms.pickup("bob")
        assert msg["subject"] == ""
        assert msg["body"] == "Hey, quick question"


# ---------------------------------------------------------------------------
# Task generation modality assignment
# ---------------------------------------------------------------------------


class TestTaskModality:
    def test_chat_persona_gets_chat_tasks(self):
        personas = _personas()
        dan = _chat_persona()
        tasks = generate_tasks(dan, personas)
        email_tasks = [t for t in tasks if t.action == "send_email"]
        assert len(email_tasks) >= 1
        for t in email_tasks:
            assert t.modality == "chat"

    def test_email_persona_gets_email_tasks(self):
        personas = _personas()
        bob = _email_persona()
        tasks = generate_tasks(bob, personas)
        email_tasks = [t for t in tasks if t.action == "send_email"]
        assert len(email_tasks) >= 1
        for t in email_tasks:
            assert t.modality == "email"

    def test_non_message_tasks_default_modality(self):
        """Non-message tasks keep default modality (doesn't matter, not used)."""
        personas = _personas()
        dan = _chat_persona()
        tasks = generate_tasks(dan, personas)
        browse_tasks = [t for t in tasks if t.action == "browse"]
        assert len(browse_tasks) >= 1
        # Non-email tasks keep default "email" since it's not used
        for t in browse_tasks:
            assert t.modality == "email"

    def test_no_profile_defaults_to_email(self):
        """Persona without a profile gets email modality."""
        bare = GreenPersona(id="bare", role="Analyst", department="Data")
        others = _personas()
        tasks = generate_tasks(bare, others)
        email_tasks = [t for t in tasks if t.action == "send_email"]
        for t in email_tasks:
            assert t.modality == "email"


# ---------------------------------------------------------------------------
# _build_action: chat subject stripping
# ---------------------------------------------------------------------------


class TestBuildActionModality:
    def test_chat_task_strips_subject(self):
        """Chat messages should have empty subject in the action payload."""
        personas = _personas()
        dan = _chat_persona()
        task = NPCTask(
            "Send update", "send_email", personas[0].id, "",
            0, 20, collaborators=(personas[0].id,),
            modality="chat",
            email_subject="Should be stripped", email_body="Chat body here.",
        )
        agent, outbox, _, clock, _ = _make_agent(persona=dan, tasks=[task])
        clock.advance(0.0)
        agent._maybe_submit_next()
        actions = outbox.drain()
        assert len(actions) == 1
        assert actions[0].payload["email_subject"] == ""
        assert actions[0].payload["email_body"] == "Chat body here."

    def test_email_task_keeps_subject(self):
        """Email messages should retain their subject."""
        personas = _personas()
        bob = _email_persona()
        task = NPCTask(
            "Send update", "send_email", personas[0].id, "",
            0, 20, collaborators=(personas[0].id,),
            modality="email",
            email_subject="Q1 Report", email_body="Email body here.",
        )
        agent, outbox, _, clock, _ = _make_agent(persona=bob, tasks=[task])
        clock.advance(0.0)
        agent._maybe_submit_next()
        actions = outbox.drain()
        assert len(actions) == 1
        assert actions[0].payload["email_subject"] == "Q1 Report"

    def test_chat_action_uses_svc_chat(self):
        """Chat tasks should route to svc-chat."""
        personas = _personas()
        dan = _chat_persona()
        task = NPCTask(
            "Send update", "send_email", personas[0].id, "",
            0, 20, collaborators=(personas[0].id,),
            modality="chat", email_subject="x", email_body="y",
        )
        agent, outbox, _, clock, _ = _make_agent(persona=dan, tasks=[task])
        clock.advance(0.0)
        agent._maybe_submit_next()
        actions = outbox.drain()
        assert actions[0].payload["service"] == "svc-chat"

    def test_email_action_uses_svc_email(self):
        """Email tasks should route to svc-email."""
        personas = _personas()
        bob = _email_persona()
        task = NPCTask(
            "Send update", "send_email", personas[0].id, "",
            0, 20, collaborators=(personas[0].id,),
            modality="email", email_subject="x", email_body="y",
        )
        agent, outbox, _, clock, _ = _make_agent(persona=bob, tasks=[task])
        clock.advance(0.0)
        agent._maybe_submit_next()
        actions = outbox.drain()
        assert actions[0].payload["service"] == "svc-email"

    def test_chat_action_includes_modality_in_payload(self):
        personas = _personas()
        dan = _chat_persona()
        task = NPCTask(
            "Send update", "send_email", personas[0].id, "",
            0, 20, collaborators=(personas[0].id,),
            modality="chat", email_subject="x", email_body="y",
        )
        agent, outbox, _, clock, _ = _make_agent(persona=dan, tasks=[task])
        clock.advance(0.0)
        agent._maybe_submit_next()
        actions = outbox.drain()
        assert actions[0].payload["modality"] == "chat"

    def test_chat_delivered_to_store_without_subject(self):
        """Chat messages deposited in MessageStore should have empty subject."""
        personas = _personas()
        dan = _chat_persona()
        ms = MessageStore()
        target = personas[0]
        task = NPCTask(
            "Send update", "send_email", target.id, "",
            0, 20, collaborators=(target.id,),
            modality="chat", email_subject="Should vanish", email_body="Chat body.",
        )
        agent, outbox, _, clock, _ = _make_agent(
            persona=dan, tasks=[task], mail_store=ms,
        )
        clock.advance(0.0)
        agent._maybe_submit_next()
        msg = ms.pickup(target.id, sender=dan.id)
        assert msg is not None
        assert msg["subject"] == ""
        assert msg["body"] == "Chat body."
        assert msg["modality"] == "chat"


# ---------------------------------------------------------------------------
# Reply-on-same-medium
# ---------------------------------------------------------------------------


class TestReplyOnSameMedium:
    def test_email_reply_keeps_subject(self):
        """Reply to an email retains Re: subject."""
        personas = _personas()
        bob = _email_persona()
        ms = MessageStore()
        ms.deliver("janet.liu", "bob.smith", "Q1 Report", "Please review.", modality="email")

        agent, outbox, inbox, clock, _ = _make_agent(
            persona=bob, tasks=[], mail_store=ms,
        )
        clock.advance(0.0)
        inbox.push(_event("m1", source_entity="janet.liu", target_entity="bob.smith"))
        agent._process_inbox()
        agent._process_pending_observations()
        # read
        agent._maybe_submit_next()
        read_actions = outbox.drain()
        assert read_actions[0].payload["modality"] == "email"
        assert read_actions[0].payload["email_subject"] == "Q1 Report"
        # reply
        agent._maybe_submit_next()
        reply_actions = outbox.drain()
        assert len(reply_actions) == 1
        reply = reply_actions[0]
        assert reply.payload["modality"] == "email"
        assert reply.payload["service"] == "svc-email"
        assert reply.payload["email_subject"].startswith("Re:")

    def test_chat_reply_strips_subject(self):
        """Reply to a chat message has empty subject."""
        personas = _personas()
        bob = _email_persona()
        ms = MessageStore()
        # Dan sent a chat to Bob
        ms.deliver("dan.wu", "bob.smith", "", "Hey, quick question about K8s", modality="chat")

        agent, outbox, inbox, clock, _ = _make_agent(
            persona=bob, tasks=[], mail_store=ms,
        )
        clock.advance(0.0)
        inbox.push(_event("m2", source_entity="dan.wu", target_entity="bob.smith"))
        agent._process_inbox()
        agent._process_pending_observations()
        # read
        agent._maybe_submit_next()
        read_actions = outbox.drain()
        assert read_actions[0].payload["modality"] == "chat"
        # reply
        agent._maybe_submit_next()
        reply_actions = outbox.drain()
        assert len(reply_actions) == 1
        reply = reply_actions[0]
        assert reply.payload["modality"] == "chat"
        assert reply.payload["service"] == "svc-chat"
        assert reply.payload["email_subject"] == ""

    def test_chat_reply_deposited_in_store(self):
        """Chat reply ends up in MessageStore with correct modality."""
        personas = _personas()
        bob = _email_persona()
        ms = MessageStore()
        ms.deliver("dan.wu", "bob.smith", "", "Hey Bob", modality="chat")

        agent, outbox, inbox, clock, _ = _make_agent(
            persona=bob, tasks=[], mail_store=ms,
        )
        clock.advance(0.0)
        inbox.push(_event("m3", source_entity="dan.wu", target_entity="bob.smith"))
        agent._process_inbox()
        agent._process_pending_observations()
        agent._maybe_submit_next()  # read
        agent._maybe_submit_next()  # reply
        # Dan should have a reply waiting
        reply_msg = ms.pickup("dan.wu", sender="bob.smith")
        assert reply_msg is not None
        assert reply_msg["modality"] == "chat"
        assert reply_msg["subject"] == ""

    def test_async_chat_reply_strips_subject(self):
        """Async reply path also strips subjects for chat."""
        personas = _personas()
        bob = _email_persona()
        ms = MessageStore()
        ms.deliver("dan.wu", "bob.smith", "", "Async chat test", modality="chat")

        agent, outbox, inbox, clock, _ = _make_agent(
            persona=bob, tasks=[], mail_store=ms,
        )
        clock.advance(0.0)
        inbox.push(_event("m4", source_entity="dan.wu", target_entity="bob.smith"))

        async def _go():
            await agent._process_inbox_async()
            await agent._process_pending_observations_async()
            await agent._maybe_submit_next_async()  # read
            await agent._maybe_submit_next_async()  # reply

        asyncio.run(_go())
        actions = outbox.drain()
        assert len(actions) == 2
        reply = actions[1]
        assert reply.payload["modality"] == "chat"
        assert reply.payload["email_subject"] == ""


# ---------------------------------------------------------------------------
# Read action modality
# ---------------------------------------------------------------------------


class TestReadActionModality:
    def test_read_email_uses_svc_email(self):
        personas = _personas()
        bob = _email_persona()
        ms = MessageStore()
        ms.deliver("janet.liu", "bob.smith", "Subject", "Body", modality="email")
        agent, outbox, inbox, clock, _ = _make_agent(
            persona=bob, tasks=[], mail_store=ms,
        )
        clock.advance(0.0)
        inbox.push(_event("r1", source_entity="janet.liu", target_entity="bob.smith"))
        agent._process_inbox()
        agent._process_pending_observations()
        agent._maybe_submit_next()
        actions = outbox.drain()
        assert actions[0].payload["service"] == "svc-email"
        assert actions[0].payload["modality"] == "email"

    def test_read_chat_uses_svc_chat(self):
        personas = _personas()
        bob = _email_persona()
        ms = MessageStore()
        ms.deliver("dan.wu", "bob.smith", "", "Chat body", modality="chat")
        agent, outbox, inbox, clock, _ = _make_agent(
            persona=bob, tasks=[], mail_store=ms,
        )
        clock.advance(0.0)
        inbox.push(_event("r2", source_entity="dan.wu", target_entity="bob.smith"))
        agent._process_inbox()
        agent._process_pending_observations()
        agent._maybe_submit_next()
        actions = outbox.drain()
        assert actions[0].payload["service"] == "svc-chat"
        assert actions[0].payload["modality"] == "chat"

    def test_read_chat_records_chat_memory(self):
        """Reading a chat should record 'read_chat_from' in memory."""
        personas = _personas()
        bob = _email_persona()
        ms = MessageStore()
        ms.deliver("dan.wu", "bob.smith", "", "Chat msg", modality="chat")
        agent, outbox, inbox, clock, _ = _make_agent(
            persona=bob, tasks=[], mail_store=ms,
        )
        clock.advance(0.0)
        inbox.push(_event("r3", source_entity="dan.wu", target_entity="bob.smith"))
        agent._process_inbox()
        agent._process_pending_observations()
        agent._maybe_submit_next()
        # Check memory for read_chat_from
        memories = agent.memory._memories
        read_memories = [m for m in memories if m.relation == "read_chat_from"]
        assert len(read_memories) >= 1
        assert "dan.wu" in read_memories[0].object_

    def test_read_email_records_email_memory(self):
        """Reading an email should record 'read_mail_from' in memory."""
        personas = _personas()
        bob = _email_persona()
        ms = MessageStore()
        ms.deliver("janet.liu", "bob.smith", "Subject", "Body", modality="email")
        agent, outbox, inbox, clock, _ = _make_agent(
            persona=bob, tasks=[], mail_store=ms,
        )
        clock.advance(0.0)
        inbox.push(_event("r4", source_entity="janet.liu", target_entity="bob.smith"))
        agent._process_inbox()
        agent._process_pending_observations()
        agent._maybe_submit_next()
        memories = agent.memory._memories
        read_memories = [m for m in memories if m.relation == "read_mail_from"]
        assert len(read_memories) >= 1
        assert "janet.liu" in read_memories[0].object_


# ---------------------------------------------------------------------------
# Social messages use chat
# ---------------------------------------------------------------------------


class TestSocialMessageModality:
    def _chatty_persona(self) -> GreenPersona:
        """Return janet.liu — chattiness 0.9, friends with dan.wu, prefers chat."""
        return next(p for p in _personas() if p.id == "janet.liu")

    def test_social_message_uses_chat(self):
        """Social messages between friends should use chat."""
        janet = self._chatty_persona()
        agent, outbox, _, clock, _ = _make_agent(
            persona=janet, tasks=[NPCTask("Lunch", "idle", "", "Break", 0, 60)],
        )
        clock.advance(0.0)
        # Force the chattiness check to pass (RNG seed varies per process)
        agent._rng.random = lambda: 0.0  # always < chattiness
        agent._maybe_submit_next()
        actions = outbox.drain()
        assert len(actions) == 1
        assert actions[0].payload.get("modality") == "chat"
        assert actions[0].payload.get("email_subject") == ""

    def test_social_message_body_not_empty(self):
        """Social chat messages should still have body content."""
        janet = self._chatty_persona()
        agent, outbox, _, clock, _ = _make_agent(
            persona=janet, tasks=[NPCTask("Lunch", "idle", "", "Break", 0, 60)],
        )
        clock.advance(0.0)
        agent._rng.random = lambda: 0.0
        agent._maybe_submit_next()
        actions = outbox.drain()
        assert len(actions) == 1
        assert actions[0].payload.get("email_body", "") != ""


# ---------------------------------------------------------------------------
# Identity model: preferred_modality field
# ---------------------------------------------------------------------------


class TestPreferredModality:
    def test_backstory_default_modality_is_email(self):
        b = NPCBackstory()
        assert b.preferred_modality == "email"

    def test_backstory_chat_modality(self):
        b = NPCBackstory(preferred_modality="chat")
        assert b.preferred_modality == "chat"

    def test_persona_profiles_have_modality(self):
        """All default personas should have a preferred_modality set."""
        for p in _personas():
            assert p.profile is not None
            assert p.profile.backstory.preferred_modality in ("email", "chat")

    def test_known_chat_personas(self):
        """Dan, Janet, Priya, Michael should prefer chat."""
        chat_ids = {"dan.wu", "janet.liu", "priya.patel", "michael.torres"}
        for p in _personas():
            if p.id in chat_ids:
                assert p.profile.backstory.preferred_modality == "chat", f"{p.id} should prefer chat"

    def test_known_email_personas(self):
        """Bob, Carol, Alex, Sam should prefer email."""
        email_ids = {"bob.smith", "carol.jones", "alex.chen", "sam.rivera"}
        for p in _personas():
            if p.id in email_ids:
                assert p.profile.backstory.preferred_modality == "email", f"{p.id} should prefer email"


# ---------------------------------------------------------------------------
# Observability surface per modality
# ---------------------------------------------------------------------------


class TestObservabilitySurface:
    """The runtime should emit events on svc-chat for chat and svc-email for email."""

    def test_chat_action_emits_on_svc_chat(self):
        from open_range.runtime_events import green_events_for_action
        from open_range.runtime_types import Action

        action = Action(
            actor_id="dan.wu", role="green", kind="mail",
            payload={
                "branch": "npc_chat", "recipient": "bob.smith",
                "modality": "chat", "service": "svc-chat",
            },
        )
        events: list = []

        def fake_emit(**kw):
            events.append(kw)
            return None  # unused by caller in this test

        green_events_for_action(
            action, live_recovery_applied=False, target="svc-chat",
            emit_event=fake_emit, service_surfaces=lambda t: (t,),
        )
        assert len(events) == 1
        assert events[0]["observability_surfaces"] == ("svc-chat",)

    def test_email_action_emits_on_svc_email(self):
        from open_range.runtime_events import green_events_for_action
        from open_range.runtime_types import Action

        action = Action(
            actor_id="bob.smith", role="green", kind="mail",
            payload={
                "branch": "npc_chat", "recipient": "dan.wu",
                "modality": "email", "service": "svc-email",
            },
        )
        events: list = []

        def fake_emit(**kw):
            events.append(kw)
            return None

        green_events_for_action(
            action, live_recovery_applied=False, target="svc-email",
            emit_event=fake_emit, service_surfaces=lambda t: (t,),
        )
        assert len(events) == 1
        assert events[0]["observability_surfaces"] == ("svc-email",)

    def test_no_modality_defaults_to_svc_email(self):
        from open_range.runtime_events import green_events_for_action
        from open_range.runtime_types import Action

        action = Action(
            actor_id="bob.smith", role="green", kind="mail",
            payload={"branch": "npc_chat", "recipient": "dan.wu"},
        )
        events: list = []

        def fake_emit(**kw):
            events.append(kw)
            return None

        green_events_for_action(
            action, live_recovery_applied=False, target="svc-email",
            emit_event=fake_emit, service_surfaces=lambda t: (t,),
        )
        assert len(events) == 1
        assert events[0]["observability_surfaces"] == ("svc-email",)
