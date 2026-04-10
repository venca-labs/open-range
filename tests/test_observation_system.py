"""Tests for the observation-driven NPC behavior system.

Covers: observation creation/categorization, personality-driven check
propensity, observation aging, between-task batch checking, security
fast path, determinism, and async parity.
"""

from __future__ import annotations

import asyncio

import pytest

from open_range.builder.npc.identity import NPCBackstory, NPCPersonality, NPCProfile
from open_range.builder.npc.memory import MemoryStream
from open_range.builder.npc.outbox import ActionOutbox, EventInbox, MessageStore, SimClock
from open_range.builder.npc.persona import default_personas
from open_range.builder.npc.runtime_agent import (
    Observation,
    RuntimeNPCAgent,
    _CHECK_PROPENSITY_BASE,
    _MOOD_WEIGHTS,
    _STYLE_WEIGHTS,
    _WORK_ETHIC_WEIGHTS,
)
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
    t = tasks if tasks is not None else []
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


def _persona_with_personality(**personality_kw) -> GreenPersona:
    """Create a persona with specific personality traits."""
    return GreenPersona(
        id="test-npc", role="Analyst", department="Data",
        home_host="siem", mailbox="test@corp.local",
        awareness=0.5, susceptibility={},
        profile=NPCProfile(
            backstory=NPCBackstory(friends=("colleague-1",)),
            personality=NPCPersonality(**personality_kw),
        ),
    )


# ---------------------------------------------------------------------------
# Observation creation and categorization
# ---------------------------------------------------------------------------


class TestObservationCreation:
    def test_detection_alert_is_security(self):
        """DetectionAlertRaised -> category 'security' (for security personas)."""
        personas = _personas()
        riley = next(p for p in personas if p.id == "riley.kim")
        agent, *_ = _make_agent(persona=riley)
        evt = _event("det-1", malicious=False, event_type="DetectionAlertRaised",
                      source_entity="svc-siem")
        obs = agent._create_observation(evt)
        assert obs is not None
        assert obs.category == "security"
        assert obs.importance == 8.0

    def test_suspicious_action_is_security(self):
        """SuspiciousActionObserved -> category 'security'."""
        personas = _personas()
        riley = next(p for p in personas if p.id == "riley.kim")
        agent, *_ = _make_agent(persona=riley)
        evt = _event("sus-1", malicious=False, event_type="SuspiciousActionObserved",
                      source_entity="svc-siem")
        obs = agent._create_observation(evt)
        assert obs is not None
        assert obs.category == "security"

    def test_service_degraded_is_alert(self):
        """ServiceDegraded -> category 'alert'."""
        personas = _personas()
        bob = next(p for p in personas if p.id == "bob.smith")
        agent, *_ = _make_agent(persona=bob)
        evt = _event("sd-1", malicious=False, event_type="ServiceDegraded",
                      target_entity="svc-web")
        obs = agent._create_observation(evt)
        assert obs is not None
        assert obs.category == "alert"
        assert obs.importance == 4.0

    def test_undetected_malicious_is_none(self):
        """Raw malicious events (undetected) produce no observation.

        These events don't reach NPC inboxes via routing, but even if
        they did, _create_observation should not create an actionable
        observation for them.
        """
        personas = _personas()
        bob = next(p for p in personas if p.id == "bob.smith")
        agent, *_ = _make_agent(persona=bob)
        for event_type in ("InitialAccess", "CredentialObtained", "PrivilegeEscalation"):
            evt = _event(f"m-{event_type}", malicious=True, event_type=event_type)
            obs = agent._create_observation(evt)
            assert obs is None

    def test_benign_message_targeting_self_is_message(self):
        """BenignUserAction targeting this NPC -> category 'message'."""
        personas = _personas()
        bob = next(p for p in personas if p.id == "bob.smith")
        agent, *_ = _make_agent(persona=bob)
        evt = _event("msg-1", event_type="BenignUserAction",
                      source_entity="janet.liu", target_entity="bob.smith")
        obs = agent._create_observation(evt)
        assert obs is not None
        assert obs.category == "message"
        assert obs.importance == 3.5

    def test_benign_message_not_targeting_self_is_none(self):
        """BenignUserAction targeting someone else -> None."""
        personas = _personas()
        bob = next(p for p in personas if p.id == "bob.smith")
        agent, *_ = _make_agent(persona=bob)
        evt = _event("msg-2", event_type="BenignUserAction",
                      source_entity="janet.liu", target_entity="dan.wu")
        obs = agent._create_observation(evt)
        assert obs is None

    def test_own_event_is_none(self):
        """Events from self -> None."""
        personas = _personas()
        bob = next(p for p in personas if p.id == "bob.smith")
        agent, *_ = _make_agent(persona=bob)
        evt = _event("own-1", actor="green", source_entity="bob.smith",
                      target_entity="svc-web")
        obs = agent._create_observation(evt)
        assert obs is None

    def test_routine_benign_event_is_none(self):
        """Routine benign event (not targeting NPC) -> None."""
        personas = _personas()
        bob = next(p for p in personas if p.id == "bob.smith")
        agent, *_ = _make_agent(persona=bob)
        evt = _event("routine-1", event_type="BenignUserAction",
                      source_entity="janet.liu", target_entity="svc-web")
        obs = agent._create_observation(evt)
        assert obs is None

    def test_observation_timestamp_uses_clock(self):
        """Observation timestamp should reflect sim_clock.now."""
        personas = _personas()
        bob = next(p for p in personas if p.id == "bob.smith")
        agent, _, _, clock, _ = _make_agent(persona=bob)
        clock.advance(42.5)
        evt = _event("ts-1", event_type="ServiceDegraded", target_entity="svc-web")
        obs = agent._create_observation(evt)
        assert obs.timestamp == 42.5

    def test_already_read_sender_is_none(self):
        """Second message from same sender (already in _read_from) -> None."""
        personas = _personas()
        bob = next(p for p in personas if p.id == "bob.smith")
        agent, *_ = _make_agent(persona=bob)
        agent._read_from.add("janet.liu")
        evt = _event("dup-sender", event_type="BenignUserAction",
                      source_entity="janet.liu", target_entity="bob.smith")
        obs = agent._create_observation(evt)
        assert obs is None


# ---------------------------------------------------------------------------
# Check propensity (personality-driven)
# ---------------------------------------------------------------------------


class TestCheckPropensity:
    def test_focused_diligent_terse_low_chattiness(self):
        """Bob-like persona: focused, diligent, terse, 0.3 chattiness -> low propensity."""
        persona = _persona_with_personality(
            mood="focused", work_ethic="diligent",
            interpersonal_style="terse", chattiness=0.3,
        )
        agent, *_ = _make_agent(persona=persona)
        prop = agent._check_propensity()
        expected = _CHECK_PROPENSITY_BASE + (-0.10) + (-0.15) + (-0.05) + 0.20 * 0.3
        assert prop == pytest.approx(max(0.05, expected), abs=0.001)
        assert prop < 0.15  # very unlikely to check

    def test_distracted_lazy_verbose_high_chattiness(self):
        """Maximally distractible persona -> high propensity."""
        persona = _persona_with_personality(
            mood="distracted", work_ethic="lazy",
            interpersonal_style="verbose", chattiness=1.0,
        )
        agent, *_ = _make_agent(persona=persona)
        prop = agent._check_propensity()
        expected = _CHECK_PROPENSITY_BASE + 0.30 + 0.20 + 0.10 + 0.20
        assert prop == pytest.approx(min(0.95, expected), abs=0.001)
        assert prop > 0.85

    def test_relaxed_average_casual_medium_chattiness(self):
        """Janet-like persona: relaxed, average, casual, 0.9 chattiness."""
        persona = _persona_with_personality(
            mood="relaxed", work_ethic="average",
            interpersonal_style="casual", chattiness=0.9,
        )
        agent, *_ = _make_agent(persona=persona)
        prop = agent._check_propensity()
        expected = _CHECK_PROPENSITY_BASE + 0.05 + 0.0 + 0.0 + 0.20 * 0.9
        assert prop == pytest.approx(expected, abs=0.001)
        assert 0.4 < prop < 0.6

    def test_propensity_clamped_low(self):
        """Propensity never goes below 0.05."""
        persona = _persona_with_personality(
            mood="focused", work_ethic="diligent",
            interpersonal_style="terse", chattiness=0.0,
        )
        agent, *_ = _make_agent(persona=persona)
        prop = agent._check_propensity()
        assert prop >= 0.05

    def test_propensity_clamped_high(self):
        """Propensity never exceeds 0.95."""
        persona = _persona_with_personality(
            mood="distracted", work_ethic="lazy",
            interpersonal_style="verbose", chattiness=1.0,
        )
        agent, *_ = _make_agent(persona=persona)
        prop = agent._check_propensity()
        assert prop <= 0.95

    def test_no_profile_uses_defaults(self):
        """Persona without profile uses safe defaults."""
        bare = GreenPersona(id="bare", role="Analyst", department="Data")
        agent, *_ = _make_agent(persona=bare)
        prop = agent._check_propensity()
        # defaults: focused, diligent, casual, 0.5 chattiness
        expected = _CHECK_PROPENSITY_BASE + (-0.10) + (-0.15) + 0.0 + 0.20 * 0.5
        assert prop == pytest.approx(max(0.05, expected), abs=0.001)

    def test_real_personas_propensity_range(self):
        """All default personas produce propensity in valid range."""
        for p in _personas():
            agent, *_ = _make_agent(persona=p)
            prop = agent._check_propensity()
            assert 0.05 <= prop <= 0.95, f"{p.id} propensity {prop} out of range"


# ---------------------------------------------------------------------------
# Should-check observations
# ---------------------------------------------------------------------------


class TestShouldCheckObservations:
    def test_empty_observations_returns_false(self):
        """No pending observations -> False regardless of personality."""
        persona = _persona_with_personality(
            mood="distracted", work_ethic="lazy", chattiness=1.0,
        )
        agent, *_ = _make_agent(persona=persona)
        assert not agent._should_check_observations()

    def test_between_tasks_forces_check(self):
        """_between_tasks flag forces observation check."""
        persona = _persona_with_personality(
            mood="focused", work_ethic="diligent", chattiness=0.0,
        )
        agent, _, inbox, clock, _ = _make_agent(persona=persona)
        clock.advance(0.0)
        # Add a pending observation
        evt = _event("msg-bt", event_type="BenignUserAction",
                      source_entity="janet.liu", target_entity=persona.id)
        inbox.push(evt)
        agent._process_inbox()
        assert len(agent._pending_observations) == 1
        # Without between_tasks: very unlikely (low propensity, no age)
        agent._between_tasks = True
        assert agent._should_check_observations()

    def test_age_boost_increases_probability(self):
        """Older observations boost check probability."""
        persona = _persona_with_personality(
            mood="focused", work_ethic="diligent", chattiness=0.0,
        )
        agent, _, inbox, clock, _ = _make_agent(persona=persona)
        clock.advance(0.0)
        evt = _event("msg-age", event_type="BenignUserAction",
                      source_entity="janet.liu", target_entity=persona.id)
        inbox.push(evt)
        agent._process_inbox()
        # Advance clock so observation is 60 minutes old -> max age_boost of 0.3
        clock.advance(60.0)
        # Even with low propensity (~0.06), age_boost 0.3 makes it ~0.36
        # Over many tries, should succeed at least once
        checks = sum(1 for _ in range(100)
                     if agent._should_check_observations())
        assert checks > 10  # should succeed ~36% of the time


# ---------------------------------------------------------------------------
# Security fast path
# ---------------------------------------------------------------------------


class TestSecurityFastPath:
    def test_detection_alert_immediate_reaction(self):
        """DetectionAlertRaised goes to security fast path for security persona."""
        personas = _personas()
        riley = next(p for p in personas if p.id == "riley.kim")
        agent, outbox, inbox, clock, _ = _make_agent(persona=riley)
        clock.advance(0.0)
        inbox.push(_event("sec-1", event_type="DetectionAlertRaised",
                          source_entity="svc-siem", target_entity="svc-web"))
        agent._process_inbox()
        # Should be in reaction queue, NOT in pending observations
        assert len(agent._pending_observations) == 0
        assert len(agent._reaction_queue) == 1
        agent._maybe_submit_next()
        actions = outbox.drain()
        assert len(actions) == 1
        assert actions[0].payload.get("branch") == "report_suspicious_activity"

    def test_suspicious_action_immediate(self):
        """SuspiciousActionObserved also fast-paths for security persona."""
        personas = _personas()
        riley = next(p for p in personas if p.id == "riley.kim")
        agent, outbox, inbox, clock, _ = _make_agent(persona=riley)
        clock.advance(0.0)
        inbox.push(_event("sec-2", event_type="SuspiciousActionObserved",
                          source_entity="svc-siem"))
        agent._process_inbox()
        assert len(agent._pending_observations) == 0
        assert len(agent._reaction_queue) == 1

    def test_service_degraded_is_deferred(self):
        """ServiceDegraded -> deferred as alert."""
        personas = _personas()
        bob = next(p for p in personas if p.id == "bob.smith")
        agent, outbox, inbox, clock, _ = _make_agent(persona=bob)
        clock.advance(0.0)
        inbox.push(_event("sec-3", event_type="ServiceDegraded",
                          target_entity="svc-web"))
        agent._process_inbox()
        assert len(agent._pending_observations) == 1
        assert agent._pending_observations[0].category == "alert"
        assert len(agent._reaction_queue) == 0

    def test_dedup_prevents_double_reaction(self):
        """Same event pushed twice -> only one reaction."""
        personas = _personas()
        riley = next(p for p in personas if p.id == "riley.kim")
        agent, outbox, inbox, clock, _ = _make_agent(persona=riley)
        clock.advance(0.0)
        evt = _event("dup-sec", event_type="DetectionAlertRaised",
                      source_entity="svc-siem", target_entity="svc-web")
        inbox.push(evt)
        agent._process_inbox()
        agent._maybe_submit_next()
        outbox.drain()
        # Push again
        inbox.push(evt)
        agent._process_inbox()
        agent._maybe_submit_next()
        assert len(outbox.drain()) == 0


# ---------------------------------------------------------------------------
# Between-task batch checking
# ---------------------------------------------------------------------------


class TestBetweenTaskBatchCheck:
    def test_task_completion_sets_between_tasks(self):
        """Submitting a task sets _between_tasks for next tick."""
        personas = _personas()
        bob = next(p for p in personas if p.id == "bob.smith")
        task = NPCTask("Browse portal", "browse", "/", "Checking", 0, 15)
        agent, outbox, _, clock, _ = _make_agent(persona=bob, tasks=[task])
        clock.advance(0.0)
        assert not agent._between_tasks
        agent._maybe_submit_next()
        assert len(outbox.drain()) == 1
        assert agent._between_tasks

    def test_between_tasks_processes_pending_message(self):
        """Focused NPC checks messages between tasks via _between_tasks flag."""
        # Use a maximally focused persona so propensity alone never triggers
        focused = _persona_with_personality(
            mood="focused", work_ethic="diligent",
            interpersonal_style="terse", chattiness=0.0,
        )
        ms = MessageStore()
        ms.deliver("janet.liu", focused.id, "Update", "Please review.", modality="email")
        task = NPCTask("Browse portal", "browse", "/", "Checking", 0, 15)
        agent, outbox, inbox, clock, _ = _make_agent(
            persona=focused, tasks=[task], mail_store=ms,
        )
        clock.advance(0.0)

        # Message arrives
        inbox.push(_event("bt-msg", source_entity="janet.liu", target_entity=focused.id))
        agent._process_inbox()
        assert len(agent._pending_observations) == 1

        # Submit browse task -> sets _between_tasks
        agent._maybe_submit_next()
        outbox.drain()
        assert agent._between_tasks

        # Next submit should check observations (forced by _between_tasks)
        agent._maybe_submit_next()
        actions = outbox.drain()
        assert len(actions) == 1
        assert actions[0].payload["routine"] == "read_mail"

    def test_between_tasks_cleared_after_processing(self):
        """_between_tasks is cleared after observation processing."""
        personas = _personas()
        bob = next(p for p in personas if p.id == "bob.smith")
        agent, outbox, inbox, clock, _ = _make_agent(persona=bob, tasks=[])
        clock.advance(0.0)
        agent._between_tasks = True
        # No pending observations, but _process_pending_observations clears the flag
        agent._process_pending_observations()
        assert not agent._between_tasks


# ---------------------------------------------------------------------------
# Done property
# ---------------------------------------------------------------------------


class TestDoneProperty:
    def test_done_accounts_for_pending_observations(self):
        """Agent is not done while observations are pending."""
        personas = _personas()
        bob = next(p for p in personas if p.id == "bob.smith")
        agent, _, inbox, clock, _ = _make_agent(persona=bob, tasks=[])
        clock.advance(0.0)
        assert agent.done  # no tasks, no observations
        inbox.push(_event("done-1", source_entity="janet.liu", target_entity="bob.smith"))
        agent._process_inbox()
        assert not agent.done  # has pending observation
        agent._process_pending_observations()
        # Now has reaction queue items
        assert not agent.done


# ---------------------------------------------------------------------------
# Process pending observations
# ---------------------------------------------------------------------------


class TestProcessPendingObservations:
    def test_message_observation_produces_read_and_reply(self):
        """Processing a message observation generates read_mail + reply actions."""
        personas = _personas()
        bob = next(p for p in personas if p.id == "bob.smith")
        ms = MessageStore()
        ms.deliver("janet.liu", "bob.smith", "Q1 Report", "Please review.", modality="email")
        agent, outbox, inbox, clock, _ = _make_agent(
            persona=bob, tasks=[], mail_store=ms,
        )
        clock.advance(0.0)
        inbox.push(_event("proc-1", source_entity="janet.liu", target_entity="bob.smith"))
        agent._process_inbox()
        assert len(agent._pending_observations) == 1
        agent._process_pending_observations()
        assert len(agent._pending_observations) == 0
        assert len(agent._reaction_queue) == 2  # read + reply

    def test_alert_observation_produces_reaction(self):
        """Processing a ServiceDegraded alert produces a reaction."""
        personas = _personas()
        bob = next(p for p in personas if p.id == "bob.smith")
        agent, outbox, inbox, clock, _ = _make_agent(persona=bob, tasks=[])
        clock.advance(0.0)
        inbox.push(_event("proc-2", event_type="ServiceDegraded",
                          target_entity="svc-web"))
        agent._process_inbox()
        assert len(agent._pending_observations) == 1
        agent._process_pending_observations()
        assert len(agent._reaction_queue) >= 1

    def test_already_reacted_observations_skipped(self):
        """Observations for already-reacted events are dropped."""
        personas = _personas()
        bob = next(p for p in personas if p.id == "bob.smith")
        agent, _, inbox, clock, _ = _make_agent(persona=bob, tasks=[])
        clock.advance(0.0)
        inbox.push(_event("proc-3", source_entity="janet.liu", target_entity="bob.smith"))
        agent._process_inbox()
        agent._reacted_event_ids.add("proc-3")
        agent._process_pending_observations()
        assert len(agent._pending_observations) == 0
        assert len(agent._reaction_queue) == 0


# ---------------------------------------------------------------------------
# Async parity
# ---------------------------------------------------------------------------


class TestAsyncParity:
    def test_async_inbox_defers_messages(self):
        """Async inbox processing also defers messages."""
        personas = _personas()
        bob = next(p for p in personas if p.id == "bob.smith")
        ms = MessageStore()
        ms.deliver("janet.liu", "bob.smith", "Async test", "Body.", modality="email")
        agent, outbox, inbox, clock, _ = _make_agent(
            persona=bob, tasks=[], mail_store=ms,
        )
        clock.advance(0.0)
        inbox.push(_event("async-1", source_entity="janet.liu", target_entity="bob.smith"))

        async def _go():
            await agent._process_inbox_async()

        asyncio.run(_go())
        assert len(agent._pending_observations) == 1
        assert len(agent._reaction_queue) == 0

    def test_async_security_is_immediate(self):
        """Async path also fast-tracks detection alerts for security persona."""
        personas = _personas()
        riley = next(p for p in personas if p.id == "riley.kim")
        agent, outbox, inbox, clock, _ = _make_agent(persona=riley, tasks=[])
        clock.advance(0.0)
        inbox.push(_event("async-sec", event_type="DetectionAlertRaised",
                          source_entity="svc-siem", target_entity="svc-web"))

        async def _go():
            await agent._process_inbox_async()

        asyncio.run(_go())
        assert len(agent._pending_observations) == 0
        assert len(agent._reaction_queue) == 1

    def test_async_process_pending_produces_same_result(self):
        """Async observation processing produces same actions as sync."""
        personas = _personas()
        bob = next(p for p in personas if p.id == "bob.smith")

        def _run_sync():
            ms = MessageStore()
            ms.deliver("janet.liu", "bob.smith", "Test", "Body.", modality="email")
            agent, outbox, inbox, clock, _ = _make_agent(
                persona=bob, tasks=[], mail_store=ms,
            )
            clock.advance(0.0)
            inbox.push(_event("parity-s", source_entity="janet.liu", target_entity="bob.smith"))
            agent._process_inbox()
            agent._process_pending_observations()
            return len(agent._reaction_queue)

        def _run_async():
            ms = MessageStore()
            ms.deliver("janet.liu", "bob.smith", "Test", "Body.", modality="email")
            agent, outbox, inbox, clock, _ = _make_agent(
                persona=bob, tasks=[], mail_store=ms,
            )
            clock.advance(0.0)
            inbox.push(_event("parity-a", source_entity="janet.liu", target_entity="bob.smith"))

            async def _go():
                await agent._process_inbox_async()
                await agent._process_pending_observations_async()

            asyncio.run(_go())
            return len(agent._reaction_queue)

        assert _run_sync() == _run_async()


# ---------------------------------------------------------------------------
# Determinism
# ---------------------------------------------------------------------------


class TestDeterminism:
    def test_same_seed_same_check_decisions(self):
        """Two agents with same persona produce identical check decisions."""
        personas = _personas()
        bob = next(p for p in personas if p.id == "bob.smith")

        def _run():
            agent, _, inbox, clock, _ = _make_agent(persona=bob, tasks=[])
            clock.advance(0.0)
            inbox.push(_event("det-1", source_entity="janet.liu", target_entity="bob.smith"))
            agent._process_inbox()
            results = []
            for i in range(20):
                results.append(agent._should_check_observations())
            return results

        assert _run() == _run()
