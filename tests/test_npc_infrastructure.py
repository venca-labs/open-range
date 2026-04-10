"""Tests for Phase 1 NPC infrastructure: identity models, outbox/inbox, sim clock."""

from __future__ import annotations

import threading
import time

import pytest

from open_range.builder.npc.identity import NPCBackstory, NPCPersonality, NPCProfile
from open_range.builder.npc.memory import MemoryStream
from open_range.builder.npc.outbox import ActionOutbox, EventInbox, SimClock
from open_range.episode_config import EpisodeConfig
from open_range.runtime_types import Action, RuntimeEvent
from open_range.world_ir import GreenPersona


# ---------------------------------------------------------------------------
# Identity models
# ---------------------------------------------------------------------------


class TestNPCIdentityModels:
    def test_backstory_defaults(self):
        b = NPCBackstory()
        assert b.background == ""
        assert b.full_name == ""
        assert b.years_at_company == 2
        assert b.friends == ()
        assert b.projects == ()

    def test_backstory_with_values(self):
        b = NPCBackstory(
            full_name="Janet Liu",
            location="San Francisco office",
            working_hours="9am-5pm PT",
            work_style="Creative and big-picture",
            communication_style="Friendly and informal",
            projects=("Q1 campaign", "Brand refresh"),
            responsibilities="Social media and ad spend",
            friends=("dan.wu",),
            background="Joined 2 years ago, quickly became go-to for social media.",
            years_at_company=2,
        )
        assert b.full_name == "Janet Liu"
        assert len(b.projects) == 2
        assert "dan.wu" in b.friends
        assert b.years_at_company == 2

    def test_backstory_is_frozen(self):
        b = NPCBackstory()
        with pytest.raises(Exception):
            b.background = "changed"

    def test_personality_defaults(self):
        p = NPCPersonality()
        assert p.mood == "focused"
        assert p.disposition == "cooperative"
        assert 0.0 <= p.risk_tolerance <= 1.0

    def test_personality_risk_bounds(self):
        with pytest.raises(Exception):
            NPCPersonality(risk_tolerance=1.5)
        with pytest.raises(Exception):
            NPCPersonality(risk_tolerance=-0.1)

    def test_personality_is_frozen(self):
        p = NPCPersonality()
        with pytest.raises(Exception):
            p.mood = "changed"

    def test_profile_aggregates(self):
        profile = NPCProfile(
            backstory=NPCBackstory(background="Test bio"),
            personality=NPCPersonality(mood="anxious"),
        )
        assert profile.backstory.background == "Test bio"
        assert profile.personality.mood == "anxious"

    def test_profile_defaults(self):
        profile = NPCProfile()
        assert profile.backstory.background == ""
        assert profile.personality.mood == "focused"

    def test_green_persona_profile_none_by_default(self):
        p = GreenPersona(id="test", role="IT")
        assert p.profile is None

    def test_green_persona_with_profile(self):
        profile = NPCProfile(
            backstory=NPCBackstory(background="Test"),
            personality=NPCPersonality(disposition="cautious"),
        )
        p = GreenPersona(id="test", role="IT", profile=profile)
        assert p.profile is not None
        assert p.profile.personality.disposition == "cautious"

    def test_green_persona_backward_compatible(self):
        """Existing construction patterns still work."""
        p = GreenPersona(
            id="janet.liu",
            role="Marketing Coordinator",
            department="Marketing",
            home_host="siem",
            mailbox="janet.liu@corp.local",
            awareness=0.4,
            susceptibility={"phishing_email": 0.6},
            routine=("browse_app", "send_mail"),
        )
        assert p.profile is None
        assert p.awareness == 0.4


# ---------------------------------------------------------------------------
# ActionOutbox
# ---------------------------------------------------------------------------


def _action(actor: str = "green-1") -> Action:
    return Action(actor_id=actor, role="green", kind="api", payload={"test": True})


class TestActionOutbox:
    def test_submit_and_drain(self):
        ob = ActionOutbox()
        ob.submit(_action("a"))
        ob.submit(_action("b"))
        actions = ob.drain()
        assert len(actions) == 2
        assert actions[0].actor_id == "a"
        assert actions[1].actor_id == "b"

    def test_drain_empties_queue(self):
        ob = ActionOutbox()
        ob.submit(_action())
        ob.drain()
        assert ob.drain() == ()

    def test_len(self):
        ob = ActionOutbox()
        assert len(ob) == 0
        ob.submit(_action())
        assert len(ob) == 1
        ob.drain()
        assert len(ob) == 0

    def test_max_size_evicts_oldest(self):
        ob = ActionOutbox(max_size=3)
        for i in range(5):
            ob.submit(_action(f"a{i}"))
        assert len(ob) == 3
        actions = ob.drain()
        # deque(maxlen=3) keeps the last 3
        assert [a.actor_id for a in actions] == ["a2", "a3", "a4"]

    def test_concurrent_submit_is_safe(self):
        ob = ActionOutbox(max_size=500)
        errors = []

        def writer(n):
            try:
                for i in range(100):
                    ob.submit(_action(f"t{n}-{i}"))
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=writer, args=(i,)) for i in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors
        actions = ob.drain()
        assert len(actions) == 400


# ---------------------------------------------------------------------------
# EventInbox
# ---------------------------------------------------------------------------


def _event(eid: str = "e1", malicious: bool = True) -> RuntimeEvent:
    return RuntimeEvent(
        id=eid, event_type="InitialAccess", actor="red",
        source_entity="attacker", target_entity="svc-web",
        time=1.0, malicious=malicious, observability_surfaces=("svc-web",),
    )


class TestEventInbox:
    def test_push_and_poll(self):
        inbox = EventInbox()
        inbox.push(_event("e1"))
        inbox.push(_event("e2"))
        events = inbox.poll()
        assert len(events) == 2
        assert events[0].id == "e1"

    def test_poll_empties(self):
        inbox = EventInbox()
        inbox.push(_event())
        inbox.poll()
        assert inbox.poll() == ()

    def test_len(self):
        inbox = EventInbox()
        assert len(inbox) == 0
        inbox.push(_event())
        assert len(inbox) == 1

    def test_max_size_evicts_oldest(self):
        inbox = EventInbox(max_size=2)
        inbox.push(_event("e1"))
        inbox.push(_event("e2"))
        inbox.push(_event("e3"))
        events = inbox.poll()
        assert len(events) == 2
        assert events[0].id == "e2"

    def test_concurrent_push_is_safe(self):
        inbox = EventInbox()
        errors = []

        def pusher(n):
            try:
                for i in range(50):
                    inbox.push(_event(f"t{n}-{i}"))
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=pusher, args=(i,)) for i in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors
        assert len(inbox.poll()) == 200


# ---------------------------------------------------------------------------
# SimClock
# ---------------------------------------------------------------------------


class TestSimClock:
    def test_initial_time_is_zero(self):
        clock = SimClock()
        assert clock.now == 0.0

    def test_advance(self):
        clock = SimClock()
        clock.advance(5.0)
        assert clock.now == 5.0
        clock.advance(10.5)
        assert clock.now == 10.5

    def test_reset(self):
        clock = SimClock()
        clock.advance(99.0)
        clock.reset()
        assert clock.now == 0.0

    def test_concurrent_reads_safe(self):
        clock = SimClock()
        clock.advance(42.0)
        results = []

        def reader():
            for _ in range(100):
                results.append(clock.now)

        threads = [threading.Thread(target=reader) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert all(r == 42.0 for r in results)


# ---------------------------------------------------------------------------
# MemoryStream thread safety
# ---------------------------------------------------------------------------


class TestMemoryStreamThreadSafety:
    def test_concurrent_add_and_retrieve(self):
        ms = MemoryStream()
        errors = []

        def writer(n):
            try:
                for i in range(50):
                    ms.add(f"subj-{n}", f"rel-{i}", f"obj-{n}-{i}",
                           importance=3.0, tags=["test"])
            except Exception as e:
                errors.append(e)

        def reader():
            try:
                for _ in range(50):
                    ms.retrieve(["test"], top_k=3)
                    ms.recent(3)
            except Exception as e:
                errors.append(e)

        threads = (
            [threading.Thread(target=writer, args=(i,)) for i in range(3)]
            + [threading.Thread(target=reader) for _ in range(2)]
        )
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors
        assert len(ms) == 150  # 3 writers × 50 each

    def test_concurrent_add_respects_max_size(self):
        ms = MemoryStream(max_size=20)
        errors = []

        def writer(n):
            try:
                for i in range(30):
                    ms.add(f"s{n}", f"r{i}", f"o{n}{i}", importance=float(i % 10 + 1))
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=writer, args=(i,)) for i in range(3)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors
        assert len(ms) <= 20


# ---------------------------------------------------------------------------
# EpisodeConfig npc_mode
# ---------------------------------------------------------------------------


class TestEpisodeConfigNPCMode:
    def test_default_is_offline(self):
        cfg = EpisodeConfig()
        assert cfg.npc_mode == "offline"

    def test_online_mode(self):
        cfg = EpisodeConfig(npc_mode="online")
        assert cfg.npc_mode == "online"

    def test_invalid_mode_rejected(self):
        with pytest.raises(Exception):
            EpisodeConfig(npc_mode="invalid")

    def test_existing_configs_unchanged(self):
        """Existing EpisodeConfig construction patterns still work."""
        cfg = EpisodeConfig(
            mode="joint_pool",
            green_enabled=True,
            green_branch_backend="scripted",
        )
        assert cfg.npc_mode == "offline"
        assert cfg.green_enabled is True
