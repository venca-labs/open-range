"""Integration tests for ScriptedGreenScheduler + MemoryStream/DailyPlanner wiring.

Covers the green scheduler integration (issue #111):
  - MemoryStream is initialised per persona on reset()
  - DailyPlanner template schedule is initialised per persona on reset()
  - record_event() stores malicious events in the observer's MemoryStream
  - _susceptibility_score() is reduced by prior incident memories
  - _routine_actions() uses DailyPlanner schedule hints for action type
  - Mail routine actions include npc_chat branch and recipient fields
  - runtime_events.green_events_for_action() handles npc_chat branch
  - execution._mail_command() uses recipient payload field
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock

import pytest

from open_range.builder.npc.memory import MemoryStream
from open_range.builder.npc.planner import DailyPlanner
from open_range.episode_config import EpisodeConfig
from open_range.green import ScriptedGreenScheduler, _planner_hint_for_slot, _planner_action_to_routine
from open_range.runtime_events import green_events_for_action
from open_range.runtime_types import Action, RuntimeEvent
from open_range.world_ir import GreenPersona


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_persona(
    id_: str = "janet.liu",
    role: str = "Marketing Coordinator",
    awareness: float = 0.5,
    susceptibility: dict | None = None,
    routine: tuple = ("browse_app", "send_mail", "browse_app", "browse_app"),
) -> GreenPersona:
    return GreenPersona(
        id=id_,
        role=role,
        department="Marketing",
        home_host="siem",
        mailbox=f"{id_}@corp.local",
        awareness=awareness,
        susceptibility=susceptibility or {"phishing_email": 0.6},
        routine=routine,
    )


def _make_snapshot(personas: list[GreenPersona] | None = None) -> Any:
    """Minimal snapshot stub accepted by ScriptedGreenScheduler.reset()."""
    if personas is None:
        personas = [
            _make_persona("janet.liu", awareness=0.4),
            _make_persona("bob.smith", role="IT Administrator", awareness=0.8),
        ]

    class _World:
        green_personas = personas
        green_workload = SimpleNamespace(
            routine_interval_ticks=1,
            max_parallel_actions=4,
            reactive_branch_budget=2,
        )
        seed = 42

    class _Snapshot:
        world = _World()

    return _Snapshot()


_EVENT_ID = 0


def _make_event(
    event_type: str = "InitialAccess",
    source_entity: str = "red",
    target_entity: str = "svc-web",
    time: float = 1.0,
    malicious: bool = True,
) -> RuntimeEvent:
    global _EVENT_ID
    _EVENT_ID += 1
    return RuntimeEvent(
        id=f"evt-{_EVENT_ID}",
        event_type=event_type,
        actor="red",
        source_entity=source_entity,
        target_entity=target_entity,
        time=time,
        malicious=malicious,
        observability_surfaces=("svc-web",),
    )


def _make_scheduler(snapshot=None, backend: str = "scripted") -> ScriptedGreenScheduler:
    cfg = EpisodeConfig(green_branch_backend=backend)
    snap = snapshot or _make_snapshot()
    sched = ScriptedGreenScheduler()
    sched.reset(snap, cfg)
    return sched


# ---------------------------------------------------------------------------
# MemoryStream / DailyPlanner initialisation
# ---------------------------------------------------------------------------


class TestSchedulerInitialisation:
    def test_memory_streams_created_per_persona(self):
        sched = _make_scheduler()
        assert "janet.liu" in sched._memory_streams
        assert "bob.smith" in sched._memory_streams
        assert all(isinstance(ms, MemoryStream) for ms in sched._memory_streams.values())

    def test_planners_created_per_persona(self):
        sched = _make_scheduler()
        assert "janet.liu" in sched._planners
        assert "bob.smith" in sched._planners
        assert all(isinstance(p, DailyPlanner) for p in sched._planners.values())

    def test_planner_schedule_populated_from_template(self):
        sched = _make_scheduler()
        for planner in sched._planners.values():
            assert len(planner._schedule) >= 6

    def test_memory_streams_cleared_on_re_reset(self):
        snap = _make_snapshot()
        cfg = EpisodeConfig()
        sched = ScriptedGreenScheduler()
        sched.reset(snap, cfg)
        # Seed a memory, then reset again
        sched._memory_streams["janet.liu"].add("a", "b", "c", importance=5.0)
        sched.reset(snap, cfg)
        assert len(sched._memory_streams["janet.liu"]) == 0


# ---------------------------------------------------------------------------
# record_event() → MemoryStream
# ---------------------------------------------------------------------------


class TestRecordEventMemory:
    def test_malicious_event_recorded_in_observer_memory(self):
        sched = _make_scheduler()
        event = _make_event("InitialAccess", source_entity="attacker", target_entity="svc-web")
        sched.record_event(event)

        # Observer is the highest-awareness persona (bob.smith, 0.8)
        ms = sched._memory_streams["bob.smith"]
        assert len(ms) == 1
        entry = ms._memories[0]
        assert entry.subject == "attacker"
        assert "initial_access" in entry.relation
        assert entry.object_ == "svc-web"
        assert "malicious" in entry.tags
        assert "security" in entry.tags

    def test_high_severity_event_gets_high_importance(self):
        sched = _make_scheduler()
        sched.record_event(_make_event("CredentialObtained"))
        ms = sched._memory_streams["bob.smith"]
        assert ms._memories[0].importance == 8.0

    def test_low_severity_event_gets_medium_importance(self):
        sched = _make_scheduler()
        sched.record_event(_make_event("CrossZoneTraversal"))
        ms = sched._memory_streams["bob.smith"]
        assert ms._memories[0].importance == 5.0

    def test_benign_event_not_recorded(self):
        sched = _make_scheduler()
        event = _make_event("BenignUserAction", malicious=False)
        sched.record_event(event)
        # No memory should be stored for a benign event (record_event exits early)
        ms = sched._memory_streams["bob.smith"]
        assert len(ms) == 0


# ---------------------------------------------------------------------------
# _susceptibility_score() memory-adjusted
# ---------------------------------------------------------------------------


class TestSusceptibilityScore:
    def test_base_score_without_memory(self):
        sched = _make_scheduler()
        persona = _make_persona("janet.liu", susceptibility={"initial_access": 0.6})
        event = _make_event("InitialAccess")
        # No memories yet — base score returned
        score = sched._susceptibility_score(persona, event)
        assert score == pytest.approx(0.6)

    def test_score_reduced_by_prior_incidents(self):
        sched = _make_scheduler()
        persona = _make_persona("janet.liu", susceptibility={"initial_access": 0.6})
        event = _make_event("InitialAccess")
        # Seed three prior security memories
        ms = sched._memory_streams["janet.liu"]
        for _ in range(3):
            ms.add("red", "initial_access", "svc-web", importance=8.0,
                   tags=["initial_access", "malicious", "security"])
        score = sched._susceptibility_score(persona, event)
        # Three memories → 0.15 max reduction → 0.6 - 0.15 = 0.45
        assert score == pytest.approx(0.45)

    def test_score_never_below_zero(self):
        sched = _make_scheduler()
        persona = _make_persona("janet.liu", susceptibility={"initial_access": 0.1})
        event = _make_event("InitialAccess")
        ms = sched._memory_streams["janet.liu"]
        for _ in range(5):
            ms.add("red", "initial_access", "svc-web", importance=8.0,
                   tags=["initial_access", "malicious", "security"])
        score = sched._susceptibility_score(persona, event)
        assert score >= 0.0


# ---------------------------------------------------------------------------
# _routine_actions() planner hint usage
# ---------------------------------------------------------------------------


class TestRoutineActionsPlanner:
    def test_routine_actions_generated_at_slot_0(self):
        sched = _make_scheduler()
        sched.advance_until(0.0)
        actions = sched.pop_ready_actions()
        assert len(actions) >= 1
        assert all(a.role == "green" for a in actions)

    def test_mail_action_gets_npc_chat_branch(self):
        """When a persona's schedule has a send_email action, the mail action
        should carry branch='npc_chat' and a recipient field."""
        # Force planner schedule to only have send_email at hour 9
        from open_range.builder.npc.planner import ScheduledAction
        personas = [
            _make_persona("janet.liu", routine=("send_mail",)),
            _make_persona("bob.smith", routine=("browse_app",)),
        ]
        snap = _make_snapshot(personas)
        sched = _make_scheduler(snap)
        # Override planner to return send_email at slot 0
        sched._planners["janet.liu"]._schedule = [
            ScheduledAction(hour=9, action="send_email", target="", detail="")
        ]

        sched.advance_until(0.0)
        actions = sched.pop_ready_actions()
        mail_actions = [a for a in actions if a.kind == "mail"]
        assert len(mail_actions) >= 1
        mail = mail_actions[0]
        assert mail.payload.get("branch") == "npc_chat"
        assert "recipient" in mail.payload
        # recipient should be the other persona
        assert mail.payload["recipient"] == "bob.smith"

    def test_planner_hint_for_slot_maps_hours(self):
        from open_range.builder.npc.planner import ScheduledAction
        planner = DailyPlanner(model=None)
        planner._schedule = [
            ScheduledAction(9, "login", "/admin", "Morning check"),
            ScheduledAction(12, "idle", "", "Lunch"),
            ScheduledAction(14, "query_db", "", "Afternoon"),
        ]
        # slot 0 → hour 9 → login
        assert _planner_hint_for_slot(planner, 0).action == "login"
        # slot 180 → hour 12 → idle
        assert _planner_hint_for_slot(planner, 180).action == "idle"
        # slot 300 → hour 14 → query_db
        assert _planner_hint_for_slot(planner, 300).action == "query_db"
        # slot before any action
        planner._schedule = [ScheduledAction(10, "browse", "/", "")]
        assert _planner_hint_for_slot(planner, 0) is None

    def test_planner_action_to_routine_mapping(self):
        assert _planner_action_to_routine("browse") == "browse_app"
        assert _planner_action_to_routine("send_email") == "send_mail"
        assert _planner_action_to_routine("access_share") == "access_share"
        assert _planner_action_to_routine("query_db") == "query_db"
        assert _planner_action_to_routine("unknown_action") == "browse_app"


# ---------------------------------------------------------------------------
# Routine actions → MemoryStream recording
# ---------------------------------------------------------------------------


class TestRoutineMemoryRecording:
    def test_browse_action_recorded_in_memory(self):
        sched = _make_scheduler()
        sched.advance_until(0.0)
        sched.pop_ready_actions()
        # Both personas acted at slot 0 — each should have a memory
        for pid in ("janet.liu", "bob.smith"):
            ms = sched._memory_streams[pid]
            assert len(ms) >= 1
            entry = ms._memories[0]
            assert entry.subject == pid
            assert "routine" in entry.tags

    def test_send_mail_records_sent_memory(self):
        from open_range.builder.npc.planner import ScheduledAction
        personas = [
            _make_persona("janet.liu", routine=("send_mail",)),
            _make_persona("bob.smith", routine=("browse_app",)),
        ]
        snap = _make_snapshot(personas)
        sched = _make_scheduler(snap)
        sched._planners["janet.liu"]._schedule = [
            ScheduledAction(hour=9, action="send_email", target="", detail="")
        ]
        sched.advance_until(0.0)
        sched.pop_ready_actions()

        ms = sched._memory_streams["janet.liu"]
        sent = [m for m in ms._memories if "sent" in m.tags]
        assert len(sent) >= 1
        assert sent[0].relation == "sent_mail_to"
        assert sent[0].object_ == "bob.smith"

    def test_read_mail_records_read_memory(self):
        from open_range.builder.npc.planner import ScheduledAction
        personas = [
            _make_persona("janet.liu", routine=("send_mail",)),
            _make_persona("bob.smith", routine=("browse_app",)),
        ]
        snap = _make_snapshot(personas)
        sched = _make_scheduler(snap)
        sched._planners["janet.liu"]._schedule = [
            ScheduledAction(hour=9, action="send_email", target="", detail="")
        ]
        # Slot 0: janet sends to bob → queues mail in bob's inbox
        sched.advance_until(0.0)
        sched.pop_ready_actions()
        assert "bob.smith" in sched._pending_inbox
        assert len(sched._pending_inbox["bob.smith"]) >= 1

        # Force bob to be due next slot so he reads his mail
        sched._next_action_slot["bob.smith"] = 1
        sched.advance_until(1.0)
        actions = sched.pop_ready_actions()
        read_actions = [a for a in actions if a.payload.get("routine") == "read_mail"]
        assert len(read_actions) >= 1
        assert read_actions[0].payload["recipient"] == "janet.liu"

        # Bob's memory should contain a read_mail_from entry
        ms = sched._memory_streams["bob.smith"]
        reads = [m for m in ms._memories if "read" in m.tags]
        assert len(reads) >= 1
        assert reads[0].relation == "read_mail_from"
        assert reads[0].object_ == "janet.liu"

    def test_recipient_selection_avoids_recent_contacts(self):
        """Memory-aware recipient pick prefers colleagues not recently emailed."""
        from open_range.builder.npc.planner import ScheduledAction
        personas = [
            _make_persona("janet.liu", routine=("send_mail",)),
            _make_persona("bob.smith", routine=("browse_app",)),
            _make_persona("carol.jones", routine=("browse_app",),
                          awareness=0.7,
                          susceptibility={"phishing_email": 0.3}),
        ]
        snap = _make_snapshot(personas)
        sched = _make_scheduler(snap)
        sched._planners["janet.liu"]._schedule = [
            ScheduledAction(hour=9, action="send_email", target="", detail="")
        ]
        # Seed memory: janet recently emailed bob
        ms = sched._memory_streams["janet.liu"]
        ms.add("janet.liu", "sent_mail_to", "bob.smith", importance=3.0,
               tags=["routine", "mail", "sent"])

        sched.advance_until(0.0)
        actions = sched.pop_ready_actions()
        mail = [a for a in actions if a.kind == "mail" and a.actor_id == "janet.liu"]
        assert len(mail) >= 1
        # Should pick carol (not recently emailed), not bob
        assert mail[0].payload["recipient"] == "carol.jones"


# ---------------------------------------------------------------------------
# runtime_events: npc_chat branch
# ---------------------------------------------------------------------------


class TestRuntimeEventsNpcChat:
    _emit_counter = 0

    def _emit(self, **kwargs) -> RuntimeEvent:
        TestRuntimeEventsNpcChat._emit_counter += 1
        return RuntimeEvent(
            id=f"test-{TestRuntimeEventsNpcChat._emit_counter}",
            event_type=kwargs["event_type"],
            actor=kwargs.get("actor", "green"),
            source_entity=kwargs.get("source_entity", "janet.liu"),
            target_entity=kwargs.get("target_entity", "svc-email"),
            time=0.0,
            malicious=kwargs.get("malicious", False),
            observability_surfaces=kwargs.get("observability_surfaces", ()),
        )

    def test_npc_chat_branch_emits_benign_user_action(self):
        action = Action(
            actor_id="janet.liu",
            role="green",
            kind="mail",
            payload={
                "branch": "npc_chat",
                "recipient": "bob.smith",
                "service": "svc-email",
            },
        )
        events = green_events_for_action(
            action,
            live_recovery_applied=False,
            target="svc-email",
            emit_event=self._emit,
            service_surfaces=lambda t: (t,),
        )
        assert len(events) == 1
        assert events[0].event_type == "BenignUserAction"
        assert events[0].source_entity == "janet.liu"
        assert events[0].target_entity == "bob.smith"
        assert "svc-email" in events[0].observability_surfaces

    def test_npc_chat_branch_falls_back_to_target_when_no_recipient(self):
        action = Action(
            actor_id="janet.liu",
            role="green",
            kind="mail",
            payload={"branch": "npc_chat"},
        )
        events = green_events_for_action(
            action,
            live_recovery_applied=False,
            target="svc-email",
            emit_event=self._emit,
            service_surfaces=lambda t: (t,),
        )
        assert events[0].target_entity == "svc-email"


# ---------------------------------------------------------------------------
# Async-to-sync bridge: outbox, inbox, sim clock
# ---------------------------------------------------------------------------


class TestActionOutboxBridge:
    """Actions submitted to the outbox appear in pop_ready_actions()."""

    def test_outbox_actions_included_in_pop(self):
        from open_range.builder.npc.outbox import ActionOutbox, SimClock

        outbox = ActionOutbox()
        clock = SimClock()
        sched = ScriptedGreenScheduler(action_outbox=outbox, sim_clock=clock)
        sched.reset(_make_snapshot(), EpisodeConfig())

        # Submit an action from "outside" (as an async agent would)
        external = Action(
            actor_id="janet.liu", role="green", kind="api",
            payload={"routine": "browse_app", "service": "svc-web"},
        )
        outbox.submit(external)

        actions = sched.pop_ready_actions()
        assert external in actions

    def test_outbox_drained_on_each_pop(self):
        from open_range.builder.npc.outbox import ActionOutbox

        outbox = ActionOutbox()
        sched = ScriptedGreenScheduler(action_outbox=outbox)
        sched.reset(_make_snapshot(), EpisodeConfig())

        outbox.submit(Action(
            actor_id="bob.smith", role="green", kind="api", payload={},
        ))
        sched.pop_ready_actions()
        # Second pop should not re-deliver the same action
        assert len(sched.pop_ready_actions()) == 0

    def test_outbox_actions_mixed_with_routine(self):
        from open_range.builder.npc.outbox import ActionOutbox

        outbox = ActionOutbox()
        sched = ScriptedGreenScheduler(action_outbox=outbox)
        sched.reset(_make_snapshot(), EpisodeConfig())

        # Advance to fire routine actions at slot 0
        sched.advance_until(0.0)
        # Also submit an external action
        external = Action(
            actor_id="external-agent", role="green", kind="shell",
            payload={"command": "echo hello"},
        )
        outbox.submit(external)

        actions = sched.pop_ready_actions()
        actor_ids = {a.actor_id for a in actions}
        # Should include both routine personas and the external action
        assert "external-agent" in actor_ids
        assert len(actions) >= 2  # at least 1 routine + 1 external


class TestEventInboxBridge:
    """Events pushed by record_event() reach per-NPC inboxes."""

    def test_malicious_event_reaches_all_inboxes(self):
        sched = _make_scheduler()
        event = _make_event("InitialAccess")
        sched.record_event(event)

        for pid in ("janet.liu", "bob.smith"):
            inbox = sched._event_inboxes[pid]
            events = inbox.poll()
            assert len(events) == 1
            assert events[0].id == event.id

    def test_benign_event_targeting_persona_reaches_only_that_inbox(self):
        """A benign event targeting a specific NPC only reaches that NPC."""
        sched = _make_scheduler()
        event = _make_event("BenignUserAction", malicious=False,
                            target_entity="janet.liu")
        sched.record_event(event)

        janet_events = sched._event_inboxes["janet.liu"].poll()
        bob_events = sched._event_inboxes["bob.smith"].poll()
        assert len(janet_events) == 1
        assert len(bob_events) == 0

    def test_benign_service_event_reaches_no_inbox(self):
        """A benign event targeting a service doesn't reach any NPC inbox."""
        sched = _make_scheduler()
        event = _make_event("BenignUserAction", malicious=False,
                            target_entity="svc-web")
        sched.record_event(event)

        for pid in ("janet.liu", "bob.smith"):
            assert len(sched._event_inboxes[pid].poll()) == 0

    def test_inboxes_created_per_persona_on_reset(self):
        sched = _make_scheduler()
        assert "janet.liu" in sched._event_inboxes
        assert "bob.smith" in sched._event_inboxes
        assert len(sched._event_inboxes) == 2


class TestSimClockBridge:
    """SimClock advances when the scheduler advances."""

    def test_clock_advances_with_scheduler(self):
        from open_range.builder.npc.outbox import SimClock

        clock = SimClock()
        sched = ScriptedGreenScheduler(sim_clock=clock)
        sched.reset(_make_snapshot(), EpisodeConfig())

        assert clock.now == 0.0
        sched.advance_until(5.0)
        assert clock.now == 5.0
        sched.advance_until(10.5)
        assert clock.now == 10.5

    def test_clock_reset_on_scheduler_reset(self):
        from open_range.builder.npc.outbox import SimClock

        clock = SimClock()
        sched = ScriptedGreenScheduler(sim_clock=clock)
        sched.reset(_make_snapshot(), EpisodeConfig())
        sched.advance_until(100.0)
        assert clock.now == 100.0

        sched.reset(_make_snapshot(), EpisodeConfig())
        assert clock.now == 0.0

    def test_no_clock_no_error(self):
        """Scheduler works fine without a SimClock (offline mode)."""
        sched = ScriptedGreenScheduler()
        sched.reset(_make_snapshot(), EpisodeConfig())
        sched.advance_until(5.0)
        sched.pop_ready_actions()  # no crash
