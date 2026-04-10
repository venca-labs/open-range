"""Scripted green scheduler for runtime-owned enterprise activity."""

from __future__ import annotations

import random
from collections import defaultdict, deque
from math import floor
from typing import Any, Protocol

from open_range.builder.npc.memory import MemoryStream
from open_range.builder.npc.outbox import ActionOutbox, EventInbox, SimClock
from open_range.builder.npc.planner import DailyPlanner, ScheduledAction, _template_schedule
from open_range.episode_config import EpisodeConfig
from open_range.runtime_types import Action, RuntimeEvent
from open_range.snapshot import RuntimeSnapshot
from open_range.world_ir import GreenPersona


class GreenScheduler(Protocol):
    def reset(
        self, snapshot: RuntimeSnapshot, episode_config: EpisodeConfig
    ) -> None: ...
    def advance_until(self, sim_time: float) -> None: ...
    def pop_ready_actions(self) -> tuple[Action, ...]: ...
    def record_event(self, event: RuntimeEvent) -> None: ...


# Realistic cadence: an employee does something every 5-15 minutes, not
# every 1 minute.  These constants gate per-persona action timing.
_MIN_CADENCE = 5
_MAX_CADENCE = 15
_SECURITY_DEPARTMENTS = frozenset(("security", "infosec", "soc"))


class ScriptedGreenScheduler:
    """Deterministic routine and branch scheduling owned by the runtime.

    In offline mode (default), all actions are generated deterministically
    from template schedules.  In online mode, async NPC agents submit
    actions through an ``ActionOutbox`` and observe events through
    per-persona ``EventInbox`` instances.  The scheduler coordinates both
    sources transparently — the runtime calls the same four methods
    regardless of mode.
    """

    def __init__(
        self,
        *,
        action_outbox: ActionOutbox | None = None,
        sim_clock: SimClock | None = None,
    ) -> None:
        self._snapshot: RuntimeSnapshot | None = None
        self._episode_config = EpisodeConfig()
        self._seed = 0
        self._last_advanced_slot = -1
        self._reactive_queue: dict[int, deque[Action]] = defaultdict(deque)
        self._scheduled_reactions: set[tuple[int, str, str]] = set()
        self._ready_actions: deque[Action] = deque()
        # Per-persona memory and planner (populated on reset)
        self._memory_streams: dict[str, MemoryStream] = {}
        self._planners: dict[str, DailyPlanner] = {}
        # Per-persona cadence: each persona acts at their own pace
        self._next_action_slot: dict[str, int] = {}
        # Pending inbox: recipient_id → [sender_id, …]
        # Used in offline mode only; in online mode agents handle reads
        # via MessageStore + the observation system instead.
        self._pending_inbox: dict[str, list[str]] = defaultdict(list)
        # Async-to-sync bridge (optional — populated for online mode)
        self._action_outbox: ActionOutbox | None = action_outbox
        self._sim_clock: SimClock | None = sim_clock
        self._event_inboxes: dict[str, EventInbox] = {}

    def reset(self, snapshot: RuntimeSnapshot, episode_config: EpisodeConfig) -> None:
        self._snapshot = snapshot
        self._episode_config = episode_config
        self._seed = snapshot.world.seed
        self._last_advanced_slot = -1
        self._reactive_queue = defaultdict(deque)
        self._scheduled_reactions = set()
        self._ready_actions = deque()
        # Initialise per-persona MemoryStream and DailyPlanner (template-only)
        self._memory_streams = {}
        self._planners = {}
        self._next_action_slot = {}
        self._pending_inbox = defaultdict(list)
        self._event_inboxes = {}
        for persona in snapshot.world.green_personas:
            self._memory_streams[persona.id] = MemoryStream()
            planner = DailyPlanner(model=None)
            planner._schedule = _template_schedule(persona)
            self._planners[persona.id] = planner
            self._next_action_slot[persona.id] = 0
            self._event_inboxes[persona.id] = EventInbox()
        # Security personas receive detection alerts; others don't
        self._security_persona_ids: set[str] = {
            p.id for p in snapshot.world.green_personas
            if p.department.lower() in _SECURITY_DEPARTMENTS
        }
        # Map service → persona IDs whose tasks use that service
        self._service_to_personas: dict[str, set[str]] = defaultdict(set)
        for persona in snapshot.world.green_personas:
            for routine in persona.routine:
                svc = _routine_service(routine)
                self._service_to_personas[svc].add(persona.id)
        if self._sim_clock is not None:
            self._sim_clock.reset()

    def advance_until(self, sim_time: float) -> None:
        if self._snapshot is None or not self._episode_config.green_enabled:
            return
        if self._sim_clock is not None:
            self._sim_clock.advance(sim_time)
        goal_slot = max(0, floor(sim_time))
        for slot in range(self._last_advanced_slot + 1, goal_slot + 1):
            self._ready_actions.extend(self._routine_actions(slot))
            self._ready_actions.extend(self._reactive_actions(slot))
            self._last_advanced_slot = slot

    def pop_ready_actions(self) -> tuple[Action, ...]:
        # Drain any actions submitted by async NPC agents
        if self._action_outbox is not None:
            self._ready_actions.extend(self._action_outbox.drain())
        actions = tuple(self._ready_actions)
        self._ready_actions.clear()
        return actions

    def record_event(self, event: RuntimeEvent) -> None:
        # Route events to relevant NPC inboxes only
        if self._event_inboxes:
            self._route_event_to_inboxes(event)
        if (
            self._snapshot is None
            or not self._episode_config.green_enabled
            or not self._episode_config.green_branch_enabled
            or self._episode_config.green_branch_backend == "none"
            or not event.malicious
        ):
            return
        # In online mode, RuntimeNPCAgents handle their own reactions via
        # the observation system.  Skip scheduler-generated reactions to
        # avoid duplicates.
        if self._action_outbox is not None:
            return
        all_personas = sorted(
            self._snapshot.world.green_personas,
            key=lambda persona: (-persona.awareness, persona.id),
        )
        if not all_personas:
            return
        # Record the malicious event in the most-aware persona's memory so
        # future susceptibility calculations reflect prior incidents.
        observer = all_personas[0]
        ms = self._memory_streams.get(observer.id)
        if ms is not None:
            high_severity = event.event_type in {
                "CredentialObtained", "UnauthorizedCredentialUse", "InitialAccess",
            }
            ms.add(
                subject=event.source_entity or "red",
                relation=_event_susceptibility_key(event.event_type),
                object_=event.target_entity,
                importance=8.0 if high_severity else 5.0,
                tags=[event.event_type.lower(), "malicious", "security"],
            )
        # Prefer security personas for reactions; fall back to all if none
        security_personas = [p for p in all_personas if p.id in self._security_persona_ids]
        responders = security_personas if security_personas else all_personas
        backend = self._episode_config.green_branch_backend
        slot = floor(event.time) + 1
        target = event.target_entity
        reaction_key = (slot, event.event_type, target)
        if reaction_key in self._scheduled_reactions:
            return
        self._scheduled_reactions.add(reaction_key)
        if backend == "scripted":
            self._schedule_scripted_reaction(event, responders, slot)
            return
        if backend == "small_llm":
            self._schedule_small_llm_reaction(event, responders, slot)
            return
        self._schedule_workflow_orchestrator_reaction(event, responders, slot)

    def _routine_actions(self, slot: int) -> tuple[Action, ...]:
        assert self._snapshot is not None
        if not self._episode_config.green_routine_enabled:
            return ()
        if self._episode_config.green_profile == "off":
            return ()
        personas = list(self._snapshot.world.green_personas)
        if not personas:
            return ()
        workload = self._snapshot.world.green_workload
        base_interval = max(1, workload.routine_interval_ticks)

        rng = random.Random(self._seed + slot)

        # Select personas that are *due* this slot (per-persona cadence)
        due = [p for p in personas if self._next_action_slot.get(p.id, 0) <= slot]
        if not due:
            return ()
        due.sort(key=lambda p: p.id)

        max_parallel = min(
            self._parallel_budget(workload.max_parallel_actions), len(due)
        )
        chosen = (
            due
            if max_parallel >= len(due)
            else rng.sample(due, k=max_parallel)
        )
        chosen.sort(key=lambda p: p.id)

        all_personas = list(self._snapshot.world.green_personas)
        actions: list[Action] = []
        for persona in chosen:
            ms = self._memory_streams.get(persona.id)

            # ── Priority 1: read pending inbox mail ─────────────────────
            inbox = self._pending_inbox.get(persona.id)
            if inbox:
                sender_id = inbox.pop(0)
                actions.append(Action(
                    actor_id=persona.id,
                    role="green",
                    kind="mail",
                    payload={
                        "routine": "read_mail",
                        "service": "svc-email",
                        "host": persona.home_host,
                        "mailbox": persona.mailbox,
                        "branch": "npc_chat",
                        "recipient": sender_id,
                    },
                ))
                # Record in memory
                if ms is not None:
                    ms.add(
                        subject=persona.id,
                        relation="read_mail_from",
                        object_=sender_id,
                        importance=3.0,
                        tags=["routine", "mail", "read"],
                    )
            else:
                # ── Priority 2: planner-scheduled routine ───────────────
                planner = self._planners.get(persona.id)
                hint = _planner_hint_for_slot(planner, slot) if planner else None
                if hint:
                    routine = _planner_action_to_routine(hint.action)
                elif persona.routine:
                    routine = persona.routine[slot % len(persona.routine)]
                else:
                    routine = "browse_app"

                # Idle: persona is at their desk doing nothing — skip
                if routine == "idle":
                    self._next_action_slot[persona.id] = (
                        slot + rng.randint(_MIN_CADENCE, _MAX_CADENCE)
                    )
                    continue

                service = _routine_service(routine)
                kind = "mail" if "mail" in routine else "api"

                payload: dict[str, Any] = {
                    "routine": routine,
                    "service": service,
                    "host": persona.home_host,
                    "mailbox": persona.mailbox,
                }
                # NPC-to-NPC chat: add recipient and npc_chat branch
                if kind == "mail":
                    colleagues = [p for p in all_personas if p.id != persona.id]
                    if colleagues:
                        recipient = self._pick_recipient(
                            persona.id, colleagues, ms, rng,
                        )
                        payload["to"] = recipient.mailbox
                        payload["recipient"] = recipient.id
                        payload["branch"] = "npc_chat"
                        # Queue delivery so recipient reads it later
                        self._pending_inbox[recipient.id].append(persona.id)
                        # Record send in memory
                        if ms is not None:
                            ms.add(
                                subject=persona.id,
                                relation="sent_mail_to",
                                object_=recipient.id,
                                importance=3.0,
                                tags=["routine", "mail", "sent"],
                            )
                    elif ms is not None:
                        ms.add(
                            subject=persona.id,
                            relation=_routine_to_relation(routine),
                            object_=service,
                            importance=2.0,
                            tags=["routine", routine],
                        )
                else:
                    # Record non-mail routine in memory
                    if ms is not None:
                        ms.add(
                            subject=persona.id,
                            relation=_routine_to_relation(routine),
                            object_=service,
                            importance=2.0,
                            tags=["routine", routine],
                        )

                actions.append(Action(
                    actor_id=persona.id, role="green",
                    kind=kind, payload=payload,
                ))

            # Schedule next action with realistic cadence
            cadence = max(base_interval, rng.randint(_MIN_CADENCE, _MAX_CADENCE))
            self._next_action_slot[persona.id] = slot + cadence

        return tuple(actions)

    @staticmethod
    def _pick_recipient(
        sender_id: str,
        colleagues: list[GreenPersona],
        ms: MemoryStream | None,
        rng: random.Random,
    ) -> GreenPersona:
        """Pick a mail recipient, preferring colleagues not recently emailed."""
        if ms is not None:
            recent_recipients = {
                m.object_
                for m in ms.recent(5)
                if "sent" in m.tags
            }
            uncontacted = [c for c in colleagues if c.id not in recent_recipients]
            if uncontacted:
                return rng.choice(uncontacted)
        return rng.choice(colleagues)

    def _route_event_to_inboxes(self, event: RuntimeEvent) -> None:
        """Push an event only to the NPC inboxes that should see it.

        Routing rules (realism-driven):
        - Directed at a persona (email/chat/phishing) → only that persona
        - DetectionAlertRaised / SuspiciousActionObserved → security team only
        - ServiceDegraded → personas whose tasks use the affected service
        - Undetected malicious events → nobody (invisible until detected)
        - Routine BenignUserAction → nobody
        """
        target = event.target_entity
        # Directed at a specific NPC (e.g. incoming email, phishing)
        if target in self._event_inboxes:
            self._event_inboxes[target].push(event)
            return
        # Detection alerts → security team only
        if event.event_type in ("DetectionAlertRaised", "SuspiciousActionObserved"):
            for pid in self._security_persona_ids:
                inbox = self._event_inboxes.get(pid)
                if inbox is not None:
                    inbox.push(event)
            return
        # Service degradation → only personas who use that service
        if event.event_type == "ServiceDegraded":
            affected = self._service_to_personas.get(target, set())
            for pid in affected:
                inbox = self._event_inboxes.get(pid)
                if inbox is not None:
                    inbox.push(event)
            return
        # Undetected malicious events (credential theft, lateral movement, etc.)
        # are invisible — no NPC is notified.
        # Routine BenignUserAction on services: no NPC needs to react.

    def _reactive_actions(self, slot: int) -> tuple[Action, ...]:
        if not self._episode_config.green_branch_enabled:
            self._reactive_queue.pop(slot, None)
            return ()
        actions: list[Action] = []
        budget = self._reactive_budget()
        while self._reactive_queue[slot] and len(actions) < budget:
            actions.append(self._reactive_queue[slot].popleft())
        if self._reactive_queue[slot]:
            self._reactive_queue[slot + 1].extend(self._reactive_queue[slot])
        self._reactive_queue.pop(slot, None)
        return tuple(actions)

    def _parallel_budget(self, base_budget: int) -> int:
        if self._episode_config.green_profile == "off":
            return 0
        if self._episode_config.green_profile == "low":
            return max(1, base_budget // 2)
        if self._episode_config.green_profile == "high":
            return base_budget + 1
        return base_budget

    def _reactive_budget(self) -> int:
        assert self._snapshot is not None
        base_budget = self._snapshot.world.green_workload.reactive_branch_budget
        if self._episode_config.green_branch_backend == "workflow_orchestrator":
            base_budget += 2
        elif self._episode_config.green_branch_backend == "small_llm":
            base_budget += 1
        if self._episode_config.green_profile == "off":
            return 0
        if self._episode_config.green_profile == "low":
            return max(0, base_budget - 1)
        if self._episode_config.green_profile == "high":
            return base_budget + 1
        return base_budget

    def _schedule_scripted_reaction(
        self, event: RuntimeEvent, personas: list[Any], slot: int
    ) -> None:
        reporter = personas[0]
        self._reactive_queue[slot].append(
            self._report_action(reporter.id, event.target_entity, event.event_type)
        )
        if event.event_type in {"CredentialObtained", "UnauthorizedCredentialUse"}:
            self._reactive_queue[slot].append(
                self._recover_action(reporter.id, event.target_entity)
            )

    def _schedule_small_llm_reaction(
        self, event: RuntimeEvent, personas: list[Any], slot: int
    ) -> None:
        reporter = max(
            personas,
            key=lambda persona: (
                round(
                    persona.awareness
                    - (self._susceptibility_score(persona, event) * 0.4),
                    4,
                ),
                persona.id,
            ),
        )
        delay = 2 if event.event_type == "InitialAccess" else 1
        llm_slot = slot + delay - 1
        self._reactive_queue[llm_slot].append(
            self._report_action(
                reporter.id, event.target_entity, event.event_type, depth=40
            )
        )
        if event.event_type in {
            "CredentialObtained",
            "UnauthorizedCredentialUse",
        } and reporter.awareness >= (self._susceptibility_score(reporter, event) * 0.8):
            self._reactive_queue[llm_slot].append(
                self._recover_action(reporter.id, event.target_entity)
            )

    def _susceptibility_score(self, persona: GreenPersona, event: RuntimeEvent) -> float:
        """Compute susceptibility, reduced by prior incident memories."""
        if not persona.susceptibility:
            base = 0.0
        else:
            event_key = _event_susceptibility_key(event.event_type)
            base = persona.susceptibility.get(event_key, max(persona.susceptibility.values()))
        # Reduce effective susceptibility for each prior security incident in memory
        ms = self._memory_streams.get(persona.id)
        if ms is not None:
            prior = ms.retrieve(
                ["malicious", "security", event.event_type.lower()], top_k=3
            )
            if prior:
                # Up to 0.15 reduction: each recalled incident reduces by 0.05
                reduction = min(0.15, len(prior) * 0.05)
                return max(0.0, base - reduction)
        return base

    def _schedule_workflow_orchestrator_reaction(
        self, event: RuntimeEvent, personas: list[Any], slot: int
    ) -> None:
        reporter = personas[0]
        self._reactive_queue[slot].append(
            self._report_action(reporter.id, event.target_entity, event.event_type)
        )
        self._reactive_queue[slot].append(
            Action(
                actor_id=reporter.id,
                role="green",
                kind="shell",
                payload={
                    "target": "svc-siem",
                    "command": "printf '%s\n' openrange-ticket >> /tmp/openrange-green-ticket",
                    "branch": "open_it_ticket",
                    "reported_target": event.target_entity,
                    "reported_event_type": event.event_type,
                },
            )
        )
        if event.event_type in {
            "CredentialObtained",
            "UnauthorizedCredentialUse",
            "InitialAccess",
        }:
            self._reactive_queue[slot].append(
                self._recover_action(reporter.id, event.target_entity)
            )

    @staticmethod
    def _report_action(
        actor_id: str, target: str, event_type: str, *, depth: int = 20
    ) -> Action:
        return Action(
            actor_id=actor_id,
            role="green",
            kind="shell",
            payload={
                "target": "svc-siem",
                "command": f"wget -qO- http://svc-siem:9200/all.log | tail -n {depth}",
                "branch": "report_suspicious_activity",
                "reported_target": target,
                "reported_event_type": event_type,
            },
        )

    @staticmethod
    def _recover_action(actor_id: str, target: str) -> Action:
        return Action(
            actor_id=actor_id,
            role="green",
            kind="control",
            payload={
                "target": "svc-idp",
                "action": "recover",
                "branch": "reset_password",
                "reported_target": target,
            },
        )


def _routine_service(routine: str) -> str:
    lowered = routine.lower()
    if "mail" in lowered:
        return "svc-email"
    if "file" in lowered or "share" in lowered:
        return "svc-fileshare"
    if "idp" in lowered or "password" in lowered or "login" in lowered:
        return "svc-idp"
    if "alert" in lowered or "triage" in lowered:
        return "svc-siem"
    if "payroll" in lowered or "db" in lowered or "query" in lowered:
        return "svc-db"
    if "lookup" in lowered or "search" in lowered:
        return "svc-db"
    return "svc-web"


def _planner_hint_for_slot(
    planner: DailyPlanner, slot: int
) -> ScheduledAction | None:
    """Return the most recent scheduled action due by *slot* (1 slot ≈ 1 min).

    Maps slot number to a simulated 9am–5pm workday hour and returns the
    latest scheduled action at or before that hour, without advancing an
    internal pointer (safe to call multiple times for the same slot).
    """
    sim_hour = 9 + min(slot // 60, 8)
    candidates = [a for a in planner._schedule if a.hour <= sim_hour]
    return candidates[-1] if candidates else None


def _planner_action_to_routine(action: str) -> str:
    """Map a DailyPlanner action name to a GreenPersona routine string."""
    return {
        "browse": "browse_app",
        "send_email": "send_mail",
        "lookup": "query_db",
        "access_share": "access_fileshare",
        "login": "login",
        "query_db": "query_db",
        "idle": "idle",
    }.get(action, "browse_app")


def _routine_to_relation(routine: str) -> str:
    """Map a routine action name to a memory relation verb."""
    return {
        "browse_app": "browsed",
        "send_mail": "sent_mail_to",
        "read_mail": "read_mail_from",
        "access_share": "accessed_share",
        "query_db": "queried",
        "login": "logged_into",
    }.get(routine, "performed")


def _event_susceptibility_key(event_type: str) -> str:
    chunks: list[str] = []
    token: list[str] = []
    for char in event_type:
        if char.isupper() and token:
            chunks.append("".join(token).lower())
            token = [char]
            continue
        token.append(char)
    if token:
        chunks.append("".join(token).lower())
    return "_".join(chunks)
