"""Runtime NPC agent for online mode.

Each NPC persona runs as an async task alongside the runtime.  The
agent observes events via an EventInbox, processes tasks from a daily
task list, and submits Actions to an ActionOutbox.  The runtime drains
the outbox and turns actions into RuntimeEvents visible to red/blue.

**Observation-driven behavior:**

Incoming events are recorded as *observations* in the agent's memory.
High-severity security events trigger an immediate reaction (fast path),
while messages and lower-priority alerts accumulate in a pending list.
The agent periodically decides whether to act on pending observations
based on personality traits (mood, work_ethic, chattiness, etc.),
current task focus, and how long the observations have been waiting.

Focused, diligent NPCs batch-check messages between tasks.  Distracted
or chatty NPCs interrupt their current work more frequently.

**LLM integration:**

When ``model`` is set, the agent uses LLM calls for:
  - Composing email body content (task.needs_llm)
  - Writing contextual replies to received emails
  - Making nuanced security reaction decisions
All LLM calls fall back to templates on failure.

Priority order:
  1. Security reactions (fast path — immediate response)
  2. Pending observations (personality-gated check)
  3. Pre-generated task (from the daily task list)
"""

from __future__ import annotations

import json
import logging
import os
import random
from collections import deque
from dataclasses import dataclass
from typing import Any

from open_range.builder.npc.email_templates import generate_reply_content
from open_range.builder.npc.identity import display_name
from open_range.builder.npc.memory import MemoryStream
from open_range.builder.npc.outbox import ActionOutbox, EventInbox, MailStore, SimClock
from open_range.builder.npc.tasks import NPCTask
from open_range.runtime_types import Action, RuntimeEvent
from open_range.world_ir import GreenPersona

logger = logging.getLogger(__name__)

# Routine-to-service mapping (same as green.py)
_ROUTINE_SERVICE: dict[str, str] = {
    "browse": "svc-web", "browse_app": "svc-web", "login": "svc-web",
    "lookup": "svc-web", "send_email": "svc-email", "send_mail": "svc-email",
    "send_chat": "svc-chat", "read_mail": "svc-email", "read_chat": "svc-chat",
    "read_message": "svc-email", "access_share": "svc-fileshare",
    "query_db": "svc-db",
}

def _modality_service(modality: str) -> str:
    """Map a communication modality to its service ID."""
    return {"email": "svc-email", "chat": "svc-chat"}.get(modality, "svc-email")


# Events that require the NPC to deviate from their scripted routine
_REACTION_EVENT_TYPES = {
    "InitialAccess", "CredentialObtained", "UnauthorizedCredentialUse",
    "PrivilegeEscalation", "PersistenceEstablished",
    "DetectionAlertRaised", "ServiceDegraded",
}
_HIGH_SEVERITY = {"CredentialObtained", "UnauthorizedCredentialUse", "InitialAccess"}


@dataclass(frozen=True)
class Observation:
    """A recorded observation that the NPC may act on later.

    Security observations go straight to the reaction queue (fast path).
    Messages and alerts accumulate in ``_pending_observations`` and are
    processed when the NPC's personality and focus state allow it.
    """

    event: RuntimeEvent
    timestamp: float   # sim_clock.now when observed
    importance: float  # 1-10, same scale as MemoryEntry
    category: str      # "security" | "alert" | "message" | "routine"


# Personality trait → check-propensity weights
_MOOD_WEIGHTS: dict[str, float] = {
    "distracted": 0.30, "anxious": 0.20, "bored": 0.15,
    "relaxed": 0.05, "focused": -0.10,
}
_WORK_ETHIC_WEIGHTS: dict[str, float] = {
    "lazy": 0.20, "average": 0.0, "diligent": -0.15,
}
_STYLE_WEIGHTS: dict[str, float] = {
    "verbose": 0.10, "terse": -0.05,
}
_CHECK_PROPENSITY_BASE = 0.3

# ---------------------------------------------------------------------------
# LLM prompts
# ---------------------------------------------------------------------------

_EMAIL_COMPOSE_PROMPT = """\
You are {full_name} ({persona_id}), a {role} in the {department} department.
{background}

Your communication style: {communication_style}
You are currently working on: {task_description}

Write a short work email to {recipient_name} ({recipient_role}, {recipient_dept}).
{relationship_context}

Recent memories: {memories}

Return valid JSON:
{{"subject": "<email subject line>", "body": "<email body, 2-4 sentences>"}}

Guidelines:
- Write in your communication style ({communication_style})
- Reference the specific task you are working on
- Explain why you need this specific person's involvement
- Keep it concise — real employees don't write essays"""

_REPLY_COMPOSE_PROMPT = """\
You are {full_name} ({persona_id}), a {role} in the {department} department.
Your communication style: {communication_style}

Reply to the email below. Stay in character.
{relationship_context}

From: {sender_name}
Subject: {original_subject}
Body: {original_body}

Recent memories: {memories}

Return valid JSON:
{{"subject": "Re: {original_subject}", "body": "<your reply, 1-3 sentences>"}}

Guidelines:
- Write in your style ({communication_style})
- Respond to the specific content of the email
- Keep it brief — this is a quick reply"""

_SECURITY_REACT_PROMPT = """\
You are {full_name} ({persona_id}), a {role} in the {department} department.
{background}
Your disposition: {disposition}. Risk tolerance: {risk_tolerance}.

A security event has occurred that you are aware of.

Event: {event_type} — {source_entity} targeting {target_entity}
Your security awareness: {awareness}
Recent memories: {memories}

Return valid JSON:
{{"action": "<report_to_IT|investigate|ignore>", "reason": "<1 sentence why>"}}

Guidelines:
- High awareness (>0.7): likely to report or investigate thoroughly
- Low awareness (<0.3): may not recognize the threat, might ignore
- Your disposition ({disposition}) and risk tolerance ({risk_tolerance}) affect your response
- Prior security incidents in your memories make you more cautious"""

_SOCIAL_MESSAGE_PROMPT = """\
You are {full_name}, a {role}. You're friends with {friend_name} at work.
You're between tasks and want to send a quick non-work chat message.

Your communication style: {communication_style}
Your mood: {mood}

Return valid JSON:
{{"body": "<1-2 casual sentences — water cooler chat>"}}

Keep it natural — weekend plans, lunch spots, something funny, a shared interest."""


def _parse_json_safe(content: str) -> dict[str, Any]:
    """Parse JSON from LLM response, stripping markdown fences."""
    content = content.strip()
    if content.startswith("```"):
        lines = content.splitlines()
        inner = lines[1:-1] if lines[-1].strip() == "```" else lines[1:]
        content = "\n".join(inner).strip()
    return json.loads(content)


class RuntimeNPCAgent:
    """Async NPC agent that submits Actions through the outbox bridge."""

    def __init__(
        self,
        persona: GreenPersona,
        *,
        memory: MemoryStream,
        outbox: ActionOutbox,
        inbox: EventInbox,
        clock: SimClock,
        tasks: list[NPCTask],
        colleagues: list[GreenPersona],
        model: str | None = None,
        mail_store: MailStore | None = None,
    ) -> None:
        self.persona = persona
        self.memory = memory
        self.outbox = outbox
        self.inbox = inbox
        self.clock = clock
        self.mail_store = mail_store
        self.tasks = list(tasks)
        self.colleagues = [c for c in colleagues if c.id != persona.id]
        self.model = model or os.environ.get("OPENRANGE_NPC_MODEL", "")
        self._task_idx = 0
        self._rng = random.Random(hash(persona.id))
        self._actions_submitted = 0
        self._submitted: list[Action] = []
        self._reaction_queue: deque[Action] = deque()
        self._reacted_event_ids: set[str] = set()
        self._read_from: set[str] = set()
        self._pending_observations: list[Observation] = []
        self._between_tasks: bool = False
        self._is_security_role: bool = persona.department.lower() in (
            "security", "infosec", "soc",
        )

    @property
    def _use_llm(self) -> bool:
        return bool(self.model)

    @property
    def done(self) -> bool:
        return (
            self._task_idx >= len(self.tasks)
            and not self._reaction_queue
            and not self._pending_observations
        )

    async def run(self) -> None:
        """Main agent loop — async, uses LLM when model is set."""
        import asyncio
        logger.info("NPC %s (%s) starting workday — %d tasks, llm=%s",
                     self.persona.id, self.persona.role, len(self.tasks),
                     bool(self.model))
        try:
            while not self.done:
                await self._process_inbox_async()
                await self._maybe_submit_next_async()
                await asyncio.sleep(0.3)
        except asyncio.CancelledError:
            logger.info("NPC %s workday ended (%d actions)",
                         self.persona.id, self._actions_submitted)

    # ------------------------------------------------------------------
    # Memory context helper
    # ------------------------------------------------------------------

    def _memory_context(self, n: int = 5) -> list[str]:
        return self.memory.to_summary_list(n)

    # ------------------------------------------------------------------
    # Profile accessors (safe defaults when profile is None)
    # ------------------------------------------------------------------

    @property
    def _full_name(self) -> str:
        return display_name(self.persona)

    @property
    def _communication_style(self) -> str:
        p = self.persona.profile
        return p.backstory.communication_style if p else "professional"

    @property
    def _background_summary(self) -> str:
        p = self.persona.profile
        return p.backstory.background if p else ""

    @property
    def _disposition(self) -> str:
        p = self.persona.profile
        return p.personality.disposition if p else "cooperative"

    @property
    def _risk_tolerance(self) -> float:
        p = self.persona.profile
        return p.personality.risk_tolerance if p else 0.5

    @property
    def _chattiness(self) -> float:
        p = self.persona.profile
        return p.personality.chattiness if p else 0.5

    @property
    def _mood(self) -> str:
        p = self.persona.profile
        return p.personality.mood if p else "focused"

    @property
    def _work_ethic(self) -> str:
        p = self.persona.profile
        return p.personality.work_ethic if p else "diligent"

    @property
    def _interpersonal_style(self) -> str:
        p = self.persona.profile
        return p.personality.interpersonal_style if p else "casual"

    @property
    def _friends(self) -> tuple[str, ...]:
        p = self.persona.profile
        return p.backstory.friends if p else ()

    @property
    def _preferred_modality(self) -> str:
        p = self.persona.profile
        return p.backstory.preferred_modality if p else "email"

    def _is_friend(self, persona_id: str) -> bool:
        return persona_id in self._friends

    def _relationship_context(self, other_id: str) -> str:
        if self._is_friend(other_id):
            return f"You and {other_id} are friends at work — you have a warm, casual relationship."
        return ""

    # ------------------------------------------------------------------
    # Observation system
    # ------------------------------------------------------------------

    def _create_observation(self, event: RuntimeEvent) -> Observation | None:
        """Categorize an event into an Observation, or None if not actionable.

        Events are pre-filtered by green.py routing — only events relevant
        to this NPC reach the inbox.  Detection alerts only arrive for
        security personas; ServiceDegraded only for personas who use the
        affected service; undetected malicious events reach nobody.
        """
        # Skip own events
        if event.actor == "green" and event.source_entity == self.persona.id:
            return None
        # Detection/security alerts (only security personas receive these)
        if event.event_type in ("DetectionAlertRaised", "SuspiciousActionObserved"):
            return Observation(event, self.clock.now, 8.0, "security")
        # Service degradation (routed to affected users only)
        if event.event_type == "ServiceDegraded":
            return Observation(event, self.clock.now, 4.0, "alert")
        # Direct message from another NPC
        if (
            event.event_type == "BenignUserAction"
            and event.target_entity == self.persona.id
            and event.source_entity != self.persona.id
            and event.source_entity not in self._read_from
        ):
            return Observation(event, self.clock.now, 3.5, "message")
        return None

    def _check_propensity(self) -> float:
        """How likely this NPC is to check pending observations right now.

        Combines personality traits into a 0.0-1.0 propensity score.
        Higher values mean the NPC checks more frequently (distractible).
        """
        score = _CHECK_PROPENSITY_BASE
        score += _MOOD_WEIGHTS.get(self._mood, 0.0)
        score += _WORK_ETHIC_WEIGHTS.get(self._work_ethic, 0.0)
        score += _STYLE_WEIGHTS.get(self._interpersonal_style, 0.0)
        score += 0.20 * self._chattiness
        return max(0.05, min(0.95, score))

    def _should_check_observations(self) -> bool:
        """Decide whether to process pending observations this tick."""
        if not self._pending_observations:
            return False
        # Between tasks: always check (batch-check behavior)
        if self._between_tasks:
            return True
        propensity = self._check_propensity()
        # Age boost: older observations become harder to ignore
        oldest = min(obs.timestamp for obs in self._pending_observations)
        age_minutes = max(0.0, self.clock.now - oldest)
        age_boost = min(0.3, age_minutes / 60.0)
        return self._rng.random() < (propensity + age_boost)

    def _process_pending_observations(self) -> None:
        """Move actionable pending observations into the reaction queue (sync)."""
        self._between_tasks = False
        remaining: list[Observation] = []
        for obs in self._pending_observations:
            if obs.event.id in self._reacted_event_ids:
                continue
            if obs.category in ("message", "alert"):
                reaction = self._build_reaction(obs.event)
                self._reaction_queue.append(reaction)
                self._reacted_event_ids.add(obs.event.id)
                if reaction.payload.get("routine") == "read_mail":
                    subject = reaction.payload.get("email_subject", "")
                    sender_id = reaction.payload.get("recipient", "")
                    reply_modality = reaction.payload.get("modality", "email")
                    if sender_id and not subject.startswith("Re:"):
                        reply = self._reply_action(sender_id, modality=reply_modality)
                        if reply is not None:
                            self._reaction_queue.append(reply)
            else:
                remaining.append(obs)
        self._pending_observations = remaining

    async def _process_pending_observations_async(self) -> None:
        """Move actionable pending observations into the reaction queue (async)."""
        self._between_tasks = False
        remaining: list[Observation] = []
        for obs in self._pending_observations:
            if obs.event.id in self._reacted_event_ids:
                continue
            if obs.category in ("message", "alert"):
                if self._use_llm and obs.event.malicious:
                    reaction = await self._llm_decide_reaction(obs.event)
                else:
                    reaction = self._build_reaction(obs.event)
                self._reaction_queue.append(reaction)
                self._reacted_event_ids.add(obs.event.id)
                if reaction.payload.get("routine") == "read_mail":
                    subject = reaction.payload.get("email_subject", "")
                    sender_id = reaction.payload.get("recipient", "")
                    reply_modality = reaction.payload.get("modality", "email")
                    if sender_id and not subject.startswith("Re:"):
                        reply = await self._reply_action_async(sender_id, modality=reply_modality)
                        if reply is not None:
                            self._reaction_queue.append(reply)
            else:
                remaining.append(obs)
        self._pending_observations = remaining

    # ------------------------------------------------------------------
    # Inbox processing (sync for script, async for run loop)
    # ------------------------------------------------------------------

    def _process_inbox(self) -> None:
        """Sync version — security fast path + deferred observations."""
        for event in self.inbox.poll():
            self._observe(event)
            obs = self._create_observation(event)
            if obs is None or event.id in self._reacted_event_ids:
                continue
            if obs.category == "security":
                # Fast path: high-severity security events react immediately
                reaction = self._build_reaction(event)
                self._reaction_queue.append(reaction)
                self._reacted_event_ids.add(event.id)
            else:
                # Deferred path: messages and alerts wait for personality check
                self._pending_observations.append(obs)

    async def _process_inbox_async(self) -> None:
        """Async version — security fast path + deferred observations."""
        for event in self.inbox.poll():
            self._observe(event)
            obs = self._create_observation(event)
            if obs is None or event.id in self._reacted_event_ids:
                continue
            if obs.category == "security":
                if self._use_llm and event.malicious:
                    reaction = await self._llm_decide_reaction(event)
                else:
                    reaction = self._build_reaction(event)
                self._reaction_queue.append(reaction)
                self._reacted_event_ids.add(event.id)
            else:
                self._pending_observations.append(obs)

    def _observe(self, event: RuntimeEvent) -> None:
        if event.actor == "green" and event.source_entity == self.persona.id:
            return
        tags = [event.event_type.lower()]
        if event.malicious:
            tags.extend(["malicious", "security"])
            importance = 8.0 if event.event_type in _HIGH_SEVERITY else 5.0
        else:
            tags.append("observed")
            importance = 2.0
        self.memory.add(
            subject=event.source_entity or event.actor,
            relation=event.event_type.lower(),
            object_=event.target_entity,
            importance=importance,
            tags=tags,
        )

    def _needs_reaction(self, event: RuntimeEvent) -> bool:
        if event.id in self._reacted_event_ids:
            return False
        if event.actor == "green" and event.source_entity == self.persona.id:
            return False
        if event.event_type in _REACTION_EVENT_TYPES and event.malicious:
            return True
        if event.event_type == "DetectionAlertRaised":
            return True
        if (
            event.event_type == "BenignUserAction"
            and event.target_entity == self.persona.id
            and event.source_entity != self.persona.id
            and event.source_entity not in self._read_from
        ):
            return True
        return False

    # ------------------------------------------------------------------
    # Rule-based reactions (template fallbacks)
    # ------------------------------------------------------------------

    def _build_reaction(self, event: RuntimeEvent) -> Action:
        # Security alerts (only security personas receive these via routing)
        if event.event_type in ("DetectionAlertRaised", "SuspiciousActionObserved"):
            if self.persona.awareness > 0.5:
                return self._report_action(event)
            return self._investigate_action(event)
        # Service degradation
        if event.event_type == "ServiceDegraded":
            if self._is_security_role:
                return self._investigate_action(event)
            return self._service_issue_action(event)
        # Direct message from another NPC
        if (
            event.event_type == "BenignUserAction"
            and event.target_entity == self.persona.id
        ):
            return self._read_mail_action(event.source_entity)
        return self._investigate_action(event)

    def _report_action(self, event: RuntimeEvent) -> Action:
        self.memory.add(
            subject=self.persona.id,
            relation="reported_suspicious_activity",
            object_=event.target_entity,
            importance=7.0,
            tags=["reactive", "security", "report", event.event_type.lower()],
        )
        return Action(
            actor_id=self.persona.id, role="green", kind="shell",
            payload={
                "target": "svc-siem",
                "command": "wget -qO- http://svc-siem:9200/all.log | tail -n 20",
                "branch": "report_suspicious_activity",
                "reported_target": event.target_entity,
                "reported_event_type": event.event_type,
            },
        )

    def _investigate_action(self, event: RuntimeEvent) -> Action:
        self.memory.add(
            subject=self.persona.id, relation="investigated",
            object_=event.target_entity, importance=5.0,
            tags=["reactive", "security", "investigate", event.event_type.lower()],
        )
        return Action(
            actor_id=self.persona.id, role="green", kind="api",
            payload={
                "routine": "browse_app", "service": "svc-siem",
                "host": self.persona.home_host, "mailbox": self.persona.mailbox,
            },
        )

    def _service_issue_action(self, event: RuntimeEvent) -> Action:
        """Non-security NPC reacts to a service degradation.

        Chatty NPCs message a colleague ("is X down for you?").
        Others contact helpdesk.  If the degraded service is the
        communication channel itself, fall back to the other channel.
        """
        affected_service = event.target_entity
        self.memory.add(
            subject=self.persona.id, relation="noticed_service_outage",
            object_=affected_service, importance=4.0,
            tags=["reactive", "service_issue", event.event_type.lower()],
        )
        # Pick communication channel — avoid the one that's down
        if affected_service in ("svc-email", "svc-chat"):
            channel = "svc-chat" if affected_service == "svc-email" else "svc-email"
        else:
            channel = _modality_service(self._preferred_modality)
        # Chatty NPCs message a colleague; others contact helpdesk
        if self._chattiness > 0.5 and self.colleagues:
            colleague = self._rng.choice(self.colleagues)
            return Action(
                actor_id=self.persona.id, role="green", kind="mail",
                payload={
                    "routine": "send_mail", "service": channel,
                    "host": self.persona.home_host, "mailbox": self.persona.mailbox,
                    "branch": "npc_chat", "recipient": colleague.id,
                    "to": colleague.mailbox,
                    "modality": "chat" if channel == "svc-chat" else "email",
                    "email_subject": "" if channel == "svc-chat" else f"{affected_service} down?",
                    "email_body": f"Hey, is {affected_service} working for you? I can't access it.",
                },
            )
        return Action(
            actor_id=self.persona.id, role="green", kind="api",
            payload={
                "routine": "contact_helpdesk", "service": affected_service,
                "host": self.persona.home_host, "mailbox": self.persona.mailbox,
            },
        )

    def _read_mail_action(self, sender_id: str) -> Action:
        self._read_from.add(sender_id)
        email_subject = ""
        email_body = ""
        modality = "email"
        if self.mail_store:
            msg = self.mail_store.pickup(self.persona.id, sender=sender_id)
            if msg:
                email_subject = msg.get("subject", "")
                email_body = msg.get("body", "")
                modality = msg.get("modality", "email")
        service = _modality_service(modality)
        relation = "read_chat_from" if modality == "chat" else "read_mail_from"
        self.memory.add(
            subject=self.persona.id, relation=relation,
            object_=f"{sender_id}:{email_subject}" if email_subject else sender_id,
            importance=4.0, tags=["reactive", modality, "read"],
        )
        return Action(
            actor_id=self.persona.id, role="green", kind="mail",
            payload={
                "routine": "read_mail", "service": service,
                "host": self.persona.home_host, "mailbox": self.persona.mailbox,
                "branch": "npc_chat", "recipient": sender_id,
                "modality": modality,
                "email_subject": email_subject, "email_body": email_body,
            },
        )

    def _reply_action(self, sender_id: str, modality: str = "email") -> Action | None:
        """Template-based reply (sync). Replies on the same medium."""
        self._read_from.add(sender_id)
        original_subject, original_body = self._last_read_content(sender_id)
        sender_display = self._colleague_name(sender_id)
        reply = generate_reply_content(
            replier_role=self.persona.role, replier_name=self.persona.id,
            original_sender=sender_display,
            original_subject=original_subject, original_body=original_body,
        )
        return self._finish_reply(sender_id, reply["subject"], reply["body"], modality)

    async def _reply_action_async(self, sender_id: str, modality: str = "email") -> Action | None:
        """LLM or template reply (async). Replies on the same medium."""
        self._read_from.add(sender_id)
        original_subject, original_body = self._last_read_content(sender_id)
        sender_display = self._colleague_name(sender_id)
        if self._use_llm and original_subject:
            try:
                subject, body = await self._llm_compose_reply(
                    sender_id, original_subject, original_body,
                )
            except Exception as exc:
                logger.debug("NPC %s reply LLM failed: %s", self.persona.id, exc)
                reply = generate_reply_content(
                    replier_role=self.persona.role, replier_name=self.persona.id,
                    original_sender=sender_display,
                    original_subject=original_subject, original_body=original_body,
                )
                subject, body = reply["subject"], reply["body"]
        else:
            reply = generate_reply_content(
                replier_role=self.persona.role, replier_name=self.persona.id,
                original_sender=sender_display,
                original_subject=original_subject, original_body=original_body,
            )
            subject, body = reply["subject"], reply["body"]
        return self._finish_reply(sender_id, subject, body, modality)

    def _colleague_name(self, persona_id: str) -> str:
        """Resolve a colleague ID to their display name."""
        c = next((c for c in self.colleagues if c.id == persona_id), None)
        return display_name(c) if c else display_name(persona_id)

    def _last_read_content(self, sender_id: str) -> tuple[str, str]:
        """Extract original subject/body from recent read memory."""
        original_subject = ""
        original_body = ""
        for m in reversed(self.memory.recent(5)):
            if m.relation == "read_mail_from" and sender_id in m.object_:
                if ":" in m.object_:
                    original_subject = m.object_.split(":", 1)[1]
                break
        return original_subject, original_body

    def _finish_reply(self, sender_id: str, subject: str, body: str, modality: str = "email") -> Action:
        """Common reply finalization: deposit in MessageStore, record memory."""
        # Chat replies don't carry subjects
        if modality == "chat":
            subject = ""
        if self.mail_store:
            self.mail_store.deliver(self.persona.id, sender_id, subject, body, modality=modality)
        service = _modality_service(modality)
        self.memory.add(
            subject=self.persona.id, relation="replied_to",
            object_=f"{sender_id}:{subject}", importance=3.5,
            tags=["reactive", modality, "reply"],
        )
        sender_persona = next(
            (c for c in self.colleagues if c.id == sender_id), None
        )
        return Action(
            actor_id=self.persona.id, role="green", kind="mail",
            payload={
                "routine": "send_mail", "service": service,
                "host": self.persona.home_host, "mailbox": self.persona.mailbox,
                "branch": "npc_chat", "modality": modality, "recipient": sender_id,
                "to": (sender_persona.mailbox if sender_persona
                       else f"{sender_id}@corp.local"),
                "email_subject": subject, "email_body": body,
            },
        )

    # ------------------------------------------------------------------
    # Task submission (sync for script, async for run loop)
    # ------------------------------------------------------------------

    def _maybe_submit_next(self) -> None:
        """Sync version — template content only (for script use)."""
        # Priority 1: security reactions (fast path)
        if self._reaction_queue:
            action = self._reaction_queue.popleft()
            self._submit(action)
            return
        # Priority 2: personality-gated observation processing
        if self._should_check_observations():
            self._process_pending_observations()
            if self._reaction_queue:
                action = self._reaction_queue.popleft()
                self._submit(action)
                return
        # Priority 3: next scheduled task
        task = self._next_due_task()
        if task is None:
            return
        action = self._build_action(task)
        self._submit(action)
        self._record_task_memory(task)
        self._between_tasks = True

    async def _maybe_submit_next_async(self) -> None:
        """Async version — uses LLM for email content when model is set."""
        # Priority 1: security reactions (fast path)
        if self._reaction_queue:
            action = self._reaction_queue.popleft()
            self._submit(action)
            return
        # Priority 2: personality-gated observation processing
        if self._should_check_observations():
            await self._process_pending_observations_async()
            if self._reaction_queue:
                action = self._reaction_queue.popleft()
                self._submit(action)
                return
        # Priority 3: next scheduled task
        task = self._next_due_task()
        if task is None:
            return
        if self._use_llm and task.needs_llm and task.action in ("send_email", "send_mail"):
            action = await self._build_action_llm(task)
        else:
            action = self._build_action(task)
        self._submit(action)
        self._record_task_memory(task)
        self._between_tasks = True

    def _next_due_task(self) -> NPCTask | None:
        """Advance past idle tasks and return the next actionable task.

        During idle time, chatty NPCs with friends may send a social
        message instead of doing nothing.
        """
        while self._task_idx < len(self.tasks):
            task = self.tasks[self._task_idx]
            if self.clock.now < task.start_minutes:
                return None
            if task.action == "idle":
                self.memory.add(
                    subject=self.persona.id, relation="idle",
                    object_=task.detail or "break", importance=1.0,
                    tags=["routine", "idle"],
                )
                self._task_idx += 1
                # Chatty NPCs with friends send a social message during idle
                social = self._maybe_social_message()
                if social is not None:
                    return social
                continue
            self._task_idx += 1
            return task
        return None

    def _maybe_social_message(self) -> NPCTask | None:
        """During idle time, chatty NPCs message a friend about non-work stuff."""
        if not self._friends:
            return None
        # chattiness 0-1 maps to probability: 0.9 chattiness → 90% chance
        if self._rng.random() > self._chattiness:
            return None
        friend_id = self._rng.choice(list(self._friends))
        friend = next((c for c in self.colleagues if c.id == friend_id), None)
        if friend is None:
            return None
        friend_name = display_name(friend)
        # Social messages default to chat (casual), but respect preference
        modality = self._preferred_modality if self._preferred_modality == "chat" else "chat"
        # Pick from canned social messages
        social = self._rng.choice(_SOCIAL_MESSAGES)
        body = social["body"].format(name=friend_name)
        # Chat messages don't have subjects
        subject = "" if modality == "chat" else social["subject"].format(name=friend_name)
        return NPCTask(
            description=f"Chatting with {friend_name}",
            action="send_email",
            target=friend_id,
            detail="Social message",
            modality=modality,
            start_minutes=0,
            duration_minutes=5,
            collaborators=(friend_id,),
            email_subject=subject,
            email_body=body,
        )

    def _submit(self, action: Action) -> None:
        self.outbox.submit(action)
        self._submitted.append(action)
        self._actions_submitted += 1

    # ------------------------------------------------------------------
    # Action building (template and LLM)
    # ------------------------------------------------------------------

    def _build_action(self, task: NPCTask) -> Action:
        """Build action with pre-generated template content."""
        is_message = task.action in ("send_email", "send_mail")
        modality = task.modality if is_message else ""
        service = _modality_service(modality) if is_message else _ROUTINE_SERVICE.get(task.action, "svc-web")
        kind = "mail" if is_message else "api"

        payload: dict[str, Any] = {
            "routine": task.action, "service": service,
            "host": self.persona.home_host, "mailbox": self.persona.mailbox,
        }
        if is_message:
            recipient_id = task.target
            if not recipient_id and self.colleagues:
                recipient_id = self._rng.choice(self.colleagues).id
            if recipient_id:
                rp = next((c for c in self.colleagues if c.id == recipient_id), None)
                payload["recipient"] = recipient_id
                payload["to"] = rp.mailbox if rp else f"{recipient_id}@corp.local"
                payload["branch"] = "npc_chat"
                payload["modality"] = modality
                # Chat messages don't carry subjects
                subject = "" if modality == "chat" else task.email_subject
                payload["email_subject"] = subject
                payload["email_body"] = task.email_body
                if self.mail_store and (subject or task.email_body):
                    self.mail_store.deliver(
                        self.persona.id, recipient_id,
                        subject, task.email_body,
                        modality=modality,
                    )
        else:
            if task.target:
                payload["path"] = task.target
            if task.detail:
                payload["detail"] = task.detail
        return Action(actor_id=self.persona.id, role="green", kind=kind, payload=payload)

    async def _build_action_llm(self, task: NPCTask) -> Action:
        """Build email action with LLM-generated content, template fallback."""
        import litellm

        recipient_id = task.target
        if not recipient_id and self.colleagues:
            recipient_id = self._rng.choice(self.colleagues).id
        rp = next((c for c in self.colleagues if c.id == recipient_id), None)
        recip_name = display_name(rp) if rp else display_name(recipient_id)
        recip_role = rp.role if rp else "colleague"
        recip_dept = rp.department if rp else ""

        try:
            prompt = _EMAIL_COMPOSE_PROMPT.format(
                full_name=self._full_name,
                persona_id=self.persona.id, role=self.persona.role,
                department=self.persona.department,
                background=self._background_summary,
                communication_style=self._communication_style,
                task_description=task.description,
                recipient_name=recip_name, recipient_role=recip_role,
                recipient_dept=recip_dept,
                relationship_context=self._relationship_context(recipient_id),
                memories="; ".join(self._memory_context()),
            )
            response = await litellm.acompletion(
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
                response_format={"type": "json_object"},
                temperature=0.7,
            )
            raw = _parse_json_safe(response.choices[0].message.content)
            subject = str(raw.get("subject", task.email_subject))
            body = str(raw.get("body", task.email_body))
            logger.debug("NPC %s composed email via LLM: %s", self.persona.id, subject)
        except Exception as exc:
            logger.debug("NPC %s email LLM failed, using template: %s", self.persona.id, exc)
            subject = task.email_subject
            body = task.email_body

        modality = task.modality or "email"
        service = _modality_service(modality)
        # Chat messages don't carry subjects
        if modality == "chat":
            subject = ""
        payload: dict[str, Any] = {
            "routine": task.action, "service": service,
            "host": self.persona.home_host, "mailbox": self.persona.mailbox,
            "branch": "npc_chat", "modality": modality, "recipient": recipient_id,
            "to": rp.mailbox if rp else f"{recipient_id}@corp.local",
            "email_subject": subject, "email_body": body,
        }
        if self.mail_store and (subject or body):
            self.mail_store.deliver(self.persona.id, recipient_id, subject, body, modality=modality)
        return Action(actor_id=self.persona.id, role="green", kind="mail", payload=payload)

    # ------------------------------------------------------------------
    # LLM calls (async, with template fallbacks at call sites)
    # ------------------------------------------------------------------

    async def _llm_compose_reply(
        self, sender_id: str, original_subject: str, original_body: str,
    ) -> tuple[str, str]:
        """Use LLM to compose a contextual reply."""
        import litellm

        sender_persona = next((c for c in self.colleagues if c.id == sender_id), None)
        sender_name = display_name(sender_persona) if sender_persona else display_name(sender_id)
        prompt = _REPLY_COMPOSE_PROMPT.format(
            full_name=self._full_name,
            persona_id=self.persona.id, role=self.persona.role,
            department=self.persona.department,
            communication_style=self._communication_style,
            relationship_context=self._relationship_context(sender_id),
            sender_name=sender_name,
            original_subject=original_subject, original_body=original_body,
            memories="; ".join(self._memory_context()),
        )
        response = await litellm.acompletion(
            model=self.model,
            messages=[{"role": "user", "content": prompt}],
            response_format={"type": "json_object"},
            temperature=0.7,
        )
        raw = _parse_json_safe(response.choices[0].message.content)
        return (
            str(raw.get("subject", f"Re: {original_subject}")),
            str(raw.get("body", "")),
        )

    async def _llm_decide_reaction(self, event: RuntimeEvent) -> Action:
        """Use LLM to decide how to react to a security event."""
        import litellm

        try:
            prompt = _SECURITY_REACT_PROMPT.format(
                full_name=self._full_name,
                persona_id=self.persona.id, role=self.persona.role,
                department=self.persona.department,
                background=self._background_summary,
                disposition=self._disposition,
                risk_tolerance=self._risk_tolerance,
                event_type=event.event_type,
                source_entity=event.source_entity,
                target_entity=event.target_entity,
                awareness=self.persona.awareness,
                memories="; ".join(self._memory_context()),
            )
            response = await litellm.acompletion(
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
                response_format={"type": "json_object"},
                temperature=0.3,
            )
            raw = _parse_json_safe(response.choices[0].message.content)
            action_choice = str(raw.get("action", "investigate")).lower()
            logger.debug("NPC %s LLM security decision: %s (%s)",
                         self.persona.id, action_choice,
                         raw.get("reason", ""))
        except Exception as exc:
            logger.debug("NPC %s security LLM failed: %s", self.persona.id, exc)
            return self._build_reaction(event)

        if action_choice == "report_to_it" or action_choice == "report":
            return self._report_action(event)
        elif action_choice == "ignore":
            self.memory.add(
                subject=self.persona.id, relation="ignored_security_event",
                object_=event.target_entity, importance=3.0,
                tags=["reactive", "security", "ignore", event.event_type.lower()],
            )
            return self._investigate_action(event)  # still log something
        else:
            return self._investigate_action(event)

    # ------------------------------------------------------------------
    # Memory recording
    # ------------------------------------------------------------------

    def _record_task_memory(self, task: NPCTask) -> None:
        if task.action in ("send_email", "send_mail"):
            relation, obj = "sent_mail_to", task.target or "colleague"
            tags, importance = ["routine", "mail", "sent"], 3.0
        elif task.action == "read_mail":
            relation, obj = "read_mail_from", task.target or "colleague"
            tags, importance = ["routine", "mail", "read"], 3.0
        else:
            relation = {
                "browse": "browsed", "login": "logged_into",
                "lookup": "looked_up", "access_share": "accessed_share",
                "query_db": "queried",
            }.get(task.action, "performed")
            obj = task.target or _ROUTINE_SERVICE.get(task.action, "svc-web")
            tags, importance = ["routine", task.action], 2.0
        self.memory.add(
            subject=self.persona.id, relation=relation,
            object_=obj, importance=importance, tags=tags,
        )


# ---------------------------------------------------------------------------
# Canned social messages (used during idle time between friends)
# ---------------------------------------------------------------------------

_SOCIAL_MESSAGES = [
    {"subject": "lunch today?", "body": "Hey {name}, want to grab lunch? I'm thinking tacos."},
    {"subject": "did you see this", "body": "Hey {name}, did you catch the all-hands yesterday? That Q2 roadmap slide was wild."},
    {"subject": "weekend plans?", "body": "Hey {name}, any plans this weekend? I'm trying to get a group together for hiking."},
    {"subject": "coffee run", "body": "Hey {name}, heading to grab coffee — want anything? The usual?"},
    {"subject": "random thought", "body": "Hey {name}, I just realized we've been in back-to-back meetings all week. We should block some focus time."},
    {"subject": "that meeting tho", "body": "Hey {name}, was that meeting as painful for you as it was for me? I think we could have covered that in an email."},
    {"subject": "heads up", "body": "Hey {name}, heard they might reorganize the floor plan again. Just a heads up in case you want to claim a good desk."},
    {"subject": "nice work!", "body": "Hey {name}, saw your presentation deck — really well done. The data viz on slide 3 was great."},
]
