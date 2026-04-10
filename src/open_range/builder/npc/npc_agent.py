"""LLM-driven NPC agent (Level 1).

Each NPC autonomously lives their workday — browsing pages, emailing
colleagues, querying records, accessing shares.  Available actions are
derived from the SnapshotSpec so they adapt to whatever environment the
Builder LLM generated.

This implementation adds three capabilities from Park et al. (2023)
"Generative Agents":

  MemoryStream  — per-NPC memory with recency / importance / relevance
                  retrieval.  Each action and reaction is recorded as a
                  memory so NPCs reference prior events naturally.

  DailyPlanner  — LLM-generated (or role-template) workday schedule
                  that guides action selection, producing varied traffic
                  patterns instead of a uniform random loop.

  Reflection    — periodic summarisation of accumulated memories into
                  higher-level insights that re-shape the next day plan.

NPCs also react to incoming stimuli (phishing, social engineering) using
the same memory context, so a persona that was previously targeted will
react differently on a second attempt.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import random
import time
from typing import Any

import litellm

from dataclasses import dataclass, field

from open_range.builder.npc.memory import MemoryStream
from open_range.builder.npc.planner import _parse_json
from open_range.builder.npc.planner import DailyPlanner
from open_range.world_ir import GreenPersona


@dataclass
class Stimulus:
    """Incoming event that an NPC must react to (e.g. a phishing email)."""

    type: str
    sender: str
    subject: str
    content: str
    plausibility: float = 0.5


@dataclass
class NPCAction:
    """Decision made by an NPC in response to a stimulus."""

    action: str
    response_content: str = ""
    side_effects: list[str] = field(default_factory=list)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Prompts
# ---------------------------------------------------------------------------

NPC_ROUTINE_PROMPT = """\
You are simulating a corporate employee going about their normal workday.
You will receive your persona, available resources, recent memories, and
an optional plan hint for the current time slot.

Pick the NEXT natural work action. Stay in character for your role.
If a plan_hint is provided, follow it unless recent memories suggest
a more pressing task.

Return valid JSON:
{
  "action": "<browse|send_email|lookup|access_share|login|query_db|idle>",
  "target": "<a specific target from the available resources>",
  "detail": "<1-sentence description of what you are doing and why>",
  "email_body": "<if send_email, the message body; otherwise empty string>"
}

Guidelines:
- Pick targets from AVAILABLE RESOURCES (real pages, shares, users)
- recent_memories give context — reference prior events naturally
- Vary your actions — don't repeat the same action twice in a row
- Be mundane and realistic: checking records, status updates, reviewing docs
- Your role determines what you would naturally do
"""

NPC_REACT_PROMPT = """\
You are simulating an employee who received an unexpected message.
Based on your security_awareness, susceptibility, and prior experience
(recent_memories), decide how to respond. Stay in character.

Return valid JSON:
{
  "action": "<click_link|open_attachment|reply|share_credentials|ignore|report_to_IT|forward>",
  "response_content": "<your reply text if replying, otherwise empty string>",
  "side_effects": ["<what happens as a result>"]
}

Guidelines:
- security_awareness > 0.7: verify sender, check URLs, report suspicious messages
- security_awareness < 0.3: trusting, clicks links, may share credentials if asked
- If recent_memories include prior phishing attempts or security incidents,
  be more cautious regardless of base security_awareness
"""


class LLMNPCAgent:
    """Async NPC agent that autonomously lives its workday via LLM.

    Integrates MemoryStream and DailyPlanner to produce realistic,
    varied, and contextually coherent NPC behaviour.
    """

    def __init__(
        self,
        model: str | None = None,
        temperature: float = 0.5,
    ) -> None:
        self.model = model or os.environ.get(
            "OPENRANGE_NPC_MODEL", "claude-haiku-4-5-20251001"
        )
        self.temperature = temperature
        self._actions: list[dict[str, Any]] = []
        self._memory = MemoryStream()
        self._planner = DailyPlanner(model=self.model, temperature=temperature)

    def get_actions(self) -> list[dict[str, Any]]:
        """Return all recorded NPC actions for SIEM consumption."""
        return list(self._actions)

    # ------------------------------------------------------------------
    # Reactive: respond to external stimulus
    # ------------------------------------------------------------------

    async def decide(self, persona: GreenPersona, stimulus: Stimulus) -> NPCAction:
        """Decide how to respond to a stimulus (NPCBehavior protocol).

        Passes relevant memories as context so the NPC can reference
        prior incidents (e.g. a second phishing attempt is treated with
        more suspicion if the first was noticed).
        """
        relevant = self._memory.retrieve(
            query_tags=[stimulus.type, "suspicious", "security", "phishing"],
            top_k=3,
        )
        memory_context = [m.content for m in relevant]

        try:
            user_payload = (
                "Respond as this NPC employee in valid JSON.\n\n"
                + json.dumps({
                    "persona": {
                        "id": persona.id,
                        "role": persona.role,
                        "department": persona.department,
                        "awareness": persona.awareness,
                        "susceptibility": persona.susceptibility,
                        "recent_memories": memory_context,
                    },
                    "stimulus": {
                        "type": stimulus.type,
                        "sender": stimulus.sender,
                        "subject": stimulus.subject,
                        "content": stimulus.content,
                        "plausibility": stimulus.plausibility,
                    },
                })
            )
            response = await litellm.acompletion(
                model=self.model,
                messages=[
                    {"role": "system", "content": NPC_REACT_PROMPT},
                    {"role": "user", "content": user_payload},
                ],
                response_format={"type": "json_object"},
                temperature=self.temperature,
            )
            raw = _parse_json(response.choices[0].message.content)
            result = NPCAction(
                action=raw.get("action", "ignore"),
                response_content=raw.get("response_content", ""),
                side_effects=raw.get("side_effects", []),
            )
        except Exception as exc:
            logger.warning("NPC %s react failed: %s", persona.id, exc)
            result = NPCAction(action="ignore")

        # Record the reaction as a memory (entity-relationship triple)
        importance = 8.0 if result.action in ("report_to_IT", "share_credentials", "click_link") else 4.0
        self._memory.add(
            subject=persona.id,
            relation=f"reacted_to_{stimulus.type}_with",
            object_=result.action,
            importance=importance,
            tags=[stimulus.type, result.action, "reactive", "security"],
        )
        return result

    # ------------------------------------------------------------------
    # Proactive: what to do next at work
    # ------------------------------------------------------------------

    async def next_routine_action(
        self,
        persona: GreenPersona,
        env_context: dict[str, Any],
        plan_hint: dict[str, str] | None = None,
    ) -> dict[str, str]:
        """Ask the LLM what this NPC would naturally do next.

        Passes recent memories and the current plan hint so actions are
        contextually coherent and follow the daily schedule.
        """
        memory_context = self._memory.to_summary_list(5)

        try:
            user_payload = (
                "Pick this employee's next work action in valid JSON.\n\n"
                + json.dumps({
                    "persona": {
                        "id": persona.id,
                        "role": persona.role,
                        "department": persona.department,
                    },
                    "available_resources": env_context,
                    "recent_memories": memory_context,
                    "plan_hint": plan_hint,
                })
            )
            response = await litellm.acompletion(
                model=self.model,
                messages=[
                    {"role": "system", "content": NPC_ROUTINE_PROMPT},
                    {"role": "user", "content": user_payload},
                ],
                response_format={"type": "json_object"},
                temperature=self.temperature,
            )
            action = _parse_json(response.choices[0].message.content)
        except Exception as exc:
            logger.debug("NPC %s routine LLM failed: %s", persona.id, exc)
            action = _fallback_action(persona, env_context, plan_hint)

        # Record the action as a low-importance memory (entity-relationship triple)
        self._memory.add(
            subject=persona.id,
            relation=action.get("action", "idle"),
            object_=action.get("target", "") or action.get("detail", ""),
            importance=2.0,
            tags=[action.get("action", "idle"), "routine"],
        )
        return action

    # ------------------------------------------------------------------
    # Main loop
    # ------------------------------------------------------------------

    async def run_loop(
        self,
        persona: GreenPersona,
        containers: Any,
        snapshot: Any,
    ) -> None:
        """Run the NPC's autonomous workday.

        Each cycle:
        1. Reflect on accumulated memories (if threshold reached) and
           regenerate the daily plan with fresh insights.
        2. Pick and execute a scheduled routine work action.
        3. Check mailbox for incoming stimuli (phishing).
        4. React to any stimuli found.
        """
        from open_range.builder.npc.actions import NPCActionExecutor

        executor = NPCActionExecutor(containers, snapshot)

        env_context: dict[str, Any] = {
            "pages": executor._pages,
            "shares": executor._shares,
            "db_tables": executor._db_tables,
            "colleagues": executor._users,
        }

        mail_user = (
            persona.mailbox.split("@")[0]
            if "@" in persona.mailbox
            else persona.id.lower().split()[0]
        )

        base_interval = getattr(
            getattr(snapshot, "npc_traffic", None), "action_interval_min", None
        ) or 2
        interval_s = base_interval * 60

        # Generate the initial daily schedule
        await self._planner.plan_day(persona, env_context)

        logger.info(
            "NPC %s (%s) starting workday (every %dm, mood=%s, focus=%s)",
            persona.id,
            persona.role,
            base_interval,
            self._planner.mood,
            self._planner.focus,
        )

        while True:
            try:
                # --- Phase 0: Reflect and re-plan if enough memories ---
                if self._memory.needs_reflection():
                    unprocessed = self._memory.take_for_reflection()
                    reflections, adjusted = await self._planner.reflect(
                        persona, [m.content for m in unprocessed]
                    )
                    if reflections:
                        for r in reflections:
                            self._memory.add(
                                subject=persona.id,
                                relation="reflected_insight",
                                object_=r,
                                importance=7.0,
                                tags=["reflection", "insight"],
                            )
                        logger.debug(
                            "NPC %s reflected: %d insights", persona.id, len(reflections)
                        )
                    await self._planner.plan_day(persona, env_context, reflections=reflections)

                # --- Phase 1: Routine work action ---
                hint = self._planner.next_action_hint()
                plan_hint = (
                    {"action": hint.action, "target": hint.target, "detail": hint.detail}
                    if hint else None
                )
                routine = await self.next_routine_action(persona, env_context, plan_hint=plan_hint)
                log_entry = await executor.execute_routine(
                    persona,
                    routine.get("action", "idle"),
                    routine.get("target", ""),
                    routine.get("detail", ""),
                    routine.get("email_body", ""),
                )
                self._actions.append(log_entry)
                logger.debug("NPC %s: %s", persona.id, log_entry.get("detail", ""))

                # --- Phase 2: Check mailbox ---
                try:
                    mail_output = await containers.exec(
                        "mail",
                        f"find /var/mail/{mail_user} "
                        f"-newer /tmp/.npc_check_{mail_user} "
                        f"-type f 2>/dev/null | head -1",
                    )
                    await containers.exec("mail", f"touch /tmp/.npc_check_{mail_user}")

                    if mail_output and mail_output.strip():
                        email_file = mail_output.strip().split("\n")[0]
                        content = await containers.exec(
                            "mail", f"head -50 '{email_file}' 2>/dev/null || true",
                        )
                        if content and content.strip():
                            stimulus = Stimulus(
                                type="email",
                                sender="unknown",
                                subject="Incoming message",
                                content=content[:500],
                            )
                            react = await self.decide(persona, stimulus)
                            react_log = await executor.execute(persona, react)
                            react_log["stimulus_type"] = "email"
                            react_log["reactive"] = True
                            self._actions.append(react_log)
                except Exception as mail_exc:
                    logger.debug("NPC %s mail check: %s", persona.id, mail_exc)

                # --- Sleep with jitter ---
                await asyncio.sleep(interval_s * random.uniform(0.7, 1.3))

            except asyncio.CancelledError:
                logger.info("NPC %s workday ended", persona.id)
                break
            except Exception as exc:
                logger.warning("NPC %s loop error: %s", persona.id, exc)
                await asyncio.sleep(30)


# ---------------------------------------------------------------------------
# Fallback routine (no LLM)
# ---------------------------------------------------------------------------


def _fallback_action(
    persona: GreenPersona,
    env: dict[str, Any],
    plan_hint: dict[str, str] | None = None,
) -> dict[str, str]:
    """Pick a routine action without LLM.

    Respects the plan_hint when available; otherwise picks randomly from
    snapshot-derived resources.
    """
    if plan_hint and plan_hint.get("action"):
        return {
            "action": plan_hint["action"],
            "target": plan_hint.get("target", ""),
            "detail": plan_hint.get("detail", "Scheduled task"),
            "email_body": "",
        }

    pages = env.get("pages", ["/"])
    shares = env.get("shares", ["general"])
    colleagues = env.get("colleagues", [])

    actions: list[dict[str, str]] = [
        {"action": "browse", "target": random.choice(pages), "detail": "Checking portal", "email_body": ""},
        {"action": "idle", "target": "", "detail": "Reading documents at desk", "email_body": ""},
    ]
    if shares:
        actions.append({"action": "access_share", "target": random.choice(shares), "detail": "Checking files", "email_body": ""})
    if colleagues:
        actions.append({
            "action": "send_email",
            "target": random.choice(colleagues),
            "detail": "Status update",
            "email_body": "Quick check-in on today's items.",
        })
    return random.choice(actions)


# ---------------------------------------------------------------------------
# Simpler behavior classes (Level 0, no LLM)
# ---------------------------------------------------------------------------


class NullNPCBehavior:
    """No-op NPC behavior for Level 0."""

    async def decide(self, persona: GreenPersona, stimulus: Stimulus) -> NPCAction:
        return NPCAction(action="ignore")


class RuleBasedNPCBehavior:
    """Heuristic NPC decisions based on susceptibility scores."""

    async def decide(self, persona: GreenPersona, stimulus: Stimulus) -> NPCAction:
        susceptibility = persona.susceptibility.get(
            stimulus.type, persona.susceptibility.get("phishing_email", 0.5)
        )
        score = stimulus.plausibility * susceptibility
        if persona.awareness > 0.7 and score < 0.8:
            return NPCAction(action="report_to_IT", side_effects=["reported suspicious email to IT"])
        elif score > 0.6:
            return NPCAction(action="click_link", side_effects=["clicked link in email"])
        elif score > 0.3:
            return NPCAction(action="ignore")
        else:
            return NPCAction(action="report_to_IT", side_effects=["forwarded to security team"])
