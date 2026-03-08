"""LLM-driven NPC agent (Level 1).

Each NPC autonomously lives their workday -- browsing pages, emailing
colleagues, querying records, accessing shares.  Available actions are
derived from the SnapshotSpec so they adapt to whatever environment the
Builder LLM generated.  NPCs also react to incoming stimuli (phishing,
social engineering) based on their security_awareness profile.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import random
import re
import shlex
import time
from typing import Any

import litellm

from open_range.protocols import ContainerSet, NPCAction, NPCPersona, SnapshotSpec, Stimulus

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Prompts
# ---------------------------------------------------------------------------

NPC_ROUTINE_PROMPT = """\
You are simulating a corporate employee going about their normal workday. \
You will receive your persona, the available resources in this environment, \
and your recent activity.

Pick the NEXT natural work action. Stay in character for your role.

Return valid JSON:
{
  "action": "<browse|send_email|lookup|access_share|login|query_db|idle>",
  "target": "<a specific target from the available resources>",
  "detail": "<1-sentence description of what you're doing and why>",
  "email_body": "<if send_email, the message; otherwise empty>"
}

Guidelines:
- Pick targets from the AVAILABLE RESOURCES provided (real pages, shares, users)
- Vary your actions -- don't repeat the same thing twice in a row
- Be mundane and realistic: checking records, status updates, reviewing docs
- Your role determines what you'd naturally do (clinical staff look up records, \
  admin checks billing, IT reviews systems, executives read reports)
"""

NPC_REACT_PROMPT = """\
You are simulating an employee who received an unexpected message. \
Based on your security_awareness and susceptibility, decide how to respond. \
Stay in character. Return valid JSON:

{
  "action": "<click_link|open_attachment|reply|share_credentials|ignore|report_to_IT|forward>",
  "response_content": "<your reply text if replying, otherwise empty>",
  "side_effects": ["<what happens as a result>"]
}

- security_awareness > 0.7: verify sender, check URLs, report suspicious messages
- security_awareness < 0.3: trusting, clicks links, may share credentials if asked
"""


class LLMNPCAgent:
    """Async NPC agent that autonomously lives its workday via LLM."""

    def __init__(
        self,
        model: str | None = None,
        temperature: float = 0.3,
    ) -> None:
        self.model = model or os.environ.get(
            "OPENRANGE_NPC_MODEL", "azure/gpt-5.2-codex"
        )
        if "codex" in self.model.lower():
            self.temperature: float | None = None
        else:
            self.temperature = temperature
        self._actions: list[dict[str, Any]] = []

    def get_actions(self) -> list[dict[str, Any]]:
        """Return all recorded NPC actions for SIEM consumption."""
        return list(self._actions)

    # ------------------------------------------------------------------
    # Reactive: respond to external stimulus
    # ------------------------------------------------------------------

    async def decide(self, persona: NPCPersona, stimulus: Stimulus) -> NPCAction:
        """Decide how to respond to a stimulus (NPCBehavior protocol)."""
        try:
            user_payload = (
                "Respond as this NPC employee in valid JSON.\n\n"
                + json.dumps({
                    "persona": persona.model_dump(),
                    "stimulus": stimulus.model_dump(),
                })
            )
            kwargs: dict[str, Any] = {
                "model": self.model,
                "messages": [
                    {"role": "system", "content": NPC_REACT_PROMPT},
                    {"role": "user", "content": user_payload},
                ],
                "response_format": {"type": "json_object"},
            }
            if self.temperature is not None:
                kwargs["temperature"] = self.temperature

            response = await litellm.acompletion(**kwargs)
            raw = json.loads(response.choices[0].message.content)
            return NPCAction(
                action=raw.get("action", "ignore"),
                response_content=raw.get("response_content", ""),
                side_effects=raw.get("side_effects", []),
            )
        except Exception as exc:
            logger.warning("NPC %s react failed: %s", persona.name, exc)
            return NPCAction(action="ignore")

    # ------------------------------------------------------------------
    # Proactive: what to do next at work (derived from snapshot)
    # ------------------------------------------------------------------

    async def next_routine_action(
        self, persona: NPCPersona, env_context: dict[str, Any],
    ) -> dict[str, str]:
        """Ask LLM what this NPC would naturally do next.

        env_context contains available_pages, available_shares, etc.
        derived from the SnapshotSpec so the LLM picks real targets.
        """
        recent = [
            f"{a.get('action','?')}: {a.get('detail','')}"
            for a in self._actions[-5:]
        ]
        try:
            user_payload = (
                "Pick this employee's next work action in valid JSON.\n\n"
                + json.dumps({
                    "persona": {
                        "name": persona.name,
                        "role": persona.role,
                        "department": persona.department,
                    },
                    "available_resources": env_context,
                    "recent_actions": recent,
                })
            )
            kwargs: dict[str, Any] = {
                "model": self.model,
                "messages": [
                    {"role": "system", "content": NPC_ROUTINE_PROMPT},
                    {"role": "user", "content": user_payload},
                ],
                "response_format": {"type": "json_object"},
            }
            if self.temperature is not None:
                kwargs["temperature"] = self.temperature

            response = await litellm.acompletion(**kwargs)
            return json.loads(response.choices[0].message.content)
        except Exception as exc:
            logger.debug("NPC %s routine LLM failed: %s", persona.name, exc)
            return _fallback_action(persona, env_context)

    # ------------------------------------------------------------------
    # Main loop
    # ------------------------------------------------------------------

    async def run_loop(
        self,
        persona: NPCPersona,
        containers: ContainerSet,
        snapshot: SnapshotSpec,
    ) -> None:
        """Run the NPC's autonomous workday.

        Each cycle:
        1. Pick and execute a routine work action
        2. Check mailbox for incoming stimuli (phishing)
        3. React to any stimuli found
        """
        from open_range.builder.npc.actions import NPCActionExecutor

        executor = NPCActionExecutor(containers, snapshot)

        # Build environment context once from snapshot
        env_context = {
            "pages": executor._pages,
            "shares": executor._shares,
            "db_tables": executor._db_tables,
            "colleagues": executor._users,
        }

        email_acct = persona.accounts.get("email", "")
        mail_user = (
            email_acct.split("@")[0]
            if "@" in email_acct
            else persona.name.lower().split()[0]
        )
        # Sanitize mail_user to prevent path traversal / injection
        if not re.match(r"^[a-zA-Z0-9._-]+$", mail_user):
            mail_user = re.sub(r"[^a-zA-Z0-9._-]", "_", mail_user)

        base_interval = persona.routine.get("action_interval_min", 2)
        interval_s = base_interval * 60

        logger.info(
            "NPC %s (%s) starting workday (every %dm, %d pages, %d shares)",
            persona.name, persona.role, base_interval,
            len(env_context["pages"]), len(env_context["shares"]),
        )

        while True:
            try:
                # --- Phase 1: Routine work action ---
                routine = await self.next_routine_action(persona, env_context)
                log_entry = await executor.execute_routine(
                    persona,
                    routine.get("action", "idle"),
                    routine.get("target", ""),
                    routine.get("detail", ""),
                    routine.get("email_body", ""),
                )
                self._actions.append(log_entry)
                logger.debug("NPC %s: %s", persona.name, log_entry.get("detail", ""))

                # --- Phase 2: Check mailbox for incoming stimuli ---
                # Red may send real phishing emails via SMTP. Check multiple
                # mail spool locations for new messages.
                try:
                    safe_mail_user = shlex.quote(mail_user)
                    mail_host = executor._host_mail
                    mail_output = await containers.exec(
                        mail_host,
                        f"{{ find /var/spool/mail/ /var/mail/ "
                        f"/home/{safe_mail_user}/Maildir/new/ "
                        f"-newer /tmp/.npc_check_{safe_mail_user} "
                        f"-type f 2>/dev/null || true; }} | head -3",
                    )
                    await containers.exec(mail_host, f"touch /tmp/.npc_check_{safe_mail_user}")

                    if mail_output and mail_output.strip():
                        for email_file in mail_output.strip().split("\n")[:3]:
                            email_file = email_file.strip()
                            if not email_file:
                                continue
                            content = await containers.exec(
                                mail_host, f"head -50 {shlex.quote(email_file)} 2>/dev/null || true",
                            )
                            if not content or not content.strip():
                                continue
                            # Extract sender from email headers
                            sender = "unknown"
                            subject = "Incoming message"
                            for line in content.split("\n")[:20]:
                                if line.lower().startswith("from:"):
                                    sender = line.split(":", 1)[1].strip()
                                elif line.lower().startswith("subject:"):
                                    subject = line.split(":", 1)[1].strip()
                            stimulus = Stimulus(
                                type="email",
                                sender=sender,
                                subject=subject,
                                content=content[:500],
                                plausibility=0.7,
                            )
                            react = await self.decide(persona, stimulus)
                            react_log = await executor.execute(persona, react)
                            react_log["stimulus_type"] = "email"
                            react_log["reactive"] = True
                            self._actions.append(react_log)
                except Exception as mail_exc:
                    logger.debug("NPC %s mail check: %s", persona.name, mail_exc)

                # --- Sleep with jitter ---
                await asyncio.sleep(interval_s * random.uniform(0.7, 1.3))

            except asyncio.CancelledError:
                logger.info("NPC %s workday ended", persona.name)
                break
            except Exception as exc:
                logger.warning("NPC %s loop error: %s", persona.name, exc)
                await asyncio.sleep(30)


# ---------------------------------------------------------------------------
# Fallback routine (no LLM, picks from snapshot-derived resources)
# ---------------------------------------------------------------------------


def _fallback_action(persona: NPCPersona, env: dict[str, Any]) -> dict[str, str]:
    """Pick a routine action without LLM, using available resources."""
    pages = env.get("pages", ["/"])
    shares = env.get("shares", ["general"])
    colleagues = env.get("colleagues", [])

    actions = [
        {"action": "browse", "target": random.choice(pages) if pages else "/", "detail": "Checking portal"},
        {"action": "browse", "target": random.choice(pages) if pages else "/", "detail": "Reviewing page"},
        {"action": "idle", "target": "", "detail": "Reading documents at desk"},
    ]
    if shares:
        actions.append({"action": "access_share", "target": random.choice(shares), "detail": "Checking files"})
    if colleagues:
        actions.append({"action": "send_email", "target": random.choice(colleagues), "detail": "Status update", "email_body": "Quick check-in on today's items."})

    return random.choice(actions)


# ---------------------------------------------------------------------------
# Simpler behavior classes (Level 0, no LLM)
# ---------------------------------------------------------------------------


class NullNPCBehavior:
    """No-op NPC behavior for Level 0."""

    async def decide(self, persona: NPCPersona, stimulus: Stimulus) -> NPCAction:
        return NPCAction(action="ignore")


class RuleBasedNPCBehavior:
    """Heuristic NPC decisions based on susceptibility scores."""

    async def decide(self, persona: NPCPersona, stimulus: Stimulus) -> NPCAction:
        susceptibility = persona.susceptibility.get(
            stimulus.type, persona.susceptibility.get("phishing_email", 0.5)
        )
        score = stimulus.plausibility * susceptibility
        if persona.security_awareness > 0.7 and score < 0.8:
            return NPCAction(action="report_to_IT", side_effects=["reported suspicious email to IT"])
        elif score > 0.6:
            return NPCAction(action="click_link", side_effects=["clicked link in email"])
        elif score > 0.3:
            return NPCAction(action="ignore")
        else:
            return NPCAction(action="report_to_IT", side_effects=["forwarded to security team"])
