"""LLM-driven NPC agent (Level 1).

Each NPC has a persona card and polls for incoming stimuli (emails, chat
messages) on a configurable interval. The agent decides how to respond
using an LLM call via LiteLLM.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
from typing import Any

import litellm

from open_range.protocols import ContainerSet, NPCAction, NPCPersona, Stimulus

logger = logging.getLogger(__name__)

NPC_SYSTEM_PROMPT = """\
You are simulating an employee in a corporate environment. You will receive \
your persona card and an incoming stimulus (email, chat message, etc.).

Based on your persona's security_awareness and susceptibility profile, decide \
how to respond. You must stay in character.

Return ONLY valid JSON:
{
  "action": "<click_link|open_attachment|reply|share_credentials|ignore|report_to_IT|forward>",
  "response_content": "<your reply text if action is reply/forward, empty otherwise>",
  "side_effects": ["<description of side effect>"]
}

Guidelines:
- High security_awareness (>0.7): suspicious of unusual requests, verify sender, \
  report phishing attempts.
- Low security_awareness (<0.3): trusting, clicks links readily, may share \
  credentials if asked politely.
- Always consider the stimulus plausibility and your susceptibility profile.
- Never reveal that you are an AI or break character.
"""


class LLMNPCAgent:
    """Async LLM NPC agent that responds to stimuli based on persona."""

    def __init__(
        self,
        model: str | None = None,
        temperature: float = 0.3,
    ) -> None:
        self.model = model or os.environ.get(
            "OPENRANGE_NPC_MODEL", "anthropic/claude-haiku-4-5-20251001"
        )
        self.temperature = temperature

    async def decide(
        self,
        persona: NPCPersona,
        stimulus: Stimulus,
    ) -> NPCAction:
        """Decide how an NPC responds to a stimulus via LLM.

        This satisfies the NPCBehavior protocol.
        """
        try:
            response = await litellm.acompletion(
                model=self.model,
                messages=[
                    {"role": "system", "content": NPC_SYSTEM_PROMPT},
                    {
                        "role": "user",
                        "content": json.dumps(
                            {
                                "persona": persona.model_dump(),
                                "stimulus": stimulus.model_dump(),
                            }
                        ),
                    },
                ],
                response_format={"type": "json_object"},
                temperature=self.temperature,
            )

            raw = json.loads(response.choices[0].message.content)
            return NPCAction(
                action=raw.get("action", "ignore"),
                response_content=raw.get("response_content", ""),
                side_effects=raw.get("side_effects", []),
            )

        except Exception as exc:
            logger.warning(
                "NPC %s LLM decision failed, defaulting to ignore: %s",
                persona.name,
                exc,
            )
            return NPCAction(action="ignore")

    async def run_loop(
        self,
        persona: NPCPersona,
        containers: ContainerSet,
    ) -> None:
        """Run the NPC agent loop, polling for stimuli on the persona's schedule.

        This loop runs as an asyncio task, checking for incoming emails
        and processing them according to the persona's schedule.
        """
        interval = persona.routine.get("email_check_interval_min", 15)
        interval_s = interval * 60

        logger.info(
            "NPC %s starting loop (check every %d min)",
            persona.name,
            interval,
        )

        while True:
            try:
                await asyncio.sleep(interval_s)

                # In a full implementation, this would:
                # 1. docker exec into mail container to check persona's mailbox
                # 2. Parse new emails into Stimulus objects
                # 3. Call self.decide() for each stimulus
                # 4. Execute side effects (click links, reply, etc.)
                #
                # For now, the loop just keeps the task alive.
                # The actual stimulus injection happens when Red sends
                # phishing emails via the environment's step() method.

                logger.debug("NPC %s checked mailbox (no new stimuli)", persona.name)

            except asyncio.CancelledError:
                logger.info("NPC %s loop cancelled", persona.name)
                break
            except Exception as exc:
                logger.warning("NPC %s loop error: %s", persona.name, exc)
                await asyncio.sleep(30)  # back off on error


class NullNPCBehavior:
    """No-op NPC behavior for Level 0 (shell scripts handle everything)."""

    async def decide(
        self,
        persona: NPCPersona,
        stimulus: Stimulus,
    ) -> NPCAction:
        """Always ignore -- Level 0 NPCs don't process stimuli."""
        return NPCAction(action="ignore")


class RuleBasedNPCBehavior:
    """Heuristic NPC decisions based on susceptibility scores. No LLM calls."""

    async def decide(
        self,
        persona: NPCPersona,
        stimulus: Stimulus,
    ) -> NPCAction:
        """Decide based on persona susceptibility and stimulus plausibility."""
        # Get the susceptibility score for this stimulus type
        susceptibility = persona.susceptibility.get(
            f"{stimulus.type}", persona.susceptibility.get("phishing_email", 0.5)
        )
        score = stimulus.plausibility * susceptibility

        if persona.security_awareness > 0.7 and score < 0.8:
            return NPCAction(
                action="report_to_IT",
                side_effects=["reported suspicious email to IT"],
            )
        elif score > 0.6:
            return NPCAction(
                action="click_link",
                side_effects=["clicked link in email"],
            )
        elif score > 0.3:
            return NPCAction(action="ignore")
        else:
            return NPCAction(
                action="report_to_IT",
                side_effects=["forwarded suspicious email to security team"],
            )
