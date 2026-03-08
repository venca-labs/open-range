"""Level 0 chat traffic generator.

Generates realistic internal chat messages between NPC personas,
based on their roles, departments, and daily activities. This is
the chat equivalent of http_traffic.sh -- deterministic background
noise for the Blue team to filter.
"""

from __future__ import annotations

import random
import time
from typing import Any

from open_range.builder.npc.channels import ChatChannel
from open_range.protocols import NPCPersona


# Pre-defined message templates keyed by topic category.
# Each template is a (sender_role_hint, content) tuple.
_CHAT_TEMPLATES: list[dict[str, str]] = [
    {
        "topic": "IT",
        "messages": [
            "Has anyone else had trouble connecting to the VPN this morning?",
            "The printer on 3rd floor is jammed again.",
            "Can someone approve my access request for the staging server?",
            "Reminder: system maintenance window is tonight 11pm-2am.",
            "Is Jira down for anyone else right now?",
        ],
    },
    {
        "topic": "work",
        "messages": [
            "Can you review the Q4 report when you get a chance?",
            "Meeting moved to 2pm, same room.",
            "The client wants the deliverable by Friday.",
            "I've updated the spreadsheet with the latest numbers.",
            "Anyone have the link to the project wiki?",
        ],
    },
    {
        "topic": "security",
        "messages": [
            "Got a weird email from 'IT support' asking me to reset my password. Legit?",
            "Reminder: security awareness training is due by end of month.",
            "Please don't share credentials over chat.",
            "New phishing campaign targeting our domain. Be careful with attachments.",
            "Password rotation is happening next Monday.",
        ],
    },
    {
        "topic": "social",
        "messages": [
            "Anyone want to grab lunch at the new place down the street?",
            "Happy birthday! Cake in the break room at 3.",
            "Who's coming to the team outing on Saturday?",
            "The coffee machine is finally fixed!",
            "Does anyone have a phone charger I can borrow?",
        ],
    },
]


def _pick_message(topic: str | None = None) -> str:
    """Pick a random chat message, optionally from a specific topic."""
    if topic:
        for group in _CHAT_TEMPLATES:
            if group["topic"] == topic:
                return random.choice(group["messages"])
    # Random topic
    group = random.choice(_CHAT_TEMPLATES)
    return random.choice(group["messages"])


def generate_chat_traffic(
    personas: list[NPCPersona],
    channel: ChatChannel,
    num_messages: int = 10,
    seed: int | None = None,
) -> list[dict[str, Any]]:
    """Generate a batch of realistic internal chat messages.

    Args:
        personas: List of NPC personas to generate chat between.
        channel: ChatChannel instance to send messages through.
        num_messages: Number of messages to generate.
        seed: Optional random seed for reproducibility.

    Returns:
        List of message dicts (same as channel log entries).
    """
    if seed is not None:
        random.seed(seed)

    if len(personas) < 2:
        return []

    generated: list[dict[str, Any]] = []

    for _ in range(num_messages):
        # Pick sender and recipient (different people)
        sender_persona = random.choice(personas)
        recipient_candidates = [p for p in personas if p.name != sender_persona.name]
        if not recipient_candidates:
            continue
        recipient_persona = random.choice(recipient_candidates)

        # Pick a topic based on sender's role
        topic = None
        if "security" in sender_persona.department.lower():
            topic = random.choice(["security", "IT", "work"])
        elif "IT" in sender_persona.department.lower():
            topic = random.choice(["IT", "work"])
        # Otherwise random

        content = _pick_message(topic)
        msg = channel.send_message(
            sender=sender_persona.name,
            recipient=recipient_persona.name,
            content=content,
        )
        generated.append({
            "sender": msg.sender,
            "recipient": msg.recipient,
            "content": msg.content,
            "timestamp": msg.timestamp,
        })

    return generated
