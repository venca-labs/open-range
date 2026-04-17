"""Canned and LLM-generated email content for NPC communication.

Provides template-based email content for offline mode and an async
LLM generation path for online mode.  Templates are keyed by
(sender_role, action_context) and personalized with recipient details.
"""

from __future__ import annotations

import hashlib
import random


def generate_email_content(
    sender_role: str,
    sender_name: str,
    recipient_name: str,
    recipient_role: str,
    recipient_dept: str,
    context: str = "",
    seed: int = 0,
) -> dict[str, str]:
    """Generate a subject + body for an NPC email.

    Returns {"subject": ..., "body": ...} using template pools.
    Deterministic for the same (sender, recipient, seed) combination.
    """
    rng = random.Random(
        int(
            hashlib.md5(f"{sender_name}:{recipient_name}:{seed}".encode()).hexdigest()[
                :8
            ],
            16,
        )
    )

    pool = _pool_for_role(sender_role)
    template = rng.choice(pool)

    subs = {
        "sender": sender_name,
        "name": recipient_name,
        "role": recipient_role,
        "dept": recipient_dept,
        "context": context or "our current project",
    }
    return {
        "subject": template["subject"].format_map(_SafeMap(subs)),
        "body": template["body"].format_map(_SafeMap(subs)),
    }


def generate_reply_content(
    replier_role: str,
    replier_name: str,
    original_sender: str,
    original_subject: str,
    original_body: str,
    seed: int = 0,
) -> dict[str, str]:
    """Generate a reply to an email.

    Returns {"subject": "Re: ...", "body": ...} using reply templates.
    """
    rng = random.Random(
        int(
            hashlib.md5(
                f"{replier_name}:reply:{original_sender}:{seed}".encode()
            ).hexdigest()[:8],
            16,
        )
    )

    pool = _REPLY_TEMPLATES
    template = rng.choice(pool)

    from open_range.builder.npc.identity import display_name

    sender_short = display_name(original_sender)
    subs = {
        "sender": sender_short,
        "name": sender_short,
        "subject": original_subject,
    }
    return {
        "subject": f"Re: {original_subject}",
        "body": template["body"].format_map(_SafeMap(subs)),
    }


class _SafeMap(dict):
    def __missing__(self, key: str) -> str:
        return f"{{{key}}}"


# ---------------------------------------------------------------------------
# Template pools
# ---------------------------------------------------------------------------


def _pool_for_role(role: str) -> list[dict[str, str]]:
    lowered = role.lower()
    if any(kw in lowered for kw in ("it", "admin", "engineer", "devops", "security")):
        return _IT_EMAILS
    if any(kw in lowered for kw in ("manager", "director", "vp", "executive", "chief")):
        return _EXEC_EMAILS
    if any(kw in lowered for kw in ("sales", "marketing", "account")):
        return _SALES_EMAILS
    return _GENERIC_EMAILS


_IT_EMAILS = [
    {
        "subject": "{context} — {dept} Impact",
        "body": "Hi {name}, reaching out about {context}. This touches {dept} so I wanted to keep you "
        "in the loop. No action needed on your end yet — I'll let you know if anything changes.",
    },
    {
        "subject": "RE: {context}",
        "body": "Hi {name}, update on {context}. I've completed the work on my side. If this affects "
        "anything in {dept}, let me know and I'll coordinate with your team.",
    },
    {
        "subject": "{context} — Status Update",
        "body": "Hi {name}, quick status on {context}. Everything looks stable. I ran the checks this "
        "morning and no issues flagged for {dept}. Let me know if you're seeing anything different.",
    },
    {
        "subject": "{context} — Action Required",
        "body": "Hi {name}, I need your input on {context}. Specifically, can you confirm whether {dept} "
        "has any dependencies here? I'd like to wrap this up by end of day.",
    },
]

_EXEC_EMAILS = [
    {
        "subject": "RE: {context}",
        "body": "Hi {name}, I've reviewed the materials for {context}. {dept}'s numbers look strong. "
        "Let's discuss the two items I flagged in our next sync.",
    },
    {
        "subject": "Approved: {context}",
        "body": "Hi {name}, I've approved the request related to {context}. Please coordinate with "
        "{dept} on the timeline. Good work pulling this together.",
    },
    {
        "subject": "{context} — Action Items for {dept}",
        "body": "Hi {name}, a few action items from today's discussion on {context} that touch {dept}: "
        "1) Finalize the deliverables by Friday, 2) Schedule the cross-team review. Let me know if you need support.",
    },
    {
        "subject": "{context} — Follow Up",
        "body": "Hi {name}, following up on {context}. I'd like {dept}'s perspective before we finalize. "
        "Can you send me your thoughts by end of week?",
    },
]

_SALES_EMAILS = [
    {
        "subject": "{context} — {dept} Collaboration",
        "body": "Hi {name}, reaching out about {context}. I think there's an opportunity to involve "
        "{dept} here. I've put together some numbers — when can we connect to discuss?",
    },
    {
        "subject": "{context} — Ready for {name}'s Review",
        "body": "Hi {name}, the materials for {context} are ready for your review. I've tailored "
        "the {dept} section based on your earlier feedback. Let me know your thoughts.",
    },
    {
        "subject": "{context} — Update",
        "body": "Hi {name}, quick update on {context}. Two new developments this week that are "
        "relevant to {dept}. I'll loop you in on the follow-up calls tomorrow.",
    },
    {
        "subject": "{context} — Need Your Input",
        "body": "Hi {name}, working on {context} and could use your perspective from the {dept} side. "
        "Can we sync for 15 minutes this afternoon?",
    },
]

_GENERIC_EMAILS = [
    {
        "subject": "{context} — {dept} Sync",
        "body": "Hi {name}, checking in on {context} as it relates to {dept}. "
        "Let me know if anything shifted or if you need help with any blockers.",
    },
    {
        "subject": "{context} — Status Update",
        "body": "Hi {name}, quick status update on {context}. Everything is on track from my side. "
        "I'll flag anything that needs {dept}'s attention before end of day.",
    },
    {
        "subject": "{context} — Shared Document",
        "body": "Hi {name}, I've shared the updated document for {context}. "
        "Take a look when you get a chance — it has the latest {dept} data.",
    },
    {
        "subject": "RE: {context}",
        "body": "Hi {name}, following up on {context}. Wanted to make sure {dept} is aligned on "
        "the next steps. Let me know if you have any questions.",
    },
]

_REPLY_TEMPLATES = [
    {
        "body": "Thanks {name}, got it. I'll take a look and follow up if I have questions.",
    },
    {
        "body": "Hi {name}, appreciate the update. This looks good — no concerns from my end.",
    },
    {
        "body": "Thanks for the heads up, {name}. I'll adjust my schedule accordingly. "
        "Let me know if anything else comes up.",
    },
    {
        "body": "Got it, {name}. I'll review this today and circle back with any feedback.",
    },
    {
        "body": "Hi {name}, thanks for sending this over. I'll coordinate with my team and get back to you.",
    },
]
