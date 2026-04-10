"""NIM-powered episode narrator — Sims-style commentary on runtime events."""

from __future__ import annotations

import json
import logging
import os
from typing import Any

from open_range.runtime_types import RuntimeEvent

logger = logging.getLogger(__name__)

_ACTOR_EMOJI = {"red": "🔴", "blue": "🔵", "green": "🟢"}
_EVENT_VERBS: dict[str, str] = {
    "InitialAccess": "breaches",
    "CredentialObtained": "steals credentials from",
    "UnauthorizedCredentialUse": "uses stolen credentials on",
    "PrivilegeEscalation": "escalates privileges on",
    "CrossZoneTraversal": "pivots across zones to",
    "SensitiveAssetRead": "exfiltrates data from",
    "PersistenceEstablished": "establishes persistence on",
    "DetectionAlertRaised": "raises an alert on",
    "ContainmentApplied": "contains a threat on",
    "PatchApplied": "patches a vulnerability on",
    "RecoveryCompleted": "completes recovery on",
    "ServiceDegraded": "degrades",
    "BenignUserAction": "performs routine work on",
    "SuspiciousActionObserved": "observes suspicious activity on",
}


def fallback_narrate(events: list[RuntimeEvent]) -> str:
    """Generate simple text narration without calling an LLM."""
    lines: list[str] = []
    for ev in events[-5:]:
        emoji = _ACTOR_EMOJI.get(ev.actor, "⚪")
        verb = _EVENT_VERBS.get(ev.event_type, "interacts with")
        line = f"{emoji} {ev.actor.capitalize()} {verb} {ev.target_entity}"
        if ev.malicious:
            line += " ⚠️"
        lines.append(line)
    return "\n".join(lines)


async def nim_narrate(events: list[RuntimeEvent]) -> str:
    """Call NIM (Kimi K2 or configured model) to generate dramatic narration."""
    api_key = os.environ.get("NVIDIA_API_KEY", "")
    base_url = os.environ.get("OPENAI_BASE_URL", "https://integrate.api.nvidia.com/v1")
    model = os.environ.get("MODEL_ID", "moonshotai/kimi-k2-instruct")

    if not api_key:
        logger.debug("No NVIDIA_API_KEY — using fallback narrator")
        return fallback_narrate(events)

    event_digest = []
    for ev in events[-8:]:
        event_digest.append(
            {
                "time": round(ev.time, 1),
                "actor": ev.actor,
                "type": ev.event_type,
                "source": ev.source_entity,
                "target": ev.target_entity,
                "malicious": ev.malicious,
            }
        )

    system_prompt = (
        "You are the narrator of a cybersecurity simulation, like a dramatic "
        "Sims-style commentator. Describe what's happening in 2-3 vivid, concise "
        "sentences. Use emoji sparingly. Reference specific services and actors. "
        "Be dramatic but accurate. Never mention you are an AI."
    )

    payload: dict[str, Any] = {
        "model": model,
        "messages": [
            {"role": "system", "content": system_prompt},
            {
                "role": "user",
                "content": (
                    "Narrate these cyber range events:\n"
                    f"```json\n{json.dumps(event_digest, indent=2)}\n```"
                ),
            },
        ],
        "max_tokens": 200,
        "temperature": 0.8,
    }

    try:
        import httpx

        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(
                f"{base_url.rstrip('/')}/chat/completions",
                json=payload,
                headers={
                    "Authorization": f"Bearer {api_key}",
                    "Content-Type": "application/json",
                },
            )
            resp.raise_for_status()
            data = resp.json()
            return data["choices"][0]["message"]["content"].strip()
    except Exception:
        logger.warning("NIM narration failed, using fallback", exc_info=True)
        return fallback_narrate(events)
