"""NPC daily planner.

Generates a workday schedule for each NPC persona based on their role,
recent memories, and the available environment resources.  The schedule
guides the NPC's next_routine_action calls, producing varied traffic
patterns across the workday instead of a uniform random loop.

LLM-driven when a model is provided; falls back to a role-keyed template
schedule so the planner works in mock mode and unit tests without any
API calls.
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass
from typing import Any

try:
    import litellm
except ImportError:  # pragma: no cover
    litellm = None  # type: ignore[assignment]

from open_range.world_ir import GreenPersona


def _parse_json(content: str) -> Any:
    """Parse JSON from an LLM response, stripping markdown code fences if present."""
    content = content.strip()
    if content.startswith("```"):
        # Drop the opening fence line (```json or ```) and the closing ```
        lines = content.splitlines()
        inner = lines[1:-1] if lines[-1].strip() == "```" else lines[1:]
        content = "\n".join(inner).strip()
    return json.loads(content)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Prompts
# ---------------------------------------------------------------------------

_PLAN_SYSTEM_PROMPT = """\
Generate a realistic workday schedule for a corporate employee.
Based on their role and recent reflections, plan their day as a sequence
of concrete work actions spread across 9am–5pm.

Return valid JSON:
{
  "schedule": [
    {"hour": 9, "action": "browse", "target": "/dashboard", "detail": "Review morning metrics"},
    {"hour": 10, "action": "send_email", "target": "colleague", "detail": "Follow up on project"},
    ...
  ],
  "mood": "<focused|distracted|busy|relaxed>",
  "focus": "<one sentence: what they are primarily working on today>"
}

Actions must be one of: browse, send_email, lookup, access_share, login, query_db, idle
Schedule 6–8 actions. Match action type to role (IT does more logins/queries, \
marketing does more browsing/email, executives do more email/reviewing).
Spread actions naturally across the day with idle time around lunch (12–13).
"""

_REFLECT_SYSTEM_PROMPT = """\
You are reflecting on a corporate employee's recent work experiences.
Given their recent memories, produce 1–3 high-level insights that should
influence their future behaviour.

Return valid JSON:
{
  "reflections": [
    "<concise insight 1>",
    "<concise insight 2>"
  ],
  "adjusted_awareness": <null, or a float 0.0–1.0 if the employee's security
                         awareness should shift based on what they experienced>
}

Focus on: work patterns, security incidents, colleague interactions.
Be concise — one sentence per insight.
"""


# ---------------------------------------------------------------------------
# Data
# ---------------------------------------------------------------------------


@dataclass
class ScheduledAction:
    """A single entry in a DailyPlanner schedule."""

    hour: int    # 9–17 (9am–5pm)
    action: str  # browse | send_email | lookup | access_share | login | query_db | idle
    target: str
    detail: str


# ---------------------------------------------------------------------------
# DailyPlanner
# ---------------------------------------------------------------------------


class DailyPlanner:
    """Generates and tracks a daily schedule for one NPC persona.

    Usage::

        planner = DailyPlanner(model="claude-haiku-4-5-20251001")
        await planner.plan_day(persona, env_context)

        # In the run loop:
        hint = planner.next_action_hint()  # ScheduledAction | None
    """

    def __init__(
        self,
        model: str | None = None,
        temperature: float = 0.5,
    ) -> None:
        self.model = model
        self.temperature = temperature
        self._schedule: list[ScheduledAction] = []
        self._schedule_index: int = 0
        self._mood: str = "focused"
        self._focus: str = "routine work"
        self._day_start: float = time.time()

    # ------------------------------------------------------------------
    # Clock
    # ------------------------------------------------------------------

    def _simulated_hour(self) -> int:
        """Map real elapsed time to a workday hour (9–17).

        The mapping stretches or compresses real time so that a typical
        episode (~30 min) covers the full 9am–5pm window.
        """
        elapsed_min = (time.time() - self._day_start) / 60.0
        # 480 real minutes → full 8-hour workday
        progress = min(elapsed_min / 480.0, 1.0)
        return 9 + int(progress * 8)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def next_action_hint(self) -> ScheduledAction | None:
        """Return the next scheduled action that is due, or None.

        Advances the internal pointer; each action is yielded at most once.
        """
        current_hour = self._simulated_hour()
        while self._schedule_index < len(self._schedule):
            action = self._schedule[self._schedule_index]
            if action.hour <= current_hour:
                self._schedule_index += 1
                return action
            break
        return None

    @property
    def mood(self) -> str:
        return self._mood

    @property
    def focus(self) -> str:
        return self._focus

    # ------------------------------------------------------------------
    # LLM / template schedule generation
    # ------------------------------------------------------------------

    async def plan_day(
        self,
        persona: GreenPersona,
        env_context: dict[str, Any],
        reflections: list[str] | None = None,
    ) -> None:
        """Generate (or regenerate) the daily schedule.

        Uses the LLM when ``self.model`` is set; falls back to the
        role-keyed template otherwise.
        """
        self._day_start = time.time()
        self._schedule_index = 0

        if not self.model:
            self._schedule = _template_schedule(persona)
            return

        try:

            payload = {
                "persona": {
                    "name": persona.id,
                    "role": persona.role,
                    "department": persona.department,
                    "typical_actions": list(persona.routine),
                },
                "available_resources": {k: v for k, v in env_context.items() if v},
                "reflections": reflections or [],
            }
            response = await litellm.acompletion(
                model=self.model,
                messages=[
                    {"role": "system", "content": _PLAN_SYSTEM_PROMPT},
                    {"role": "user", "content": json.dumps(payload)},
                ],
                response_format={"type": "json_object"},
                temperature=self.temperature,
            )
            data = _parse_json(response.choices[0].message.content)
            self._schedule = [
                ScheduledAction(
                    hour=int(s.get("hour", 9)),
                    action=str(s.get("action", "idle")),
                    target=str(s.get("target", "")),
                    detail=str(s.get("detail", "")),
                )
                for s in data.get("schedule", [])
            ]
            self._schedule.sort(key=lambda s: s.hour)
            self._mood = str(data.get("mood", "focused"))
            self._focus = str(data.get("focus", "routine work"))
            logger.debug(
                "DailyPlanner: %s — %d actions planned (mood=%s)",
                persona.id,
                len(self._schedule),
                self._mood,
            )
        except Exception as exc:
            logger.debug(
                "DailyPlanner LLM failed for %s (%s) — using template",
                persona.id,
                exc,
            )
            self._schedule = _template_schedule(persona)

    async def reflect(
        self,
        persona: GreenPersona,
        recent_memory_contents: list[str],
    ) -> tuple[list[str], float | None]:
        """Summarise recent memories into higher-level insights.

        Returns ``(reflections, adjusted_awareness_or_None)``.
        Does nothing (returns empty) when no model is configured or the
        memory list is empty.
        """
        if not self.model or not recent_memory_contents:
            return [], None

        try:

            payload = {
                "persona": {
                    "name": persona.id,
                    "role": persona.role,
                    "security_awareness": persona.awareness,
                },
                "recent_memories": recent_memory_contents[-15:],
            }
            response = await litellm.acompletion(
                model=self.model,
                messages=[
                    {"role": "system", "content": _REFLECT_SYSTEM_PROMPT},
                    {"role": "user", "content": json.dumps(payload)},
                ],
                response_format={"type": "json_object"},
                temperature=0.3,
            )
            data = _parse_json(response.choices[0].message.content)
            reflections = [str(r) for r in data.get("reflections", [])]
            raw_adj = data.get("adjusted_awareness")
            adjusted: float | None = float(raw_adj) if raw_adj is not None else None
            logger.debug(
                "Reflection for %s: %d insights, adjusted_awareness=%s",
                persona.id,
                len(reflections),
                adjusted,
            )
            return reflections, adjusted
        except Exception as exc:
            logger.debug("Reflection failed for %s: %s", persona.id, exc)
            return [], None


# ---------------------------------------------------------------------------
# Role-keyed template schedules (no LLM required)
# ---------------------------------------------------------------------------

_IT_SCHEDULE = [
    ScheduledAction(9, "login", "/admin", "Morning system check"),
    ScheduledAction(10, "query_db", "", "Review application logs"),
    ScheduledAction(11, "browse", "/status", "Service health dashboard"),
    ScheduledAction(12, "send_email", "", "IT ticket follow-up"),
    ScheduledAction(13, "idle", "", "Lunch"),
    ScheduledAction(14, "access_share", "configs", "Update configuration files"),
    ScheduledAction(15, "query_db", "", "Afternoon health check"),
    ScheduledAction(16, "send_email", "", "End-of-day status report"),
]

_EXECUTIVE_SCHEDULE = [
    ScheduledAction(9, "browse", "/reports", "Morning KPI review"),
    ScheduledAction(10, "send_email", "", "Respond to overnight messages"),
    ScheduledAction(11, "browse", "/dashboard", "Review team dashboards"),
    ScheduledAction(12, "send_email", "", "Approve pending requests"),
    ScheduledAction(13, "idle", "", "Executive lunch"),
    ScheduledAction(14, "browse", "/reports", "Afternoon review"),
    ScheduledAction(15, "send_email", "", "Stakeholder update"),
    ScheduledAction(16, "idle", "", "Planning for tomorrow"),
]

_SALES_SCHEDULE = [
    ScheduledAction(9, "browse", "/", "Morning portal check"),
    ScheduledAction(10, "send_email", "", "Client follow-ups"),
    ScheduledAction(11, "lookup", "leads", "Research prospects"),
    ScheduledAction(12, "send_email", "", "Proposal emails"),
    ScheduledAction(13, "idle", "", "Lunch"),
    ScheduledAction(14, "browse", "/campaigns", "Campaign review"),
    ScheduledAction(15, "access_share", "marketing", "Update collateral"),
    ScheduledAction(16, "send_email", "", "EOD pipeline update"),
]

_GENERIC_SCHEDULE = [
    ScheduledAction(9, "browse", "/", "Morning check-in"),
    ScheduledAction(10, "send_email", "", "Team communication"),
    ScheduledAction(11, "lookup", "", "Data lookup"),
    ScheduledAction(12, "idle", "", "Lunch"),
    ScheduledAction(13, "browse", "/", "Afternoon tasks"),
    ScheduledAction(14, "access_share", "shared", "File access"),
    ScheduledAction(15, "send_email", "", "Status update"),
    ScheduledAction(16, "idle", "", "Wrap up"),
]

_IT_KEYWORDS = ("it", "admin", "sysadmin", "engineer", "devops", "security", "network", "ciso", "cto")
_EXEC_KEYWORDS = ("manager", "director", "executive", "vp", "president", "chief", "head of")
_SALES_KEYWORDS = ("sales", "marketing", "coordinator", "account", "business development")


def _template_schedule(persona: GreenPersona) -> list[ScheduledAction]:
    """Return a pre-built schedule matched to the persona's role."""
    role = persona.role.lower()
    if any(kw in role for kw in _IT_KEYWORDS):
        return list(_IT_SCHEDULE)
    if any(kw in role for kw in _EXEC_KEYWORDS):
        return list(_EXECUTIVE_SCHEDULE)
    if any(kw in role for kw in _SALES_KEYWORDS):
        return list(_SALES_SCHEDULE)
    return list(_GENERIC_SCHEDULE)
