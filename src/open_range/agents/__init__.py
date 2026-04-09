"""NPC agent system for enterprise simulation.

Provides:
- A lightweight ``NPCAgent`` with composable components (memory,
  personality, routine, social).
- ``PersonaFactory`` — generates realistic enterprise office workers
  with departments, routines, susceptibility profiles, and social
  relationships.
- Dispatch helpers shared with the legacy ``ScriptedGreenScheduler``.

Design goals:
- **Generalizable**: NPCs work in any enterprise domain (SaaS, finance,
  healthcare) — the persona factory is parameterized by org structure.
- **Scalable**: O(k) per-event processing via perception filters.
  No global broadcasts. Memory is per-agent, bounded.
- **Not over-engineered**: No abstract protocol hierarchies. Concrete
  classes with clear responsibilities. ~400 lines total.

The runtime remains the "Game Master" — it resolves NPC intents into
concrete execution. NPCs propose actions; the runtime decides outcomes.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from typing import Any

from open_range.runtime_types import Action, RuntimeEvent
from open_range.world_ir import GreenPersona


# ---------------------------------------------------------------------------
# Memory
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class MemoryEntry:
    """A single timestamped observation."""

    time: float
    event_type: str
    target: str
    importance: float = 0.5
    malicious: bool = False
    suspicious: bool = False


class Memory:
    """Sliding-window memory with recency × importance retrieval."""

    __slots__ = ("_entries", "_capacity")

    def __init__(self, capacity: int = 50) -> None:
        self._entries: list[MemoryEntry] = []
        self._capacity = capacity

    def add(self, event: RuntimeEvent) -> None:
        importance = 0.9 if event.malicious else (0.7 if event.suspicious else 0.3)
        self._entries.append(
            MemoryEntry(
                time=event.time,
                event_type=event.event_type,
                target=event.target_entity,
                importance=importance,
                malicious=event.malicious,
                suspicious=event.suspicious,
            )
        )
        if len(self._entries) > self._capacity:
            self._entries = self._entries[-self._capacity :]

    def top(self, k: int = 5, current_time: float = 0.0) -> list[MemoryEntry]:
        """Return k most relevant memories (recency × importance)."""
        if not self._entries:
            return []
        scored = []
        for e in self._entries:
            recency = 1.0 / (1.0 + max(0.0, current_time - e.time) * 0.1)
            scored.append((e, recency * e.importance))
        scored.sort(key=lambda p: -p[1])
        return [e for e, _ in scored[:k]]

    def suspicious_count(self) -> int:
        return sum(1 for e in self._entries if e.suspicious or e.malicious)

    def reset(self) -> None:
        self._entries.clear()

    def to_dicts(self) -> list[dict[str, Any]]:
        return [
            {
                "time": e.time,
                "type": e.event_type,
                "target": e.target,
                "malicious": e.malicious,
            }
            for e in self._entries
        ]


# ---------------------------------------------------------------------------
# NPCAgent — one per persona, owns its own state
# ---------------------------------------------------------------------------


@dataclass
class NPCAgent:
    """A lightweight autonomous NPC.

    Each agent has:
    - ``persona``: the manifest-defined identity
    - ``memory``: sliding-window observation log
    - ``effective_awareness``: starts at persona.awareness, escalates
      with suspicious observations
    - ``relationships``: trust scores to other NPCs (auto-derived from
      department/host proximity)
    """

    persona: GreenPersona
    memory: Memory = field(default_factory=Memory)
    effective_awareness: float = 0.5
    relationships: dict[str, float] = field(default_factory=dict)
    _obs_count: int = field(default=0, repr=False)

    def __post_init__(self) -> None:
        self.effective_awareness = self.persona.awareness

    def observe(self, event: RuntimeEvent) -> None:
        """Record an event and update awareness."""
        self.memory.add(event)
        if event.suspicious or event.malicious:
            self._obs_count += 1
            self.effective_awareness = min(
                1.0, self.persona.awareness + self._obs_count * 0.1
            )

    def routine_action(self, slot: int) -> Action:
        """Propose the routine action for this time slot."""
        routine = (
            self.persona.routine[slot % len(self.persona.routine)]
            if self.persona.routine
            else "browse_app"
        )
        kind, service = _routine_dispatch(routine)
        return Action(
            actor_id=self.persona.id,
            role="green",
            kind=kind,
            payload={
                "routine": routine,
                "service": service,
                "host": self.persona.home_host,
                "mailbox": self.persona.mailbox,
            },
        )

    def gossip_action(self, event: RuntimeEvent) -> Action | None:
        """Warn the most trusted colleague about a suspicious event."""
        if not self.relationships:
            return None
        best_id, best_trust = max(self.relationships.items(), key=lambda p: p[1])
        if best_trust < 0.5:
            return None
        return Action(
            actor_id=self.persona.id,
            role="green",
            kind="chat",
            payload={
                "to": best_id,
                "message": f"Heads up — saw {event.event_type} on {event.target_entity}",
                "service": "svc-web",
                "gossip": True,
            },
        )

    def reset(self) -> None:
        self.memory.reset()
        self.effective_awareness = self.persona.awareness
        self._obs_count = 0


# ---------------------------------------------------------------------------
# Persona factory — generates realistic enterprise workers
# ---------------------------------------------------------------------------

# Department templates: (department, roles, routines, base_awareness, susceptibility_profile)
_DEPARTMENTS: list[dict[str, Any]] = [
    {
        "department": "Engineering",
        "roles": ["Software Engineer", "DevOps Engineer", "QA Engineer", "Tech Lead"],
        "routines": [
            ("browse_app", "check_mail", "access_fileshare", "browse_app"),
            ("check_mail", "browse_app", "triage_alerts", "browse_app"),
            ("browse_app", "browse_app", "check_mail", "access_fileshare"),
        ],
        "awareness_range": (0.5, 0.8),
        "susceptibility": {"phishing": 0.3, "credential_theft": 0.2},
    },
    {
        "department": "IT Security",
        "roles": ["Security Analyst", "SOC Analyst", "Security Engineer"],
        "routines": [
            ("triage_alerts", "check_mail", "triage_alerts", "browse_app"),
            ("triage_alerts", "triage_alerts", "check_mail", "review_idp"),
        ],
        "awareness_range": (0.7, 0.95),
        "susceptibility": {"phishing": 0.1, "credential_theft": 0.1},
    },
    {
        "department": "Finance",
        "roles": ["Accountant", "Financial Analyst", "Payroll Specialist"],
        "routines": [
            ("check_mail", "open_payroll_dashboard", "browse_app", "check_mail"),
            ("open_payroll_dashboard", "check_mail", "access_fileshare", "check_mail"),
        ],
        "awareness_range": (0.3, 0.5),
        "susceptibility": {"phishing": 0.6, "credential_theft": 0.5},
    },
    {
        "department": "HR",
        "roles": ["HR Coordinator", "Recruiter", "HR Manager"],
        "routines": [
            ("check_mail", "browse_app", "chat_colleague", "check_mail"),
            ("check_mail", "share_document", "chat_colleague", "browse_app"),
        ],
        "awareness_range": (0.2, 0.4),
        "susceptibility": {"phishing": 0.7, "credential_theft": 0.4},
    },
    {
        "department": "Sales",
        "roles": ["Account Executive", "Sales Manager", "BDR"],
        "routines": [
            ("check_mail", "chat_colleague", "browse_app", "check_mail"),
            ("chat_colleague", "check_mail", "browse_app", "chat_colleague"),
        ],
        "awareness_range": (0.2, 0.4),
        "susceptibility": {"phishing": 0.8, "credential_theft": 0.3},
    },
    {
        "department": "Operations",
        "roles": ["Operations Manager", "Systems Administrator", "IT Support"],
        "routines": [
            ("check_mail", "browse_app", "review_idp", "triage_alerts"),
            ("browse_app", "check_mail", "access_fileshare", "reset_password"),
        ],
        "awareness_range": (0.4, 0.7),
        "susceptibility": {"phishing": 0.4, "credential_theft": 0.3},
    },
    {
        "department": "Executive",
        "roles": ["CEO", "CTO", "CFO", "VP Engineering"],
        "routines": [
            ("check_mail", "browse_app", "chat_colleague", "check_mail"),
            ("check_mail", "chat_colleague", "browse_app", "share_document"),
        ],
        "awareness_range": (0.3, 0.5),
        "susceptibility": {"phishing": 0.5, "credential_theft": 0.6},
    },
]

# Host assignments by department
_DEPT_HOSTS: dict[str, str] = {
    "Engineering": "host-web",
    "IT Security": "host-siem",
    "Finance": "host-db",
    "HR": "host-web",
    "Sales": "host-web",
    "Operations": "host-idp",
    "Executive": "host-web",
}


def generate_personas(
    count: int = 10,
    *,
    seed: int = 42,
) -> tuple[GreenPersona, ...]:
    """Generate ``count`` diverse enterprise personas.

    Distributes across departments proportionally, assigns realistic
    routines, awareness levels, and susceptibility profiles. Deterministic
    given the same seed.
    """
    rng = random.Random(seed)
    personas: list[GreenPersona] = []

    # Round-robin across departments, then fill
    dept_cycle = _DEPARTMENTS * ((count // len(_DEPARTMENTS)) + 1)
    rng.shuffle(dept_cycle)

    for i in range(count):
        dept = dept_cycle[i]
        department = dept["department"]
        role = rng.choice(dept["roles"])
        routine = rng.choice(dept["routines"])
        lo, hi = dept["awareness_range"]
        awareness = round(rng.uniform(lo, hi), 2)
        # Add jitter to susceptibility
        susceptibility = {
            k: round(min(1.0, max(0.0, v + rng.uniform(-0.15, 0.15))), 2)
            for k, v in dept["susceptibility"].items()
        }

        pid = f"{role.lower().replace(' ', '_')}_{i}"
        host = _DEPT_HOSTS.get(department, "host-web")

        personas.append(
            GreenPersona(
                id=pid,
                role=role,
                department=department,
                home_host=host,
                mailbox=f"{pid}@company.local",
                awareness=awareness,
                susceptibility=susceptibility,
                routine=routine,
            )
        )

    return tuple(personas)


def build_agents(
    personas: tuple[GreenPersona, ...],
    *,
    memory_capacity: int = 50,
) -> dict[str, NPCAgent]:
    """Build NPCAgents from personas with auto-derived relationships."""
    agents: dict[str, NPCAgent] = {}
    for persona in personas:
        relationships: dict[str, float] = {}
        for other in personas:
            if other.id == persona.id:
                continue
            trust = 0.3
            if other.department == persona.department:
                trust += 0.3
            if other.home_host == persona.home_host:
                trust += 0.2
            relationships[other.id] = min(1.0, trust)
        agents[persona.id] = NPCAgent(
            persona=persona,
            memory=Memory(memory_capacity),
            relationships=relationships,
        )
    return agents


# ---------------------------------------------------------------------------
# Dispatch helpers — shared between ScriptedGreenScheduler and NPCAgent
# ---------------------------------------------------------------------------

_ROUTINE_DISPATCH: dict[str, tuple[str, str]] = {
    "check_mail": ("mail", "svc-email"),
    "send_mail": ("mail", "svc-email"),
    "browse_app": ("api", "svc-web"),
    "open_payroll_dashboard": ("api", "svc-web"),
    "access_fileshare": ("api", "svc-fileshare"),
    "review_idp": ("api", "svc-idp"),
    "triage_alerts": ("api", "svc-siem"),
    "reset_password": ("api", "svc-idp"),
    "chat_colleague": ("chat", "svc-web"),
    "slack_message": ("chat", "svc-web"),
    "teams_message": ("chat", "svc-web"),
    "share_document": ("document_share", "svc-fileshare"),
    "upload_file": ("document_share", "svc-fileshare"),
}


def _routine_dispatch(routine: str) -> tuple[str, str]:
    """Return (action_kind, target_service) for a routine name."""
    exact = _ROUTINE_DISPATCH.get(routine)
    if exact is not None:
        return exact
    lowered = routine.lower()
    if "mail" in lowered:
        return ("mail", "svc-email")
    if "chat" in lowered or "slack" in lowered or "teams" in lowered:
        return ("chat", "svc-web")
    if "doc" in lowered or "upload" in lowered:
        return ("document_share", "svc-fileshare")
    if "file" in lowered:
        return ("api", "svc-fileshare")
    if "idp" in lowered or "password" in lowered:
        return ("api", "svc-idp")
    if "alert" in lowered or "triage" in lowered:
        return ("api", "svc-siem")
    if "payroll" in lowered:
        return ("api", "svc-db")
    return ("api", "svc-web")


def _event_susceptibility_key(event_type: str) -> str:
    """Convert CamelCase event type to underscore key."""
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
