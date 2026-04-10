"""NPC identity models and template generators.

Build-time data that persists across episodes for the same world.
These are frozen pydantic models stored on GreenPersona.profile.

Identity focuses on work-relevant details: how the person works,
who they get along with, what projects they're on, and how they
communicate.  This context feeds into LLM prompts so NPCs behave
like real people — not generic role-fillers.
"""

from __future__ import annotations

import hashlib
from typing import Sequence

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

# Async modalities that NPCs can use for communication.
# Future sync modalities (voice, video) would need a separate signaling
# mechanism since they require both parties to be available at once.
AsyncModality = Literal["email", "chat"]


def display_name(persona) -> str:
    """Return the NPC's full name, falling back to a title-cased ID.

    Works with GreenPersona objects or plain persona ID strings.
    """
    if isinstance(persona, str):
        return persona.replace("-", " ").replace("_", " ").title()
    profile = getattr(persona, "profile", None)
    if profile and profile.backstory.full_name:
        return profile.backstory.full_name
    pid = getattr(persona, "id", str(persona))
    return pid.replace("-", " ").replace("_", " ").title()


class _Frozen(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class NPCBackstory(_Frozen):
    """Work-focused biography for an NPC."""

    # Core identity
    full_name: str = ""          # "Janet Liu", "Bob Smith"
    location: str = ""           # "San Francisco office", "Remote — Portland"
    working_hours: str = ""      # "9am-5pm PT", "early riser — 7am-3pm ET"

    # Work style and relationships
    work_style: str = ""         # "Methodical, prefers written communication"
    communication_style: str = ""  # "Direct and concise", "Warm, uses lots of exclamations"
    projects: tuple[str, ...] = ()  # ("Q1 marketing campaign", "Website redesign")
    responsibilities: str = ""   # "Manages social media calendar and ad spend"
    friends: tuple[str, ...] = ()  # persona IDs of coworker friends

    # Communication preferences
    preferred_modality: AsyncModality = "email"  # email | chat

    # Background color
    background: str = ""         # 2-3 sentences of work-relevant history
    years_at_company: int = Field(default=2, ge=0)


class NPCPersonality(_Frozen):
    """Behavioral traits that influence NPC decisions and communication."""

    mood: str = "focused"                # focused | anxious | relaxed | distracted | bored
    disposition: str = "cooperative"      # cooperative | competitive | cautious | impulsive
    interpersonal_style: str = "casual"   # formal | casual | terse | verbose
    work_ethic: str = "diligent"          # diligent | average | lazy
    risk_tolerance: float = Field(default=0.5, ge=0.0, le=1.0)
    chattiness: float = Field(default=0.5, ge=0.0, le=1.0)  # tendency to send non-task messages


class NPCProfile(_Frozen):
    """Aggregated identity for a single NPC persona."""

    backstory: NPCBackstory = Field(default_factory=NPCBackstory)
    personality: NPCPersonality = Field(default_factory=NPCPersonality)


# ---------------------------------------------------------------------------
# Template identity generation (no LLM required)
# ---------------------------------------------------------------------------

def generate_profiles(
    personas: Sequence[dict[str, str]],
    seed: int = 0,
) -> list[NPCProfile]:
    """Generate template profiles for a list of personas.

    Args:
        personas: list of dicts with keys: id, role, department
        seed: deterministic seed
    """
    n = len(personas)
    profiles: list[NPCProfile] = []
    # Build friendship pairs — every other persona is friends with the next
    friend_pairs: list[tuple[int, int]] = []
    for i in range(0, n - 1, 2):
        friend_pairs.append((i, i + 1))
    friend_map: dict[str, list[str]] = {p["id"]: [] for p in personas}
    for a, b in friend_pairs:
        friend_map[personas[a]["id"]].append(personas[b]["id"])
        friend_map[personas[b]["id"]].append(personas[a]["id"])

    for i, p in enumerate(personas):
        pid = p["id"]
        role = p.get("role", "Employee")
        dept = p.get("department", "General")
        h = int(hashlib.md5(f"{pid}:{seed}".encode()).hexdigest()[:8], 16)

        pool = _pool_for_role(role)
        template = pool[h % len(pool)]
        friends = tuple(friend_map.get(pid, ()))

        backstory = NPCBackstory(
            full_name=template["full_name"],
            location=template["location"],
            working_hours=template["working_hours"],
            work_style=template["work_style"],
            communication_style=template["communication_style"],
            projects=template["projects"],
            responsibilities=template["responsibilities"].format(dept=dept),
            friends=friends,
            preferred_modality=template.get("preferred_modality", "email"),
            background=template["background"].format(dept=dept, role=role),
            years_at_company=template["years_at_company"],
        )
        personality = NPCPersonality(**template["personality"])
        profiles.append(NPCProfile(backstory=backstory, personality=personality))
    return profiles


def _pool_for_role(role: str) -> list[dict]:
    lowered = role.lower()
    if any(kw in lowered for kw in ("soc", "security", "infosec")):
        return _SECURITY_PROFILES
    if any(kw in lowered for kw in ("it", "admin", "engineer", "devops")):
        return _IT_PROFILES
    if any(kw in lowered for kw in ("manager", "director", "vp", "executive", "chief")):
        return _EXEC_PROFILES
    if any(kw in lowered for kw in ("sales", "marketing", "account")):
        return _SALES_PROFILES
    return _GENERIC_PROFILES


# ---------------------------------------------------------------------------
# Template profile pools
# ---------------------------------------------------------------------------

_SECURITY_PROFILES = [
    {
        "full_name": "Riley Kim",
        "location": "San Francisco office, 3rd floor (SOC room)",
        "working_hours": "7am-4pm PT — early shift, monitors overnight alerts first thing",
        "work_style": "Methodical and alert. Triages by severity. Keeps a running incident log.",
        "communication_style": "Precise and factual. Writes detailed incident reports. Avoids speculation.",
        "preferred_modality": "email",
        "projects": ("SIEM rule tuning", "Incident response playbook update"),
        "responsibilities": "Monitors {dept} alerts, triages incidents, coordinates response with IT",
        "background": "Joined from a managed security provider 3 years ago. Calm under pressure — handled the ransomware scare last year without breaking a sweat. The team trusts Riley's judgment on threat severity.",
        "years_at_company": 3,
        "personality": {"mood": "focused", "disposition": "cautious", "interpersonal_style": "terse",
                        "work_ethic": "diligent", "risk_tolerance": 0.15, "chattiness": 0.2},
    },
]

_IT_PROFILES = [
    {
        "full_name": "Bob Smith",
        "location": "San Francisco office, 3rd floor",
        "working_hours": "8am-4pm PT — likes to beat traffic",
        "work_style": "Methodical and thorough. Documents everything. Prefers tickets over Slack.",
        "communication_style": "Direct and technical. Doesn't sugarcoat. Uses bullet points in emails.",
        "preferred_modality": "email",
        "projects": ("Infrastructure migration to K8s", "Zero-trust network rollout"),
        "responsibilities": "Manages {dept} infrastructure, on-call rotation, and vendor relationships",
        "background": "Started as a junior sysadmin 5 years ago, promoted twice. Known as the person who actually reads the runbooks. Quietly proud of 99.97% uptime last quarter.",
        "years_at_company": 5,
        "personality": {"mood": "focused", "disposition": "cautious", "interpersonal_style": "terse",
                        "work_ethic": "diligent", "risk_tolerance": 0.2, "chattiness": 0.3},
    },
    {
        "full_name": "Priya Patel",
        "location": "Remote — Austin, TX",
        "working_hours": "9am-6pm CT — takes a long lunch for gym",
        "work_style": "Fast-moving, prefers quick calls over long email threads. Automates everything.",
        "communication_style": "Casual and friendly. Lots of emoji in Slack, professional in email.",
        "preferred_modality": "chat",
        "projects": ("CI/CD pipeline optimization", "Security audit remediation"),
        "responsibilities": "Owns {dept} CI/CD, deployment automation, and developer tooling",
        "background": "Joined from a startup 3 years ago. Brought a 'ship fast' mentality that initially clashed with the team but earned respect after cutting deploy time by 70%.",
        "years_at_company": 3,
        "personality": {"mood": "relaxed", "disposition": "cooperative", "interpersonal_style": "casual",
                        "work_ethic": "diligent", "risk_tolerance": 0.6, "chattiness": 0.7},
    },
]

_EXEC_PROFILES = [
    {
        "full_name": "Carol Jones",
        "location": "New York office, executive floor",
        "working_hours": "7:30am-6pm ET — always first in, reads overnight reports over coffee",
        "work_style": "Strategic thinker. Delegates well but checks in frequently. Reads every status report.",
        "communication_style": "Polished and measured. Asks probing questions. Never rushes a decision in email.",
        "preferred_modality": "email",
        "projects": ("Q1 board presentation", "Org restructuring"),
        "responsibilities": "Oversees {dept} strategy, budget, and cross-functional alignment",
        "background": "Promoted to VP two years ago after leading the platform rewrite. Well-liked across teams. Known for remembering everyone's name and their kids' names.",
        "years_at_company": 7,
        "personality": {"mood": "focused", "disposition": "cooperative", "interpersonal_style": "formal",
                        "work_ethic": "diligent", "risk_tolerance": 0.4, "chattiness": 0.5},
    },
    {
        "full_name": "Michael Torres",
        "location": "San Francisco office, 5th floor",
        "working_hours": "9am-5:30pm PT — protective of evenings for family",
        "work_style": "Hands-off with experienced reports, more involved with newer team members.",
        "communication_style": "Warm but concise. Prefers 1:1s over group emails. Says 'let's take this offline' a lot.",
        "preferred_modality": "chat",
        "projects": ("Annual planning", "New market expansion"),
        "responsibilities": "Manages {dept} P&L, hiring, and partner relationships",
        "background": "Came from a competitor 4 years ago. Brought enterprise sales expertise. The team trusts his judgment on deals but teases him about his spreadsheet obsession.",
        "years_at_company": 4,
        "personality": {"mood": "relaxed", "disposition": "cooperative", "interpersonal_style": "casual",
                        "work_ethic": "average", "risk_tolerance": 0.5, "chattiness": 0.6},
    },
]

_SALES_PROFILES = [
    {
        "full_name": "Dan Wu",
        "location": "Remote — Denver, CO",
        "working_hours": "8am-5pm MT — blocks 12-1 for prospect calls",
        "work_style": "High-energy, pipeline-obsessed. Updates CRM religiously. Follows up fast.",
        "communication_style": "Enthusiastic and persuasive. Uses exclamation marks. Personalizes every message.",
        "preferred_modality": "chat",
        "projects": ("Enterprise expansion Q1", "Partner referral program"),
        "responsibilities": "Owns {dept} enterprise pipeline, manages 3 key accounts",
        "background": "Top performer two quarters running. Transferred from the SMB team after crushing quota. Competitive but generous — mentors the new hires during lunch.",
        "years_at_company": 2,
        "personality": {"mood": "focused", "disposition": "competitive", "interpersonal_style": "verbose",
                        "work_ethic": "diligent", "risk_tolerance": 0.7, "chattiness": 0.8},
    },
    {
        "full_name": "Janet Liu",
        "location": "San Francisco office, 2nd floor",
        "working_hours": "9:30am-6pm PT — not a morning person",
        "work_style": "Creative and big-picture. Great at campaigns, less excited about spreadsheets.",
        "communication_style": "Friendly and informal. Writes messages like texts. Uses 'lol' in Slack.",
        "preferred_modality": "chat",
        "projects": ("Q1 marketing campaign", "Brand refresh"),
        "responsibilities": "Manages {dept} social media calendar, ad spend, and event coordination",
        "background": "Joined straight out of college 2 years ago. Quickly became the go-to for anything social media. Gets bored in long meetings but lights up during brainstorms.",
        "years_at_company": 2,
        "personality": {"mood": "relaxed", "disposition": "cooperative", "interpersonal_style": "casual",
                        "work_ethic": "average", "risk_tolerance": 0.6, "chattiness": 0.9},
    },
]

_GENERIC_PROFILES = [
    {
        "full_name": "Alex Chen",
        "location": "San Francisco office, 2nd floor",
        "working_hours": "9am-5pm PT",
        "work_style": "Reliable and steady. Gets things done without drama.",
        "communication_style": "Clear and professional. Prefers email for anything that needs a paper trail.",
        "preferred_modality": "email",
        "projects": ("Process improvement initiative", "Documentation overhaul"),
        "responsibilities": "Handles {dept} operations, reporting, and cross-team coordination",
        "background": "Has been with the company 3 years. Quietly dependable — the person everyone asks when they can't find a document or don't know the process.",
        "years_at_company": 3,
        "personality": {"mood": "focused", "disposition": "cooperative", "interpersonal_style": "casual",
                        "work_ethic": "diligent", "risk_tolerance": 0.4, "chattiness": 0.5},
    },
    {
        "full_name": "Sam Rivera",
        "location": "Remote — Chicago, IL",
        "working_hours": "8:30am-5pm CT — takes breaks to walk the dog",
        "work_style": "Independent worker. Prefers async communication. Delivers early.",
        "communication_style": "Thoughtful and measured. Writes longer emails but they're worth reading.",
        "preferred_modality": "email",
        "projects": ("Data quality audit", "Vendor evaluation"),
        "responsibilities": "Owns {dept} data integrity, vendor management, and compliance reporting",
        "background": "Joined 4 years ago from a consulting firm. Appreciates structure and process. The team jokes that Sam's documentation could be published as a book.",
        "years_at_company": 4,
        "personality": {"mood": "focused", "disposition": "cautious", "interpersonal_style": "formal",
                        "work_ethic": "diligent", "risk_tolerance": 0.3, "chattiness": 0.4},
    },
]
