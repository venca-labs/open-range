"""Default NPC personas for testing and mock mode."""

from __future__ import annotations

from open_range.builder.npc.identity import NPCBackstory, NPCPersonality, NPCProfile
from open_range.world_ir import GreenPersona


def default_personas() -> list[GreenPersona]:
    """Return a default set of four NPC personas with rich profiles."""
    return [
        GreenPersona(
            id="janet.liu",
            role="Marketing Coordinator",
            department="Marketing",
            home_host="siem",
            mailbox="janet.liu@corp.local",
            awareness=0.4,
            susceptibility={"phishing_email": 0.6, "social_engineering": 0.5},
            routine=("browse_app", "send_mail", "browse_app", "browse_app"),
            profile=NPCProfile(
                backstory=NPCBackstory(
                    full_name="Janet Liu",
                    location="San Francisco office, 2nd floor",
                    working_hours="9:30am-6pm PT — not a morning person",
                    work_style="Creative and big-picture. Great at campaigns, less excited about spreadsheets.",
                    communication_style="Friendly and informal. Writes messages like texts.",
                    preferred_modality="chat",
                    projects=("Q1 marketing campaign", "Brand refresh"),
                    responsibilities="Manages social media calendar, ad spend, and event coordination",
                    friends=("dan.wu",),
                    background="Joined straight out of college 2 years ago. Quickly became the go-to for anything social media. Gets bored in long meetings but lights up during brainstorms.",
                    years_at_company=2,
                ),
                personality=NPCPersonality(
                    mood="relaxed", disposition="cooperative",
                    interpersonal_style="casual", work_ethic="average",
                    risk_tolerance=0.6, chattiness=0.9,
                ),
            ),
        ),
        GreenPersona(
            id="bob.smith",
            role="IT Administrator",
            department="IT",
            home_host="siem",
            mailbox="bob.smith@corp.local",
            awareness=0.8,
            susceptibility={"phishing_email": 0.2, "social_engineering": 0.3},
            routine=("browse_app", "browse_app", "send_mail", "browse_app"),
            profile=NPCProfile(
                backstory=NPCBackstory(
                    full_name="Bob Smith",
                    location="San Francisco office, 3rd floor",
                    working_hours="8am-4pm PT — likes to beat traffic",
                    work_style="Methodical and thorough. Documents everything. Prefers tickets over Slack.",
                    communication_style="Direct and technical. Doesn't sugarcoat. Uses bullet points.",
                    preferred_modality="email",
                    projects=("Infrastructure migration to K8s", "Zero-trust network rollout"),
                    responsibilities="Manages IT infrastructure, on-call rotation, and vendor relationships",
                    friends=("carol.jones",),
                    background="Started as a junior sysadmin 5 years ago, promoted twice. Known as the person who actually reads the runbooks. Quietly proud of 99.97% uptime last quarter.",
                    years_at_company=5,
                ),
                personality=NPCPersonality(
                    mood="focused", disposition="cautious",
                    interpersonal_style="terse", work_ethic="diligent",
                    risk_tolerance=0.2, chattiness=0.3,
                ),
            ),
        ),
        GreenPersona(
            id="carol.jones",
            role="VP of Engineering",
            department="Engineering",
            home_host="siem",
            mailbox="carol.jones@corp.local",
            awareness=0.7,
            susceptibility={"phishing_email": 0.3, "social_engineering": 0.4},
            routine=("send_mail", "browse_app", "send_mail", "browse_app"),
            profile=NPCProfile(
                backstory=NPCBackstory(
                    full_name="Carol Jones",
                    location="New York office, executive floor",
                    working_hours="7:30am-6pm ET — always first in",
                    work_style="Strategic thinker. Delegates well but checks in frequently.",
                    communication_style="Polished and measured. Asks probing questions.",
                    preferred_modality="email",
                    projects=("Q1 board presentation", "Org restructuring"),
                    responsibilities="Oversees Engineering strategy, budget, and cross-functional alignment",
                    friends=("bob.smith",),
                    background="Promoted to VP two years ago after leading the platform rewrite. Well-liked across teams. Known for remembering everyone's name.",
                    years_at_company=7,
                ),
                personality=NPCPersonality(
                    mood="focused", disposition="cooperative",
                    interpersonal_style="formal", work_ethic="diligent",
                    risk_tolerance=0.4, chattiness=0.5,
                ),
            ),
        ),
        GreenPersona(
            id="dan.wu",
            role="Sales Account Executive",
            department="Sales",
            home_host="siem",
            mailbox="dan.wu@corp.local",
            awareness=0.3,
            susceptibility={"phishing_email": 0.7, "social_engineering": 0.6},
            routine=("send_mail", "browse_app", "send_mail", "send_mail"),
            profile=NPCProfile(
                backstory=NPCBackstory(
                    full_name="Dan Wu",
                    location="Remote — Denver, CO",
                    working_hours="8am-5pm MT — blocks 12-1 for prospect calls",
                    work_style="High-energy, pipeline-obsessed. Updates CRM religiously.",
                    communication_style="Enthusiastic and persuasive. Uses exclamation marks.",
                    preferred_modality="chat",
                    projects=("Enterprise expansion Q1", "Partner referral program"),
                    responsibilities="Owns enterprise pipeline, manages 3 key accounts",
                    friends=("janet.liu",),
                    background="Top performer two quarters running. Transferred from SMB team after crushing quota. Competitive but generous — mentors the new hires during lunch.",
                    years_at_company=2,
                ),
                personality=NPCPersonality(
                    mood="focused", disposition="competitive",
                    interpersonal_style="verbose", work_ethic="diligent",
                    risk_tolerance=0.7, chattiness=0.8,
                ),
            ),
        ),
    ]
