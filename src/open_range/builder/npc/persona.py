"""NPC persona models.

Re-exports NPCPersona from protocols for convenience, and provides
helpers for generating persona cards from snapshot specs.
"""

from __future__ import annotations

from open_range.protocols import NPCPersona

# Re-export so other modules can import from here
__all__ = ["NPCPersona", "default_personas"]


def default_personas() -> list[NPCPersona]:
    """Return a default set of NPC personas for testing.

    Two personas with contrasting security awareness levels:
    a low-awareness marketing employee and a high-awareness CISO.
    """
    return [
        NPCPersona(
            name="Janet Smith",
            role="Marketing Coordinator",
            department="Marketing",
            reports_to="",
            communication_style="casual, responds quickly, uses exclamation marks",
            security_awareness=0.3,
            susceptibility={
                "phishing_email": 0.7,
                "credential_sharing": 0.4,
                "attachment_opening": 0.8,
                "vishing": 0.6,
            },
            routine={
                "email_check_interval_min": 15,
                "typical_actions": [
                    "browse intranet",
                    "send marketing reports",
                    "LDAP lookups",
                ],
            },
            accounts={
                "email": "jsmith@acmecorp.local",
                "ldap": "jsmith",
                "smb_shares": "marketing,shared",
            },
        ),
        NPCPersona(
            name="David Chen",
            role="CISO",
            department="Security",
            reports_to="",
            communication_style=(
                "formal, suspicious of unusual requests, always verifies sender"
            ),
            security_awareness=0.95,
            susceptibility={
                "phishing_email": 0.05,
                "credential_sharing": 0.01,
                "attachment_opening": 0.1,
                "vishing": 0.05,
            },
            routine={
                "email_check_interval_min": 5,
                "typical_actions": [
                    "review SIEM alerts",
                    "approve access requests",
                    "policy updates",
                ],
            },
            accounts={
                "email": "dchen@acmecorp.local",
                "ldap": "dchen",
                "smb_shares": "security,executive",
            },
        ),
    ]
