"""Cyber NPCs for the v1 webapp offense pack.

Each NPC is a small autonomous actor that runs alongside the agent
during an episode, hitting the realized HTTP service. Registered as
entry points in the ``openrange.npcs`` group via pyproject.toml so
``manifest.npc`` can reference them by id (``cyber.browsing_user``,
``cyber.admin_audit``).
"""

from __future__ import annotations

from openrange.packs.cyber_webapp_offense_v1.npcs.admin_audit import (
    AdminAudit,
)
from openrange.packs.cyber_webapp_offense_v1.npcs.admin_audit import (
    factory as admin_audit_factory,
)
from openrange.packs.cyber_webapp_offense_v1.npcs.browsing_user import (
    BrowsingUser,
)
from openrange.packs.cyber_webapp_offense_v1.npcs.browsing_user import (
    factory as browsing_user_factory,
)

__all__ = [
    "AdminAudit",
    "BrowsingUser",
    "admin_audit_factory",
    "browsing_user_factory",
]
