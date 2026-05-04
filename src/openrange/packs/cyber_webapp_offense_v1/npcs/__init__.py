"""Cyber NPCs for the v1 webapp offense pack.

NPCs are registered as entry points in the ``openrange.npcs`` group
via pyproject.toml (referencing the per-NPC module's ``factory``).
Imports of the NPC classes themselves go via the leaf modules
(``cyber_webapp_offense_v1.npcs.admin_audit``,
``cyber_webapp_offense_v1.npcs.browsing_user``).
"""

from __future__ import annotations

from abc import abstractmethod
from collections.abc import Mapping
from typing import Any, cast

from openrange.core.npc import NPC


class _HTTPCadenceNPC(NPC):
    """Base for cyber NPCs that hit HTTP at a fixed tick cadence.

    Subclasses implement ``_next_path`` to choose the path to GET on
    each acting tick. The base class owns the cooldown state machine
    (act once, then idle for ``cadence_ticks - 1`` ticks) and the
    http_get safety wrapper (silently swallows missing handle / errors).
    """

    def __init__(self, *, cadence_ticks: int) -> None:
        if cadence_ticks < 1:
            raise ValueError("cadence_ticks must be >= 1")
        self._cadence_ticks = cadence_ticks
        self._cooldown = 0

    @abstractmethod
    def _next_path(self) -> str: ...

    def step(self, interface: Mapping[str, Any]) -> None:
        if self._cooldown > 0:
            self._cooldown -= 1
            return
        self._cooldown = self._cadence_ticks - 1
        http_get = interface.get("http_get")
        if http_get is None:
            return
        try:
            cast(Any, http_get)(self._next_path())
        except Exception:  # noqa: BLE001 — NPC failures are silent
            return
