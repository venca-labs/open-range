"""``cyber.office_chatter`` — a person walking around the office.

Scripted, no LLM required. The backend is intentionally minimal: each
chatter only emits *walk* events (``record_action({"move":
"wandering"})``). The dashboard owns the dialogue: when a visitor
arrives at a colleague's desk, the JS picks a coherent
opener-and-reply exchange from its global pool and animates the
two-way conversation. Keeping dialogue choreography on the JS side
lets the office hum with sensible back-and-forth without any
backend coordination between chatters.

Config:
    name: str (required)           — display name + dashboard actor_id
    cadence_ticks: int = 6         — act every Nth tick (walk attempt)
    home: str | None = None        — optional service id for the
                                     ``move`` event's target field;
                                     advisory — the dashboard picks
                                     the destination desk itself.
    walk_probability: float = 1.0  — chance an acting tick triggers a
                                     walk (otherwise the chatter just
                                     stands at the desk for that
                                     window).
    seed: int | None = None        — deterministic randomness for
                                     reproducible gif demos
"""

from __future__ import annotations

import random
from collections.abc import Mapping
from typing import Any

from openrange import NPC


class OfficeChatter(NPC):
    """A scripted office NPC. Walks to colleagues. The dashboard
    handles speech; this class never emits ``speak`` events itself."""

    def __init__(
        self,
        *,
        name: str,
        cadence_ticks: int = 6,
        home: str | None = None,
        walk_probability: float = 1.0,
        seed: int | None = None,
    ) -> None:
        if not name:
            raise ValueError("name must be a non-empty string")
        if cadence_ticks < 1:
            raise ValueError("cadence_ticks must be >= 1")
        if not 0.0 <= walk_probability <= 1.0:
            raise ValueError("walk_probability must be in [0.0, 1.0]")
        self._actor_id = name
        self._cadence_ticks = cadence_ticks
        self._home = home
        self._walk_probability = walk_probability
        self._rng = random.Random(seed)
        # Stagger the very first action so a roomful of chatters
        # constructed at the same instant doesn't fire in lock-step
        # on tick 0. Each NPC's initial cooldown is a different
        # offset within ``[0, cadence_ticks)``; same seed gives the
        # same offset across re-runs so the gif stays reproducible.
        self._cooldown = self._rng.randrange(cadence_ticks) if cadence_ticks > 1 else 0
        self._record: Any = None

    def start(self, context: Mapping[str, Any]) -> None:
        self._record = context.get("record_action")
        # Announce presence so the dashboard can spawn this chatter
        # at their home desk *before* their first cadence-driven act.
        if self._record is not None:
            self._record({"present": True})

    def step(self, interface: Mapping[str, Any]) -> None:
        del interface
        if self._cooldown > 0:
            self._cooldown -= 1
            return
        self._cooldown = self._cadence_ticks - 1
        if self._record is None:
            return
        if self._rng.random() < self._walk_probability:
            if self._home is not None:
                self._record({"move": "wandering"}, target=self._home)
            else:
                self._record({"move": "wandering"})


def factory(config: Mapping[str, object]) -> NPC:
    name_raw = config.get("name")
    cadence_raw = config.get("cadence_ticks", 6)
    home_raw = config.get("home")
    walk_p_raw = config.get("walk_probability", 1.0)
    seed_raw = config.get("seed")
    if not isinstance(name_raw, str) or not name_raw:
        raise ValueError("name must be a non-empty string")
    if not isinstance(cadence_raw, int):
        raise ValueError("cadence_ticks must be an int")
    if home_raw is not None and not isinstance(home_raw, str):
        raise ValueError("home must be a string or unset")
    if not isinstance(walk_p_raw, int | float):
        raise ValueError("walk_probability must be a number")
    if seed_raw is not None and not isinstance(seed_raw, int):
        raise ValueError("seed must be an int or unset")
    return OfficeChatter(
        name=name_raw,
        cadence_ticks=cadence_raw,
        home=home_raw,
        walk_probability=float(walk_p_raw),
        seed=seed_raw,
    )
