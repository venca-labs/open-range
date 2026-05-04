"""``cyber.office_chatter`` — a person walking around the office.

Scripted, no LLM. Each acting tick the chatter walks toward a
colleague, and the move event carries an ``opener`` line plus a
``reply`` line drawn from a paired-exchange pool. The dashboard
animates the walk and pops both bubbles at the appropriate beat;
all dialogue content lives in the pack, so the renderer stays
generic.

Config:
    name: str (required)           — display name + dashboard actor_id
    cadence_ticks: int = 6         — act every Nth tick
    home: str | None = None        — optional service id for the
                                     move event's target field
    walk_probability: float = 1.0  — chance an acting tick walks
                                     (otherwise the chatter is idle
                                     for that window)
    seed: int | None = None        — deterministic randomness
"""

from __future__ import annotations

import random
from collections.abc import Mapping
from typing import Any

from openrange import NPC

EXCHANGES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("deploy went out?", ("yeah, just now", "still rolling", "blocked on review")),
    ("coffee?", ("please", "in five", "you read my mind")),
    ("got a sec?", ("sure, what's up?", "give me two", "yeah, hit me")),
    ("build is red on main", ("which test?", "i'll take a look", "ugh, again")),
    (
        "did you see the slack thread?",
        ("yeah, weird right?", "no, link me", "haven't caught up"),
    ),
    ("lunch in 20?", ("i'm in", "swamped, next time", "i'll meet you there")),
    ("merge conflict on auth", ("i'll rebase", "yours wins", "let's pair on it")),
    ("rolled back the migration", ("good call", "what broke?", "was it the index?")),
    (
        "incident channel is quiet",
        ("finally", "calm before the storm", "knock on wood"),
    ),
    ("this query is slow", ("explain analyze", "missing index?", "send me the plan")),
    ("found a flaky test", ("which one?", "rerun and ignore", "file a ticket")),
    (
        "anyone seen the wifi go down?",
        ("yeah just now", "mine's fine", "switching to hotspot"),
    ),
    ("wfh tomorrow", ("enjoy", "same", "send me your draft first")),
    ("standup in five", ("on my way", "i'll be late", "skip me, i'll post async")),
    ("shipped the patch", ("nice", "test in staging?", "thanks for the quick turn")),
    ("i need another reviewer", ("link me", "what's the size?", "i can take it")),
)


class OfficeChatter(NPC):
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
        # Stagger the first action across a roomful of chatters so they
        # don't all fire on tick 0. Same seed gives the same offset so
        # demo recordings reproduce.
        self._cooldown = self._rng.randrange(cadence_ticks) if cadence_ticks > 1 else 0
        self._record: Any = None

    def start(self, context: Mapping[str, Any]) -> None:
        self._record = context.get("record_action")
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
        if self._rng.random() >= self._walk_probability:
            return
        opener, replies = self._rng.choice(EXCHANGES)
        action: dict[str, object] = {
            "move": "wandering",
            "opener": opener,
            "reply": self._rng.choice(replies),
        }
        if self._home is not None:
            self._record(action, target=self._home)
        else:
            self._record(action)


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
