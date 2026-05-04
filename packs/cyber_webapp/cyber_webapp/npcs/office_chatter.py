"""``cyber.office_chatter`` — a person walking around the office.

Scripted, no LLM required. Each chatter has a name, a home desk
(targeted via service id), a list of canned phrases, and a slow
cadence. Per acting tick it does one of:

* **speak** — emits a ``record_action({"speak": phrase})`` so the
  dashboard pops a speech bubble above their character.
* **walk** — emits ``record_action({"move": "wandering"}, target=desk)``
  pointing at a random service id, which makes the existing 3D
  renderer animate the character walking to that desk.

Together these two actions are enough to make a populated
"office full of people doing things" feel — the demo target for
the Concordia-shaped physical-sim vision (#219).

Config:
    name: str (required)           — display name + dashboard actor_id
    cadence_ticks: int = 6         — act every Nth tick
    home: str | None = None        — service id to default-walk back to
    lines: list[str] | None = None — phrases to speak (otherwise a
                                     small built-in pool is used)
    walk_probability: float = 0.5  — chance an acting tick is a walk
                                     (otherwise it's a speak)
    seed: int | None = None        — deterministic randomness for
                                     reproducible gif demos
"""

from __future__ import annotations

import random
from collections.abc import Mapping
from typing import Any

from openrange import NPC

_DEFAULT_LINES: tuple[str, ...] = (
    "morning",
    "did you see the build go red?",
    "coffee?",
    "back-to-back meetings today",
    "anyone got bandwidth for a code review?",
    "lunch at 12:30?",
    "okay i'm gonna head to the kitchen",
    "deploy is paused — talk to ops",
    "found a flaky test in main",
    "ping me when you push",
    "wfh tomorrow",
    "standup in 5",
    "this query is slow on prod",
    "anyone know the wifi password?",
)


class OfficeChatter(NPC):
    """A scripted office NPC. Walks. Speaks. Doesn't touch HTTP."""

    def __init__(
        self,
        *,
        name: str,
        cadence_ticks: int = 6,
        home: str | None = None,
        lines: tuple[str, ...] = _DEFAULT_LINES,
        walk_probability: float = 0.5,
        seed: int | None = None,
    ) -> None:
        if not name:
            raise ValueError("name must be a non-empty string")
        if cadence_ticks < 1:
            raise ValueError("cadence_ticks must be >= 1")
        if not 0.0 <= walk_probability <= 1.0:
            raise ValueError("walk_probability must be in [0.0, 1.0]")
        if not lines:
            raise ValueError("lines must be non-empty")
        self._actor_id = name
        self._cadence_ticks = cadence_ticks
        self._home = home
        self._lines = tuple(lines)
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
        # Otherwise the office looks empty until the staggered initial
        # cooldown elapses (up to a full cadence window).
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
        # Walk vs. speak is a single coin flip on ``walk_probability``.
        # The dashboard picks the destination desk client-side based on
        # the chatter's home — the backend doesn't need to know any
        # service ids to emit a walk. Previously this was gated on a
        # ``self._known_targets`` set populated only when ``home`` was
        # configured, which meant the example manifest (no home) never
        # walked at all.
        if self._rng.random() < self._walk_probability:
            target = self._home if self._home else None
            if target is not None:
                self._record({"move": "wandering"}, target=target)
            else:
                self._record({"move": "wandering"})
        else:
            line = self._rng.choice(self._lines)
            self._record({"speak": line})


def factory(config: Mapping[str, object]) -> NPC:
    name_raw = config.get("name")
    cadence_raw = config.get("cadence_ticks", 6)
    home_raw = config.get("home")
    lines_raw = config.get("lines")
    walk_p_raw = config.get("walk_probability", 0.5)
    seed_raw = config.get("seed")
    if not isinstance(name_raw, str) or not name_raw:
        raise ValueError("name must be a non-empty string")
    if not isinstance(cadence_raw, int):
        raise ValueError("cadence_ticks must be an int")
    if home_raw is not None and not isinstance(home_raw, str):
        raise ValueError("home must be a string or unset")
    if lines_raw is None:
        lines: tuple[str, ...] = _DEFAULT_LINES
    elif isinstance(lines_raw, list | tuple) and all(
        isinstance(line, str) for line in lines_raw
    ):
        lines = tuple(lines_raw)
    else:
        raise ValueError("lines must be a list of strings")
    if not isinstance(walk_p_raw, int | float):
        raise ValueError("walk_probability must be a number")
    if seed_raw is not None and not isinstance(seed_raw, int):
        raise ValueError("seed must be an int or unset")
    return OfficeChatter(
        name=name_raw,
        cadence_ticks=cadence_raw,
        home=home_raw,
        lines=lines,
        walk_probability=float(walk_p_raw),
        seed=seed_raw,
    )
