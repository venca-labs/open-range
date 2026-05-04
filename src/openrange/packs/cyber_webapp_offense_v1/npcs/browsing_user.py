"""``cyber.browsing_user`` — generates background HTTP traffic.

Each tick, decrement an internal cooldown; when it hits zero, GET the
next path from the configured rotation, then reset the cooldown to
``cadence_ticks``. This keeps the agent's exploit requests from being
the only entries in the request log.

Config:
    cadence_ticks: int = 2       — act every Nth tick
    paths: list[str] = ["/"]     — paths to rotate through (cycled)
    timeout_seconds: float = 1.0 — per-request HTTP timeout
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, cast

from openrange.core.npc import NPC

_DEFAULT_PATHS: tuple[str, ...] = ("/",)


class BrowsingUser(NPC):
    def __init__(
        self,
        *,
        cadence_ticks: int = 2,
        paths: tuple[str, ...] = _DEFAULT_PATHS,
        timeout_seconds: float = 1.0,
    ) -> None:
        if cadence_ticks < 1:
            raise ValueError("cadence_ticks must be >= 1")
        if not paths:
            raise ValueError("paths must be non-empty")
        self._cadence_ticks = cadence_ticks
        self._paths = tuple(paths)
        self._timeout = timeout_seconds
        self._cooldown = 0
        self._index = 0

    def step(self, interface: Mapping[str, Any]) -> None:
        if self._cooldown > 0:
            self._cooldown -= 1
            return
        path = self._paths[self._index % len(self._paths)]
        self._index += 1
        self._cooldown = self._cadence_ticks - 1
        http_get = interface.get("http_get")
        if http_get is None:
            return
        try:
            cast(Any, http_get)(path)
        except Exception:  # noqa: BLE001 — NPC failures are silent
            return


def factory(config: Mapping[str, object]) -> NPC:
    """NPC factory — registered as ``cyber.browsing_user`` entry point.

    Reads optional ``cadence_ticks``, ``paths``, ``timeout_seconds``
    from ``config`` with sensible defaults.
    """
    cadence_raw = config.get("cadence_ticks", 2)
    paths_raw = config.get("paths", list(_DEFAULT_PATHS))
    timeout_raw = config.get("timeout_seconds", 1.0)
    if not isinstance(cadence_raw, int):
        raise ValueError("cadence_ticks must be an int")
    if not isinstance(paths_raw, list | tuple) or not all(
        isinstance(p, str) for p in paths_raw
    ):
        raise ValueError("paths must be a list of strings")
    if not isinstance(timeout_raw, int | float):
        raise ValueError("timeout_seconds must be a number")
    return BrowsingUser(
        cadence_ticks=cadence_raw,
        paths=tuple(paths_raw),
        timeout_seconds=float(timeout_raw),
    )
