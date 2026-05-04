"""``cyber.admin_audit`` — periodic privileged probe.

Models an internal admin / monitoring user who periodically pulls a
status / discovery endpoint. Every ``cadence_ticks`` ticks, GET the
``audit_path`` (default ``/openapi.json``). Lets the agent observe
admin-shaped traffic and gives the request log a third party beyond
the agent + browsing users.

Config:
    cadence_ticks: int = 5          — act every Nth tick
    audit_path: str = "/openapi.json"
    timeout_seconds: float = 1.0
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, cast

from openrange.core.npc import NPC


class AdminAudit(NPC):
    def __init__(
        self,
        *,
        cadence_ticks: int = 5,
        audit_path: str = "/openapi.json",
        timeout_seconds: float = 1.0,
    ) -> None:
        if cadence_ticks < 1:
            raise ValueError("cadence_ticks must be >= 1")
        if not audit_path:
            raise ValueError("audit_path must be non-empty")
        self._cadence_ticks = cadence_ticks
        self._audit_path = audit_path
        self._timeout = timeout_seconds
        self._cooldown = 0

    def step(self, interface: Mapping[str, Any]) -> None:
        if self._cooldown > 0:
            self._cooldown -= 1
            return
        self._cooldown = self._cadence_ticks - 1
        http_get = interface.get("http_get")
        if http_get is None:
            return
        try:
            cast(Any, http_get)(self._audit_path)
        except Exception:  # noqa: BLE001
            return


def factory(config: Mapping[str, object]) -> NPC:
    """NPC factory — registered as ``cyber.admin_audit`` entry point."""
    cadence_raw = config.get("cadence_ticks", 5)
    audit_path_raw = config.get("audit_path", "/openapi.json")
    timeout_raw = config.get("timeout_seconds", 1.0)
    if not isinstance(cadence_raw, int):
        raise ValueError("cadence_ticks must be an int")
    if not isinstance(audit_path_raw, str):
        raise ValueError("audit_path must be a string")
    if not isinstance(timeout_raw, int | float):
        raise ValueError("timeout_seconds must be a number")
    return AdminAudit(
        cadence_ticks=cadence_raw,
        audit_path=audit_path_raw,
        timeout_seconds=float(timeout_raw),
    )
