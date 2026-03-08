"""Shared OpenEnv data models for OpenRange.

These models are intentionally defined outside ``server/`` so both the client
and server depend on the same shared contract without crossing the client/server
boundary encouraged by OpenEnv.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import Field

from openenv.core.env_server.types import Action, Observation, State


class RangeAction(Action):
    """Command action for either the Red or Blue operator."""

    command: str
    mode: Literal["red", "blue"]


class RangeObservation(Observation):
    """Command/result observation for a range step."""

    stdout: str = ""
    stderr: str = ""
    flags_captured: list[str] = Field(default_factory=list)
    alerts: list[str] = Field(default_factory=list)


class RangeState(State):
    """Mutable episode state exposed through the OpenEnv state endpoint."""

    mode: str = ""
    flags_found: list[str] = Field(default_factory=list)
    services_status: dict[str, Any] = Field(default_factory=dict)
    tier: int = 1
    active_sessions: dict[str, str] = Field(default_factory=dict)
    auth_attempts: list[dict[str, Any]] = Field(default_factory=list)
    access_grants: list[str] = Field(default_factory=list)
    pivot_history: list[dict[str, str]] = Field(default_factory=list)
    milestones_completed: list[str] = Field(default_factory=list)
