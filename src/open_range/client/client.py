"""Typed OpenEnv client for OpenRange."""

from __future__ import annotations

from openenv.core.client_types import StepResult
from openenv.core.env_client import EnvClient

from open_range.server.models import RangeAction, RangeObservation, RangeState


class OpenRangeEnv(EnvClient[RangeAction, RangeObservation, RangeState]):
    """Typed OpenEnv client that speaks the standard reset/step/state contract."""

    def sync(self) -> "OpenRangeEnv":
        """Compatibility wrapper matching the documented OpenEnv sync pattern."""
        return self

    def _step_payload(self, action: RangeAction) -> dict:
        return {"command": action.command, "mode": action.mode}

    def _parse_result(self, payload: dict) -> StepResult[RangeObservation]:
        obs = RangeObservation(**payload.get("observation", {}))
        return StepResult(
            observation=obs,
            reward=payload.get("reward"),
            done=bool(payload.get("done", False)),
        )

    def _parse_state(self, payload: dict) -> RangeState:
        return RangeState(**payload)
