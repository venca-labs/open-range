"""Typed OpenEnv client for OpenRange."""

from __future__ import annotations

from typing import Any

from openenv.core.client_types import StepResult
from openenv.core.env_client import EnvClient

from open_range.models import RangeAction, RangeObservation, RangeState


class _SyncOpenRangeEnv:
    """Synchronous wrapper matching the documented OpenEnv .sync() pattern."""

    def __init__(self, client: "OpenRangeEnv") -> None:
        self._client = client

    def __enter__(self) -> "_SyncOpenRangeEnv":
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()

    def close(self) -> None:
        close = getattr(self._client, "close", None)
        if callable(close):
            close()

    def reset(self, **kwargs: Any) -> StepResult[RangeObservation]:
        return self._client.reset(**kwargs)

    def step(self, action: RangeAction, **kwargs: Any) -> StepResult[RangeObservation]:
        return self._client.step(action, **kwargs)

    def state(self) -> RangeState:
        return self._client.state()


class OpenRangeEnv(EnvClient[RangeAction, RangeObservation, RangeState]):
    """Typed OpenEnv client that speaks the standard reset/step/state contract."""

    def sync(self) -> Any:
        """Return the native sync wrapper when available, else a thin proxy."""
        base_sync = getattr(super(), "sync", None)
        if callable(base_sync):
            return base_sync()
        return _SyncOpenRangeEnv(self)

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
