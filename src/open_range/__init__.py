"""OpenRange public package surface."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from open_range.client.client import OpenRangeEnv
    from open_range.models import RangeAction, RangeObservation, RangeState
    from open_range.server.environment import RangeEnvironment

__all__ = [
    "OpenRangeEnv",
    "RangeAction",
    "RangeEnvironment",
    "RangeObservation",
    "RangeState",
]


def __getattr__(name: str) -> Any:
    """Resolve public exports lazily so light CLIs avoid heavy imports."""
    if name == "OpenRangeEnv":
        from open_range.client.client import OpenRangeEnv

        return OpenRangeEnv
    if name == "RangeAction":
        from open_range.models import RangeAction

        return RangeAction
    if name == "RangeObservation":
        from open_range.models import RangeObservation

        return RangeObservation
    if name == "RangeState":
        from open_range.models import RangeState

        return RangeState
    if name == "RangeEnvironment":
        from open_range.server.environment import RangeEnvironment

        return RangeEnvironment
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
