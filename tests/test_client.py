"""Tests for the typed OpenEnv client."""

from open_range.client.client import OpenRangeEnv
from open_range.models import RangeAction, RangeObservation, RangeState
from open_range.server.models import (
    RangeAction as ServerRangeAction,
    RangeObservation as ServerRangeObservation,
    RangeState as ServerRangeState,
)


class TestOpenRangeClient:
    def test_sync_returns_openenv_sync_wrapper(self):
        client = OpenRangeEnv(base_url="http://localhost:8000")
        sync_client = client.sync()

        assert sync_client is not client
        assert hasattr(sync_client, "reset")
        assert hasattr(sync_client, "step")
        assert hasattr(sync_client, "__enter__")

    def test_server_model_module_reexports_shared_models(self):
        assert ServerRangeAction is RangeAction
        assert ServerRangeObservation is RangeObservation
        assert ServerRangeState is RangeState
