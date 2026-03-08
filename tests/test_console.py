"""Tests for the operator debugging console.

Uses Starlette's TestClient against the OpenEnv app with console router.
No Docker dependency.

The console prefers live WebSocket session state, then published reset/step
state from real traffic, then a local fallback env for dev/test use.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest
from starlette.testclient import TestClient

from open_range.protocols import SnapshotSpec
from open_range.server.app import create_app
from open_range.server.console import clear_episode, clear_history, record_action
from open_range.server.environment import RangeEnvironment

_TEST_SNAPSHOT = SnapshotSpec(
    topology={"hosts": ["attacker", "siem"]},
    flags=[],
    golden_path=[],
    task={
        "red_briefing": "Console test mode.",
        "blue_briefing": "Console test mode.",
    },
)


@pytest.fixture()
def client():
    """Create a TestClient with a shared env on app.state for console API."""
    app = create_app()
    # Store a shared env so console API endpoints can access state
    env = RangeEnvironment(docker_available=False)
    app.state.env = env
    clear_episode()
    clear_history()
    yield TestClient(app)
    clear_episode()
    clear_history()


@pytest.fixture()
def env(client: TestClient) -> RangeEnvironment:
    """Return the shared env stored on app.state."""
    return client.app.state.env


# ===================================================================
# GET /console -- HTML page
# ===================================================================


class TestConsolePage:
    def test_returns_html(self, client: TestClient):
        resp = client.get("/console")
        assert resp.status_code == 200
        assert "text/html" in resp.headers["content-type"]

    def test_html_contains_title(self, client: TestClient):
        resp = client.get("/console")
        assert "OpenRange Operator Console" in resp.text

    def test_trailing_slash(self, client: TestClient):
        resp = client.get("/console/")
        assert resp.status_code == 200
        assert "text/html" in resp.headers["content-type"]


# ===================================================================
# GET /console/api/snapshot
# ===================================================================


class TestSnapshotAPI:
    def test_returns_json(self, client: TestClient):
        resp = client.get("/console/api/snapshot")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, dict)

    def test_snapshot_before_reset(self, client: TestClient):
        """Before reset, snapshot should have null id."""
        data = client.get("/console/api/snapshot").json()
        assert data["id"] is None

    def test_snapshot_after_reset(self, client: TestClient, env: RangeEnvironment):
        env.reset(snapshot=_TEST_SNAPSHOT, episode_id="snap_test_1")
        data = client.get("/console/api/snapshot").json()
        assert data["id"] == "snap_test_1"
        assert "hosts" in data
        assert "zones" in data
        assert "vuln_count" in data
        assert "tier" in data

    def test_snapshot_no_truth_graph_or_flags(self, client: TestClient, env: RangeEnvironment):
        """Snapshot API must NOT leak truth_graph or flag values."""
        env.reset(snapshot=_TEST_SNAPSHOT)
        data = client.get("/console/api/snapshot").json()
        assert "truth_graph" not in data
        assert "flags" not in data
        assert "golden_path" not in data

    def test_http_reset_publishes_snapshot_to_console(self):
        with patch(
            "open_range.server.environment.RangeEnvironment._select_snapshot",
            return_value=_TEST_SNAPSHOT,
        ), patch(
            "open_range.server.environment.RangeEnvironment._ensure_clean_reset_path",
        ):
            app = create_app()
            clear_episode()
            clear_history()
            client = TestClient(app)
            resp = client.post("/reset", json={"episode_id": "http_reset_1"})
            assert resp.status_code == 200

            data = client.get("/console/api/snapshot").json()
            assert data["id"] == "http_reset_1"
            assert data["state_scope"] == "published_episode"
            assert data["hosts"] == ["attacker", "siem"]
            clear_episode()
            clear_history()


# ===================================================================
# GET /console/api/episode
# ===================================================================


class TestEpisodeAPI:
    def test_returns_json(self, client: TestClient):
        resp = client.get("/console/api/episode")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, dict)

    def test_episode_fields(self, client: TestClient, env: RangeEnvironment):
        env.reset(snapshot=_TEST_SNAPSHOT)
        data = client.get("/console/api/episode").json()
        assert "step_count" in data
        assert "flags_found" in data
        assert "mode" in data
        assert "services_status" in data

    def test_episode_step_count_updates(self, client: TestClient, env: RangeEnvironment):
        from open_range.server.models import RangeAction

        env.reset(snapshot=_TEST_SNAPSHOT)
        data = client.get("/console/api/episode").json()
        assert data["step_count"] == 0

        env.step(RangeAction(command="nmap web", mode="red"))
        data = client.get("/console/api/episode").json()
        assert data["step_count"] == 1

    def test_http_reset_publishes_episode_to_console(self):
        with patch(
            "open_range.server.environment.RangeEnvironment._select_snapshot",
            return_value=_TEST_SNAPSHOT,
        ), patch(
            "open_range.server.environment.RangeEnvironment._ensure_clean_reset_path",
        ):
            app = create_app()
            clear_episode()
            clear_history()
            client = TestClient(app)
            client.post("/reset", json={"episode_id": "http_reset_2"})
            data = client.get("/console/api/episode").json()
            assert data["step_count"] == 0
            assert data["mode"] == "red"
            assert data["state_scope"] == "published_episode"
            clear_episode()
            clear_history()


# ===================================================================
# GET /console/api/history
# ===================================================================


class TestHistoryAPI:
    def test_returns_list(self, client: TestClient):
        resp = client.get("/console/api/history")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list)

    def test_history_empty_initially(self, client: TestClient):
        data = client.get("/console/api/history").json()
        assert data == []

    def test_history_records_actions(self, client: TestClient):
        import time

        record_action({"step": 1, "command": "nmap -sV web", "mode": "red", "time": time.time()})
        record_action({"step": 2, "command": "tail -f /var/log/syslog", "mode": "blue", "time": time.time()})
        data = client.get("/console/api/history").json()
        assert len(data) == 2
        # Newest first
        assert data[0]["mode"] == "blue"
        assert data[1]["mode"] == "red"

    def test_history_has_timestamps(self, client: TestClient):
        import time

        record_action({"step": 1, "command": "nmap web", "mode": "red", "time": time.time()})
        data = client.get("/console/api/history").json()
        assert len(data) == 1
        assert "time" in data[0]
        assert isinstance(data[0]["time"], float)

    def test_history_updates_from_environment_steps(self, client: TestClient, env: RangeEnvironment):
        from open_range.server.models import RangeAction

        env.reset(snapshot=_TEST_SNAPSHOT)
        env.step(RangeAction(command="nmap -sV web", mode="red"))
        data = client.get("/console/api/history").json()
        assert len(data) == 2
        assert data[0]["command"] == "nmap -sV web"
        assert data[0]["mode"] == "red"
        assert data[1]["command"] == "reset"
        assert data[1]["mode"] == "system"

    def test_history_records_meta_step_commands(self, client: TestClient, env: RangeEnvironment):
        from open_range.server.models import RangeAction

        env.reset(snapshot=_TEST_SNAPSHOT)
        env.step(RangeAction(command="submit_finding suspicious scan on web", mode="blue"))
        data = client.get("/console/api/history").json()
        assert data[0]["command"] == "submit_finding suspicious scan on web"
        assert data[0]["mode"] == "blue"

    def test_history_reset_clears_prior_entries_and_records_reset(self, client: TestClient, env: RangeEnvironment):
        import time

        record_action({"step": 99, "command": "old", "mode": "red", "time": time.time()})

        env.reset(snapshot=_TEST_SNAPSHOT, episode_id="history_reset")
        data = client.get("/console/api/history").json()
        assert len(data) == 1
        assert data[0]["command"] == "reset"
        assert data[0]["mode"] == "system"
        assert data[0]["episode_id"] == "history_reset"

    def test_history_max_20(self, client: TestClient):
        """History API should return at most 20 entries."""
        import time

        for i in range(25):
            record_action({"step": i, "command": f"cmd_{i}", "mode": "red", "time": time.time()})
        data = client.get("/console/api/history").json()
        assert len(data) == 20

    def test_http_reset_records_history(self):
        with patch(
            "open_range.server.environment.RangeEnvironment._select_snapshot",
            return_value=_TEST_SNAPSHOT,
        ), patch(
            "open_range.server.environment.RangeEnvironment._ensure_clean_reset_path",
        ):
            app = create_app()
            clear_episode()
            clear_history()
            client = TestClient(app)
            client.post("/reset", json={"episode_id": "http_reset_3"})
            data = client.get("/console/api/history").json()
            assert len(data) == 1
            assert data[0]["command"] == "reset"
            assert data[0]["mode"] == "system"
            clear_episode()
            clear_history()
