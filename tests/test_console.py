"""Tests for the operator debugging console (issue #28).

Uses Starlette's TestClient against the standalone FastAPI app.
No Docker dependency.
"""

from __future__ import annotations

import pytest
from starlette.testclient import TestClient

from open_range.server.app import create_app


@pytest.fixture()
def client():
    """Create a TestClient against a fresh app instance."""
    app = create_app()
    return TestClient(app)


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

    def test_snapshot_after_reset(self, client: TestClient):
        client.post("/reset", json={"episode_id": "snap_test_1"})
        data = client.get("/console/api/snapshot").json()
        assert data["id"] == "snap_test_1"
        assert "hosts" in data
        assert "zones" in data
        assert "vuln_count" in data
        assert "tier" in data

    def test_snapshot_no_truth_graph_or_flags(self, client: TestClient):
        """Snapshot API must NOT leak truth_graph or flag values."""
        client.post("/reset", json={})
        data = client.get("/console/api/snapshot").json()
        assert "truth_graph" not in data
        assert "flags" not in data
        assert "golden_path" not in data


# ===================================================================
# GET /console/api/episode
# ===================================================================


class TestEpisodeAPI:
    def test_returns_json(self, client: TestClient):
        resp = client.get("/console/api/episode")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, dict)

    def test_episode_fields(self, client: TestClient):
        client.post("/reset", json={})
        data = client.get("/console/api/episode").json()
        assert "step_count" in data
        assert "flags_found" in data
        assert "mode" in data
        assert "services_status" in data

    def test_episode_step_count_updates(self, client: TestClient):
        client.post("/reset", json={})
        data = client.get("/console/api/episode").json()
        assert data["step_count"] == 0

        client.post("/step", json={"command": "nmap web", "mode": "red"})
        data = client.get("/console/api/episode").json()
        assert data["step_count"] == 1


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
        # Reset clears history
        client.post("/reset", json={})
        data = client.get("/console/api/history").json()
        assert data == []

    def test_history_records_actions(self, client: TestClient):
        client.post("/reset", json={})
        client.post("/step", json={"command": "nmap -sV web", "mode": "red"})
        client.post("/step", json={"command": "tail -f /var/log/syslog", "mode": "blue"})
        data = client.get("/console/api/history").json()
        assert len(data) == 2
        # Newest first
        assert data[0]["mode"] == "blue"
        assert data[1]["mode"] == "red"

    def test_history_has_timestamps(self, client: TestClient):
        client.post("/reset", json={})
        client.post("/step", json={"command": "nmap web", "mode": "red"})
        data = client.get("/console/api/history").json()
        assert len(data) == 1
        assert "time" in data[0]
        assert isinstance(data[0]["time"], float)

    def test_history_max_20(self, client: TestClient):
        """History API should return at most 20 entries."""
        client.post("/reset", json={})
        for i in range(25):
            client.post(
                "/step",
                json={"command": f"cmd_{i}", "mode": "red"},
            )
        data = client.get("/console/api/history").json()
        assert len(data) == 20
