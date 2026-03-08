"""Tests for the FastAPI application endpoints and WebSocket.

Uses Starlette's TestClient which wraps httpx for sync HTTP testing
and provides WebSocket testing support. No Docker dependency.

OpenEnv HTTP endpoints are stateless (new env per request).
Stateful tests use WebSocket sessions.
"""

from __future__ import annotations

import json
from unittest.mock import patch

import pytest
from starlette.testclient import TestClient

from open_range.protocols import SnapshotSpec


_TEST_SNAPSHOT = SnapshotSpec(
    topology={"hosts": ["attacker", "siem"]},
    flags=[],
    golden_path=[],
    task={
        "red_briefing": "Test mode — app endpoint tests.",
        "blue_briefing": "Test mode — app endpoint tests.",
    },
)


@pytest.fixture()
def client():
    """Create a TestClient against a fresh app instance.

    Patches ``_select_snapshot`` so HTTP /reset works without a
    ManagedSnapshotRuntime (which requires a manifest and snapshot
    store on disk).
    """
    with patch(
        "open_range.server.environment.RangeEnvironment._select_snapshot",
        return_value=_TEST_SNAPSHOT,
    ):
        from open_range.server.app import create_app

        app = create_app()
        yield TestClient(app)


# ===================================================================
# GET /health
# ===================================================================


class TestHealth:
    def test_returns_healthy(self, client: TestClient):
        resp = client.get("/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "healthy"


# ===================================================================
# GET /metadata
# ===================================================================


class TestMetadata:
    def test_returns_metadata(self, client: TestClient):
        resp = client.get("/metadata")
        assert resp.status_code == 200
        data = resp.json()
        assert data["name"] == "open_range"
        assert "version" in data
        assert "description" in data


# ===================================================================
# GET /schema
# ===================================================================


class TestSchema:
    def test_returns_schemas(self, client: TestClient):
        resp = client.get("/schema")
        assert resp.status_code == 200
        data = resp.json()
        assert "action" in data
        assert "observation" in data
        assert "state" in data

    def test_action_schema_has_command(self, client: TestClient):
        resp = client.get("/schema")
        data = resp.json()
        props = data["action"].get("properties", {})
        assert "command" in props
        assert "mode" in props

    def test_observation_schema_has_stdout(self, client: TestClient):
        resp = client.get("/schema")
        data = resp.json()
        props = data["observation"].get("properties", {})
        assert "stdout" in props

    def test_state_schema_has_episode_id(self, client: TestClient):
        resp = client.get("/schema")
        data = resp.json()
        props = data["state"].get("properties", {})
        assert "episode_id" in props


# ===================================================================
# POST /reset (HTTP -- stateless, just checks response format)
# ===================================================================


class TestReset:
    def test_reset_returns_observation(self, client: TestClient):
        resp = client.post("/reset", json={})
        assert resp.status_code == 200
        data = resp.json()
        assert "observation" in data
        assert "reward" in data
        assert "done" in data
        obs = data["observation"]
        assert "stdout" in obs
        assert "Range ready" in obs["stdout"]

    def test_reset_with_seed(self, client: TestClient):
        resp = client.post("/reset", json={"seed": 42})
        assert resp.status_code == 200
        assert "observation" in resp.json()

    def test_reset_no_body(self, client: TestClient):
        """Reset with no request body should work (defaults)."""
        resp = client.post("/reset")
        assert resp.status_code == 200
        assert "observation" in resp.json()


# ===================================================================
# POST /step (HTTP -- stateless, just checks response format)
# ===================================================================


class TestStep:
    def test_step_returns_observation(self, client: TestClient):
        resp = client.post(
            "/step",
            json={"action": {"command": "nmap -sV web", "mode": "red"}},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "observation" in data
        assert "reward" in data
        assert "done" in data

    def test_step_invalid_mode_rejected(self, client: TestClient):
        """Invalid mode value should be rejected by Pydantic validation."""
        resp = client.post(
            "/step",
            json={"action": {"command": "nmap", "mode": "invalid_mode"}},
        )
        assert resp.status_code == 422


# ===================================================================
# WS /ws -- stateful tests via WebSocket
# ===================================================================


class TestWebSocket:
    def test_ws_reset(self, client: TestClient):
        with client.websocket_connect("/ws") as ws:
            ws.send_text(json.dumps({"type": "reset"}))
            resp = ws.receive_json()
            assert resp["type"] == "observation"
            obs = resp["data"]["observation"]
            assert "Range ready" in obs["stdout"]

    def test_ws_reset_with_episode_id(self, client: TestClient):
        with client.websocket_connect("/ws") as ws:
            ws.send_text(
                json.dumps({
                    "type": "reset",
                    "data": {"episode_id": "ws_ep_1"},
                })
            )
            resp = ws.receive_json()
            assert resp["type"] == "observation"
            assert "ws_ep_1" in resp["data"]["observation"]["stdout"]

    def test_ws_step(self, client: TestClient):
        with client.websocket_connect("/ws") as ws:
            ws.send_text(json.dumps({"type": "reset"}))
            ws.receive_json()

            ws.send_text(
                json.dumps({
                    "type": "step",
                    "data": {"command": "nmap -sV web", "mode": "red"},
                })
            )
            resp = ws.receive_json()
            assert resp["type"] == "observation"
            assert "stdout" in resp["data"]["observation"]
            assert "reward" in resp["data"]
            assert "done" in resp["data"]

    def test_ws_state(self, client: TestClient):
        with client.websocket_connect("/ws") as ws:
            ws.send_text(
                json.dumps({
                    "type": "reset",
                    "data": {"episode_id": "ws_state_test"},
                })
            )
            ws.receive_json()

            ws.send_text(json.dumps({"type": "state"}))
            resp = ws.receive_json()
            assert resp["type"] == "state"
            assert resp["data"]["episode_id"] == "ws_state_test"
            assert resp["data"]["step_count"] == 0

    def test_ws_step_increments_state(self, client: TestClient):
        with client.websocket_connect("/ws") as ws:
            ws.send_text(json.dumps({"type": "reset"}))
            ws.receive_json()

            ws.send_text(
                json.dumps({
                    "type": "step",
                    "data": {"command": "curl http://web", "mode": "red"},
                })
            )
            ws.receive_json()

            ws.send_text(json.dumps({"type": "state"}))
            resp = ws.receive_json()
            assert resp["data"]["step_count"] == 1

    def test_ws_reset_clears_step_count(self, client: TestClient):
        with client.websocket_connect("/ws") as ws:
            # Reset and step
            ws.send_text(json.dumps({"type": "reset"}))
            ws.receive_json()
            ws.send_text(
                json.dumps({
                    "type": "step",
                    "data": {"command": "nmap web", "mode": "red"},
                })
            )
            ws.receive_json()

            # Verify step count
            ws.send_text(json.dumps({"type": "state"}))
            state = ws.receive_json()
            assert state["data"]["step_count"] == 1

            # Reset again
            ws.send_text(json.dumps({"type": "reset"}))
            ws.receive_json()

            ws.send_text(json.dumps({"type": "state"}))
            state = ws.receive_json()
            assert state["data"]["step_count"] == 0

    def test_ws_red_and_blue_mode(self, client: TestClient):
        with client.websocket_connect("/ws") as ws:
            ws.send_text(json.dumps({"type": "reset"}))
            ws.receive_json()

            # Red step
            ws.send_text(
                json.dumps({
                    "type": "step",
                    "data": {"command": "nmap -sV web", "mode": "red"},
                })
            )
            resp = ws.receive_json()
            assert resp["type"] == "observation"

            # Blue step
            ws.send_text(
                json.dumps({
                    "type": "step",
                    "data": {"command": "tail_log /var/log/syslog", "mode": "blue"},
                })
            )
            resp = ws.receive_json()
            assert resp["type"] == "observation"

            ws.send_text(json.dumps({"type": "state"}))
            state = ws.receive_json()
            assert state["data"]["step_count"] == 2

    def test_ws_submit_finding(self, client: TestClient):
        with client.websocket_connect("/ws") as ws:
            ws.send_text(json.dumps({"type": "reset"}))
            ws.receive_json()

            ws.send_text(
                json.dumps({
                    "type": "step",
                    "data": {
                        "command": "submit_finding SQL injection on web host",
                        "mode": "blue",
                    },
                })
            )
            resp = ws.receive_json()
            assert resp["type"] == "observation"
            stdout = resp["data"]["observation"]["stdout"].lower()
            assert "submitted" in stdout or "recorded" in stdout

    def test_ws_empty_command(self, client: TestClient):
        with client.websocket_connect("/ws") as ws:
            ws.send_text(json.dumps({"type": "reset"}))
            ws.receive_json()

            ws.send_text(
                json.dumps({
                    "type": "step",
                    "data": {"command": "", "mode": "red"},
                })
            )
            resp = ws.receive_json()
            assert resp["type"] == "observation"
            assert resp["data"]["observation"]["stderr"] != ""

    def test_ws_invalid_json(self, client: TestClient):
        with client.websocket_connect("/ws") as ws:
            ws.send_text("not valid json {{{")
            resp = ws.receive_json()
            assert resp["type"] == "error"

    def test_ws_unknown_type(self, client: TestClient):
        with client.websocket_connect("/ws") as ws:
            ws.send_text(json.dumps({"type": "explode"}))
            resp = ws.receive_json()
            assert resp["type"] == "error"

    def test_ws_session_isolation(self, client: TestClient):
        """Each WebSocket session should have its own environment."""
        with client.websocket_connect("/ws") as ws1:
            ws1.send_text(
                json.dumps({
                    "type": "reset",
                    "data": {"episode_id": "session_A"},
                })
            )
            ws1.receive_json()

            ws1.send_text(
                json.dumps({
                    "type": "step",
                    "data": {"command": "nmap web", "mode": "red"},
                })
            )
            ws1.receive_json()

            ws1.send_text(json.dumps({"type": "state"}))
            resp1 = ws1.receive_json()
            assert resp1["data"]["episode_id"] == "session_A"
            assert resp1["data"]["step_count"] == 1

        # A new WebSocket session starts fresh
        with client.websocket_connect("/ws") as ws2:
            ws2.send_text(json.dumps({"type": "state"}))
            resp2 = ws2.receive_json()
            assert resp2["data"]["step_count"] == 0

    def test_ws_multiple_steps(self, client: TestClient):
        """Run a short sequence of steps over WebSocket."""
        with client.websocket_connect("/ws") as ws:
            ws.send_text(json.dumps({"type": "reset"}))
            ws.receive_json()

            for cmd in [
                "nmap -sV web",
                "curl http://web",
                "curl http://web/login",
            ]:
                ws.send_text(
                    json.dumps({
                        "type": "step",
                        "data": {"command": cmd, "mode": "red"},
                    })
                )
                resp = ws.receive_json()
                assert resp["type"] == "observation"

            ws.send_text(json.dumps({"type": "state"}))
            state_resp = ws.receive_json()
            assert state_resp["data"]["step_count"] == 3
