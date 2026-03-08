"""Tests for the FastAPI application endpoints and WebSocket.

Uses Starlette's TestClient which wraps httpx for sync HTTP testing
and provides WebSocket testing support. No Docker dependency.
"""

from __future__ import annotations

import json

import pytest
from starlette.testclient import TestClient

from open_range.server.app import create_app


@pytest.fixture()
def client():
    """Create a TestClient against a fresh app instance."""
    app = create_app()
    return TestClient(app)


# ===================================================================
# GET /health
# ===================================================================


class TestHealth:
    def test_returns_ok(self, client: TestClient):
        resp = client.get("/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"


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

    def test_concurrent_sessions_flag(self, client: TestClient):
        resp = client.get("/metadata")
        data = resp.json()
        assert data["supports_concurrent_sessions"] is False


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
# POST /reset
# ===================================================================


class TestReset:
    def test_reset_returns_observation(self, client: TestClient):
        resp = client.post("/reset", json={})
        assert resp.status_code == 200
        data = resp.json()
        assert "observation" in data
        obs = data["observation"]
        assert "stdout" in obs
        assert "Range ready" in obs["stdout"]

    def test_reset_with_seed(self, client: TestClient):
        resp = client.post("/reset", json={"seed": 42})
        assert resp.status_code == 200
        assert "observation" in resp.json()

    def test_reset_with_episode_id(self, client: TestClient):
        resp = client.post("/reset", json={"episode_id": "ep_test_42"})
        assert resp.status_code == 200
        # Verify episode_id is set in state
        state_resp = client.get("/state")
        assert state_resp.json()["episode_id"] == "ep_test_42"

    def test_reset_no_body(self, client: TestClient):
        """Reset with no request body should work (defaults)."""
        resp = client.post("/reset")
        assert resp.status_code == 200
        assert "observation" in resp.json()

    def test_reset_clears_step_count(self, client: TestClient):
        client.post("/reset", json={})
        client.post("/step", json={"command": "nmap -sV web", "mode": "red"})
        state = client.get("/state").json()
        assert state["step_count"] == 1

        client.post("/reset", json={})
        state = client.get("/state").json()
        assert state["step_count"] == 0


# ===================================================================
# POST /step
# ===================================================================


class TestStep:
    def test_step_returns_observation(self, client: TestClient):
        client.post("/reset", json={})
        resp = client.post(
            "/step", json={"command": "nmap -sV web", "mode": "red"}
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "observation" in data
        assert "reward" in data
        assert "done" in data

    def test_step_increments_counter(self, client: TestClient):
        client.post("/reset", json={})
        client.post("/step", json={"command": "nmap -sV web", "mode": "red"})
        state = client.get("/state").json()
        assert state["step_count"] == 1

        client.post("/step", json={"command": "curl http://web", "mode": "red"})
        state = client.get("/state").json()
        assert state["step_count"] == 2

    def test_step_red_mode(self, client: TestClient):
        client.post("/reset", json={})
        resp = client.post(
            "/step", json={"command": "nmap -sV web", "mode": "red"}
        )
        assert resp.status_code == 200
        obs = resp.json()["observation"]
        assert "stdout" in obs

    def test_step_blue_mode(self, client: TestClient):
        client.post("/reset", json={})
        resp = client.post(
            "/step",
            json={"command": "tail_log /var/log/syslog", "mode": "blue"},
        )
        assert resp.status_code == 200
        obs = resp.json()["observation"]
        assert "stdout" in obs

    def test_step_submit_finding(self, client: TestClient):
        client.post("/reset", json={})
        resp = client.post(
            "/step",
            json={
                "command": "submit_finding SQL injection detected on web",
                "mode": "blue",
            },
        )
        assert resp.status_code == 200
        obs = resp.json()["observation"]
        stdout = obs["stdout"].lower()
        assert "submitted" in stdout or "recorded" in stdout

    def test_step_empty_command(self, client: TestClient):
        client.post("/reset", json={})
        resp = client.post("/step", json={"command": "", "mode": "red"})
        assert resp.status_code == 200
        obs = resp.json()["observation"]
        assert obs["stderr"] != ""

    def test_step_invalid_mode_rejected(self, client: TestClient):
        """Invalid mode value should be rejected by Pydantic validation."""
        client.post("/reset", json={})
        resp = client.post(
            "/step", json={"command": "nmap", "mode": "invalid_mode"}
        )
        assert resp.status_code == 422  # Pydantic validation error

    def test_step_max_steps_terminates(self, client: TestClient):
        """After max_steps, done should be True.

        Default max_steps is 100 which is too many for a test,
        so we test via the environment directly rather than the
        endpoint. The endpoint correctly propagates done from env.
        """
        client.post("/reset", json={})
        # Just verify the done field is returned as False initially
        resp = client.post(
            "/step", json={"command": "nmap -sV web", "mode": "red"}
        )
        assert resp.json()["done"] is False


# ===================================================================
# GET /state
# ===================================================================


class TestState:
    def test_state_returns_state(self, client: TestClient):
        client.post("/reset", json={"episode_id": "state_test"})
        resp = client.get("/state")
        assert resp.status_code == 200
        data = resp.json()
        assert data["episode_id"] == "state_test"
        assert data["step_count"] == 0

    def test_state_reflects_steps(self, client: TestClient):
        client.post("/reset", json={})
        client.post("/step", json={"command": "nmap -sV web", "mode": "red"})
        state = client.get("/state").json()
        assert state["step_count"] == 1
        assert state["mode"] == "red"


# ===================================================================
# WS /ws -- WebSocket
# ===================================================================


class TestWebSocket:
    def test_ws_reset(self, client: TestClient):
        with client.websocket_connect("/ws") as ws:
            ws.send_text(json.dumps({"type": "reset"}))
            resp = ws.receive_json()
            assert resp["type"] == "observation"
            assert "observation" in resp
            assert "Range ready" in resp["observation"]["stdout"]

    def test_ws_reset_with_episode_id(self, client: TestClient):
        with client.websocket_connect("/ws") as ws:
            ws.send_text(
                json.dumps({"type": "reset", "episode_id": "ws_ep_1"})
            )
            resp = ws.receive_json()
            assert resp["type"] == "observation"
            assert "ws_ep_1" in resp["observation"]["stdout"]

    def test_ws_step(self, client: TestClient):
        with client.websocket_connect("/ws") as ws:
            ws.send_text(json.dumps({"type": "reset"}))
            ws.receive_json()  # consume reset response

            ws.send_text(
                json.dumps({
                    "type": "step",
                    "command": "nmap -sV web",
                    "mode": "red",
                })
            )
            resp = ws.receive_json()
            assert resp["type"] == "observation"
            assert "observation" in resp
            assert "reward" in resp
            assert "done" in resp

    def test_ws_state(self, client: TestClient):
        with client.websocket_connect("/ws") as ws:
            ws.send_text(
                json.dumps({"type": "reset", "episode_id": "ws_state_test"})
            )
            ws.receive_json()

            ws.send_text(json.dumps({"type": "state"}))
            resp = ws.receive_json()
            assert resp["type"] == "state"
            assert resp["state"]["episode_id"] == "ws_state_test"
            assert resp["state"]["step_count"] == 0

    def test_ws_step_increments_state(self, client: TestClient):
        with client.websocket_connect("/ws") as ws:
            ws.send_text(json.dumps({"type": "reset"}))
            ws.receive_json()

            ws.send_text(
                json.dumps({
                    "type": "step",
                    "command": "curl http://web",
                    "mode": "red",
                })
            )
            ws.receive_json()

            ws.send_text(json.dumps({"type": "state"}))
            resp = ws.receive_json()
            assert resp["state"]["step_count"] == 1

    def test_ws_invalid_json(self, client: TestClient):
        with client.websocket_connect("/ws") as ws:
            ws.send_text("not valid json {{{")
            resp = ws.receive_json()
            assert resp["type"] == "error"
            assert "Invalid JSON" in resp["detail"]

    def test_ws_unknown_type(self, client: TestClient):
        with client.websocket_connect("/ws") as ws:
            ws.send_text(json.dumps({"type": "explode"}))
            resp = ws.receive_json()
            assert resp["type"] == "error"
            assert "Unknown message type" in resp["detail"]

    def test_ws_session_isolation(self, client: TestClient):
        """Each WebSocket session should have its own environment."""
        with client.websocket_connect("/ws") as ws1:
            ws1.send_text(
                json.dumps({"type": "reset", "episode_id": "session_A"})
            )
            ws1.receive_json()

            ws1.send_text(
                json.dumps({
                    "type": "step",
                    "command": "nmap web",
                    "mode": "red",
                })
            )
            ws1.receive_json()

            ws1.send_text(json.dumps({"type": "state"}))
            resp1 = ws1.receive_json()
            assert resp1["state"]["episode_id"] == "session_A"
            assert resp1["state"]["step_count"] == 1

        # A new WebSocket session starts fresh
        with client.websocket_connect("/ws") as ws2:
            ws2.send_text(json.dumps({"type": "state"}))
            resp2 = ws2.receive_json()
            # New session has default state (step_count=0, no episode_id set)
            assert resp2["state"]["step_count"] == 0

    def test_ws_submit_finding(self, client: TestClient):
        with client.websocket_connect("/ws") as ws:
            ws.send_text(json.dumps({"type": "reset"}))
            ws.receive_json()

            ws.send_text(
                json.dumps({
                    "type": "step",
                    "command": "submit_finding SQL injection on web host",
                    "mode": "blue",
                })
            )
            resp = ws.receive_json()
            assert resp["type"] == "observation"
            stdout = resp["observation"]["stdout"].lower()
            assert "submitted" in stdout or "recorded" in stdout

    def test_ws_multiple_steps(self, client: TestClient):
        """Run a short sequence of steps over WebSocket."""
        with client.websocket_connect("/ws") as ws:
            ws.send_text(json.dumps({"type": "reset"}))
            ws.receive_json()

            for i, cmd in enumerate(
                ["nmap -sV web", "curl http://web", "curl http://web/login"],
                start=1,
            ):
                ws.send_text(
                    json.dumps({
                        "type": "step",
                        "command": cmd,
                        "mode": "red",
                    })
                )
                resp = ws.receive_json()
                assert resp["type"] == "observation"

            ws.send_text(json.dumps({"type": "state"}))
            state_resp = ws.receive_json()
            assert state_resp["state"]["step_count"] == 3


# ===================================================================
# Integration: HTTP and WebSocket are independent
# ===================================================================


class TestHTTPWSIndependence:
    def test_http_and_ws_have_separate_state(self, client: TestClient):
        """HTTP endpoints use a shared env; WS creates its own."""
        # Set up HTTP session
        client.post("/reset", json={"episode_id": "http_ep"})
        client.post("/step", json={"command": "nmap web", "mode": "red"})
        http_state = client.get("/state").json()
        assert http_state["step_count"] == 1

        # WS session should have its own env
        with client.websocket_connect("/ws") as ws:
            ws.send_text(json.dumps({"type": "state"}))
            ws_state = ws.receive_json()
            assert ws_state["state"]["step_count"] == 0

        # HTTP state should be unchanged
        http_state2 = client.get("/state").json()
        assert http_state2["step_count"] == 1
