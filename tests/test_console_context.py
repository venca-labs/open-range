"""Unit tests for console environment context resolution."""

from __future__ import annotations

from types import SimpleNamespace

from open_range.server.console import _get_env_context
from open_range.server.environment import RangeEnvironment


class _Req:
    def __init__(self, app):
        self.app = app


def _app_with_state(**kwargs):
    return SimpleNamespace(state=SimpleNamespace(**kwargs))


def test_prefers_active_websocket_session_env():
    fallback_env = RangeEnvironment(docker_available=False)
    ws_env = RangeEnvironment(docker_available=False)
    server = SimpleNamespace(
        _sessions={"session_a": ws_env},
        _session_info={"session_a": SimpleNamespace(last_activity_at=10.0)},
    )
    request = _Req(_app_with_state(env=fallback_env, openenv_server=server))

    ctx = _get_env_context(request)
    assert ctx["env"] is ws_env
    assert ctx["state_scope"] == "websocket_session"
    assert ctx["session_id"] == "session_a"
    assert ctx["warning"] is None


def test_uses_app_state_env_when_no_active_session():
    fallback_env = RangeEnvironment(docker_available=False)
    server = SimpleNamespace(_sessions={}, _session_info={})
    request = _Req(_app_with_state(env=fallback_env, openenv_server=server))

    ctx = _get_env_context(request)
    assert ctx["env"] is fallback_env
    assert ctx["state_scope"] == "app_state_env"
    assert ctx["session_id"] is None
    assert isinstance(ctx["warning"], str) and ctx["warning"]


def test_multiple_sessions_selects_most_recent_and_warns():
    older_env = RangeEnvironment(docker_available=False)
    newer_env = RangeEnvironment(docker_available=False)
    server = SimpleNamespace(
        _sessions={"old": older_env, "new": newer_env},
        _session_info={
            "old": SimpleNamespace(last_activity_at=10.0),
            "new": SimpleNamespace(last_activity_at=20.0),
        },
    )
    request = _Req(_app_with_state(openenv_server=server))

    ctx = _get_env_context(request)
    assert ctx["env"] is newer_env
    assert ctx["state_scope"] == "websocket_session"
    assert ctx["session_id"] == "new"
    assert "active sessions" in (ctx["warning"] or "").lower()
