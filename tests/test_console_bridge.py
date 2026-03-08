"""Focused console bridge tests without TestClient transport."""

from __future__ import annotations

import json
from types import SimpleNamespace
from unittest.mock import patch

from open_range.protocols import SnapshotSpec
from open_range.server.app import create_app
from open_range.server.console import (
    api_episode,
    api_history,
    api_snapshot,
    clear_episode,
    clear_history,
    get_history,
)
from open_range.server.environment import RangeEnvironment
from open_range.server.models import RangeAction

_TEST_SNAPSHOT = SnapshotSpec(
    topology={"hosts": ["attacker", "siem"]},
    flags=[],
    golden_path=[],
    task={
        "red_briefing": "Console bridge test mode.",
        "blue_briefing": "Console bridge test mode.",
    },
)


def _request(app):
    return SimpleNamespace(app=app)


def _json_response_payload(response) -> dict | list:
    return json.loads(response.body.decode())


def test_http_reset_publishes_console_snapshot_and_episode():
    clear_episode()
    clear_history()
    with patch(
        "open_range.server.environment.RangeEnvironment._select_snapshot",
        return_value=_TEST_SNAPSHOT,
    ), patch(
        "open_range.server.environment.RangeEnvironment._ensure_clean_reset_path",
    ):
        app = create_app()
        env = app.state.openenv_server._env_factory()
        try:
            env.reset(episode_id="http_console_ep")
        finally:
            env.close()

        snapshot = _json_response_payload(_run(api_snapshot(_request(app))))
        episode = _json_response_payload(_run(api_episode(_request(app))))

    assert snapshot["id"] == "http_console_ep"
    assert snapshot["hosts"] == ["attacker", "siem"]
    assert snapshot["state_scope"] == "published_episode"
    assert episode["step_count"] == 0
    assert episode["mode"] == "red"
    assert episode["state_scope"] == "published_episode"


def test_environment_reset_clears_history_and_records_reset():
    clear_episode()
    clear_history()
    env = RangeEnvironment(docker_available=False)

    env.reset(snapshot=_TEST_SNAPSHOT, episode_id="console_reset_ep")

    history = get_history()
    assert len(history) == 1
    assert history[0]["command"] == "reset"
    assert history[0]["mode"] == "system"
    assert history[0]["episode_id"] == "console_reset_ep"


def test_environment_meta_steps_record_console_history():
    clear_episode()
    clear_history()
    env = RangeEnvironment(docker_available=False)
    env.reset(snapshot=_TEST_SNAPSHOT, episode_id="console_meta_ep")

    env.step(RangeAction(command="submit_finding suspicious scan on web", mode="blue"))

    history = _json_response_payload(_run(api_history()))
    assert len(history) == 2
    assert history[0]["command"] == "submit_finding suspicious scan on web"
    assert history[0]["mode"] == "blue"
    assert history[1]["command"] == "reset"


def _run(awaitable):
    import asyncio

    return asyncio.run(awaitable)
