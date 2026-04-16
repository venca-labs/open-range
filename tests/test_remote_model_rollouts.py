from __future__ import annotations

import importlib.util
import os
import socket
import sys
from pathlib import Path
from urllib.parse import urlparse

import pytest

from open_range.runtime_types import Action


def _load_module(name: str, relpath: str):
    path = Path(__file__).resolve().parents[1] / relpath
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _endpoint_reachable(url: str) -> bool:
    parsed = urlparse(url)
    host = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    if host is None:
        return False
    try:
        with socket.create_connection((host, port), timeout=0.5):
            return True
    except OSError:
        return False


def test_parse_action_response_accepts_json_fenced_json_and_flat_payload() -> None:
    mod = _load_module(
        "eval_remote_model_rollouts_parse",
        "src/open_range/eval_remote_model_rollouts.py",
    )

    action, error = mod.parse_action_response('{"operation":"wait","timeout_s":5}')
    assert error == ""
    assert action == Action(
        actor_id="red",
        role="red",
        kind="sleep",
        payload={},
        timeout_s=5.0,
    )

    action, error = mod.parse_action_response(
        '```json\n{"operation":"http_request","target":"svc-idp","path":"/"}\n```'
    )
    assert error == ""
    assert action == Action(
        actor_id="red",
        role="red",
        kind="api",
        payload={"target": "svc-idp", "path": "/"},
        timeout_s=30.0,
    )

    action, error = mod.parse_action_response(
        '{"action":{"operation":"run_command","target":"svc-web","command":"id"}}'
    )
    assert error == ""
    assert action == Action(
        actor_id="red",
        role="red",
        kind="shell",
        payload={"target": "svc-web", "command": "id"},
        timeout_s=30.0,
    )

    action, error = mod.parse_action_response(
        "Reasoning: probe the web tier first.\n"
        '<final_action>{"operation":"http_request","target":"svc-web","path":"/health","timeout_s":9}</final_action>'
    )
    assert error == ""
    assert action == Action(
        actor_id="red",
        role="red",
        kind="api",
        payload={"target": "svc-web", "path": "/health"},
        timeout_s=9.0,
    )


def test_remote_chat_client_falls_back_to_sleep_for_invalid_action(monkeypatch) -> None:
    mod = _load_module(
        "eval_remote_model_rollouts_client",
        "src/open_range/eval_remote_model_rollouts.py",
    )

    class FakeResponse:
        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict:
            return {
                "choices": [
                    {
                        "message": {"content": "not-json"},
                        "finish_reason": "stop",
                    }
                ],
                "usage": {"completion_tokens": 4},
            }

    class FakeClient:
        def __init__(self, *args, **kwargs) -> None:
            del args, kwargs

        def post(self, endpoint: str, json: dict, headers: dict) -> FakeResponse:
            assert endpoint == "http://example.test/v1/chat/completions"
            assert json["model"] == "gemma"
            assert "messages" in json
            assert json["max_tokens"] == mod.DEFAULT_MAX_OUTPUT_TOKENS
            assert json["tool_choice"]["function"]["name"] == "submit_action"
            assert json["parallel_tool_calls"] is False
            assert "Content-Type" in headers
            return FakeResponse()

        def close(self) -> None:
            return None

    monkeypatch.setattr(mod.httpx, "Client", FakeClient)

    with mod.RemoteChatClient(
        endpoint="http://example.test/v1/chat/completions",
        model="gemma",
    ) as client:
        result = client.choose(messages=[{"role": "user", "content": "pick one"}])

    assert result.valid is False
    assert result.action == Action(actor_id="red", role="red", kind="sleep", payload={})
    assert result.parse_error
    assert result.request_mode == "tool_calling"
    assert result.request_messages == [{"role": "user", "content": "pick one"}]
    assert result.response_message == {"content": "not-json"}


def test_remote_chat_client_parses_named_tool_call(monkeypatch) -> None:
    mod = _load_module(
        "eval_remote_model_rollouts_tool_call",
        "src/open_range/eval_remote_model_rollouts.py",
    )

    class FakeResponse:
        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict:
            return {
                "choices": [
                    {
                        "message": {
                            "content": "",
                            "tool_calls": [
                                {
                                    "id": "call_1",
                                    "type": "function",
                                    "function": {
                                        "name": "submit_action",
                                        "arguments": '{"operation":"http_request","target":"svc-web","path":"/health","timeout_s":11}',
                                    },
                                }
                            ],
                        },
                        "finish_reason": "tool_calls",
                    }
                ],
                "usage": {"completion_tokens": 9},
            }

    class FakeClient:
        def __init__(self, *args, **kwargs) -> None:
            del args, kwargs

        def post(self, endpoint: str, json: dict, headers: dict) -> FakeResponse:
            assert endpoint == "http://example.test/v1/chat/completions"
            assert json["tool_choice"]["function"]["name"] == "submit_action"
            assert json["tools"][0]["function"]["name"] == "submit_action"
            assert "Content-Type" in headers
            return FakeResponse()

        def close(self) -> None:
            return None

    monkeypatch.setattr(mod.httpx, "Client", FakeClient)

    with mod.RemoteChatClient(
        endpoint="http://example.test/v1/chat/completions",
        model="gemma",
    ) as client:
        result = client.choose(messages=[{"role": "user", "content": "pick one"}])

    assert result.valid is True
    assert result.finish_reason == "tool_calls"
    assert result.action == Action(
        actor_id="red",
        role="red",
        kind="api",
        payload={"target": "svc-web", "path": "/health"},
        timeout_s=11.0,
    )
    assert result.request_mode == "tool_calling"
    assert (
        result.response_message["tool_calls"][0]["function"]["name"] == "submit_action"
    )


def test_evaluate_remote_model_rollouts_with_stubbed_actions() -> None:
    mod = _load_module(
        "eval_remote_model_rollouts_eval",
        "src/open_range/eval_remote_model_rollouts.py",
    )

    def _choose(self, *, messages):
        del self
        return mod.RemoteChoice(
            action=Action(actor_id="red", role="red", kind="sleep", payload={}),
            raw_text='{"operation":"wait","timeout_s":30}',
            valid=True,
            latency_ms=12.5,
            finish_reason="stop",
            usage={"completion_tokens": 3},
            request_messages=messages,
            request_payload={"model": "gemma"},
            request_mode="tool_calling",
            response_message={"content": "", "tool_calls": []},
        )

    mod.RemoteChatClient.choose = _choose

    report = mod.evaluate_remote_model_rollouts(
        endpoint="http://example.test/v1/chat/completions",
        model="gemma",
        validation_profile="graph_only",
        manifest="tier1_basic.yaml",
        mutations=0,
        max_turns=2,
        quiet=True,
    )

    assert report["snapshot_count"] == 1
    assert report["model"] == "gemma"
    assert report["validation_profile"] == "graph_only"
    assert report["valid_action_rate"] == 1.0
    assert "reference_match_rate" not in report
    assert 0.0 <= report["objective_progress_rate"] <= 1.0
    assert report["reports"][0]["pairs"]
    assert report["reports"][0]["weakness_count"] >= 1
    assert "weaknesses" not in report["reports"][0]
    pick = report["reports"][0]["pairs"][0]["picks"][0]
    assert pick["request_mode"] == "tool_calling"
    assert pick["request_messages"][0]["role"] == "system"
    assert isinstance(pick["request_payload"], dict)
    assert isinstance(pick["response_message"], dict)
    assert "reference_action" not in pick


@pytest.mark.live_model
def test_evaluate_remote_model_rollouts_live_endpoint_smoke() -> None:
    endpoint = os.environ.get("OPENAI_CHAT_COMPLETIONS_URL", "").strip()
    model = os.environ.get("OPENAI_MODEL", "").strip()
    api_key = os.environ.get("OPENAI_API_KEY", "").strip()
    if not endpoint or not model:
        pytest.skip("set OPENAI_CHAT_COMPLETIONS_URL and OPENAI_MODEL to enable")
    if not _endpoint_reachable(endpoint):
        pytest.skip(f"endpoint not reachable: {endpoint}")

    mod = _load_module(
        "eval_remote_model_rollouts_live",
        "src/open_range/eval_remote_model_rollouts.py",
    )

    report = mod.evaluate_remote_model_rollouts(
        endpoint=endpoint,
        model=model,
        api_key=api_key,
        validation_profile="graph_only",
        manifest="tier1_basic.yaml",
        mutations=0,
        max_turns=1,
        timeout_s=20.0,
        quiet=True,
    )

    assert report["snapshot_count"] == 1
    assert 0.0 <= report["valid_action_rate"] <= 1.0
    assert report["reports"][0]["pairs"]
