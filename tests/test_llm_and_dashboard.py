from __future__ import annotations

import asyncio
import contextlib
import json
import subprocess
import sys
import textwrap
import threading
import time
from collections.abc import Iterator
from dataclasses import replace
from pathlib import Path
from types import MappingProxyType
from typing import Protocol, cast
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import pytest

import openrange as OR
from openrange.dashboard import (
    DashboardArtifactLog,
    DashboardEvent,
    DashboardHTTPServer,
    DashboardView,
    EventBridge,
    activity_summary,
    actor_summaries,
    dashboard_event_from_mapping,
    fallback_narrate,
    health_summary,
    normalized_rows,
    normalized_strings,
    percent_value,
    public_world,
)
from openrange.dashboard import (
    read_dashboard_events as read_dashboard_artifact_events,
)
from openrange.llm import LLMBackendError, parse_json_object, run_codex
from openrange.runtime import (
    preserve_dashboard_events,
    read_base_url,
    read_requests,
    read_result,
    start_runtime_process,
    stop_process,
)

MANIFEST = {
    "world": {"goal": "find the admin flag", "title": "Ops Portal"},
    "pack": {"id": "cyber.webapp.offense"},
}


class LineReader(Protocol):
    def readline(self) -> bytes: ...


def executable(tmp_path: Path, name: str, body: str) -> Path:
    path = tmp_path / name
    path.write_text(
        "#!/usr/bin/env python3\n" + textwrap.dedent(body),
        encoding="utf-8",
    )
    path.chmod(0o755)
    return path


def builder_llm(tmp_path: Path) -> OR.CodexBackend:
    command = executable(
        tmp_path,
        "builder_backend.py",
        """
        import json
        import sys
        from pathlib import Path

        output_path = Path(sys.argv[sys.argv.index("--output-last-message") + 1])
        prompt = json.loads(sys.stdin.read().split("\\n\\n", 1)[1])
        if "task" in prompt:
            output = {
                "verifier_source": (
                    "def verify(state):\\n"
                    "    result = state.get('result', {})\\n"
                    "    world = state.get('world', {})\\n"
                    "    passed = result.get('flag') == world.get('flag')\\n"
                    "    passed = passed and world.get('flag') != ''\\n"
                    "    return {'passed': passed, "
                    "'score': 1.0 if passed else 0.0}\\n"
                ),
                "admission_source": (
                    "def admission_state(interface):\\n"
                    "    robots = interface['http_get']("
                    "'/robots.txt').decode()\\n"
                    "    path = ''\\n"
                    "    for line in robots.splitlines():\\n"
                    "        if line.startswith('Disallow:'):\\n"
                    "            path = line.split(':', 1)[1].strip()\\n"
                    "    data = interface['http_get_json'](path)\\n"
                    "    return {'result': {'flag': data['flag']}, "
                    "'requests': []}\\n"
                ),
            }
        else:
            manifest = prompt["manifest"]
            world = manifest["world"]
            output = {
                "service": world.get("service", "webapp"),
                "title": world.get("title", "OpenRange Web Portal"),
                "flag": world.get("flag", "ORANGE{webapp_admin_flag}"),
            }
        output_path.write_text(json.dumps(output), encoding="utf-8")
        """,
    )
    return OR.CodexBackend(command=command, model="local", timeout=5)


@contextlib.contextmanager
def running_dashboard(view: DashboardView) -> Iterator[str]:
    server = DashboardHTTPServer(("127.0.0.1", 0), view)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        host = cast(str, server.server_address[0])
        port = server.server_address[1]
        yield f"http://{host}:{port}"
    finally:
        view.bridge.close()
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def read_http_json(url: str, *, method: str = "GET") -> dict[str, object]:
    request = Request(url, method=method)
    with urlopen(request, timeout=5) as response:
        return cast(dict[str, object], json.loads(response.read().decode()))


def read_sse_message(response: LineReader) -> dict[str, str]:
    fields: dict[str, str] = {}
    while True:
        line = response.readline().decode().rstrip("\r\n")
        if not line:
            return fields
        name, value = line.split(": ", 1)
        fields[name] = value


def wait_for_turn_count(
    view: DashboardView,
    task_id: str,
    count: int,
) -> list[dict[str, object]]:
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        turns = view.turns(task_id)
        if len(turns) >= count:
            return turns
        time.sleep(0.05)
    return view.turns(task_id)


def read_dashboard_events(run_root: Path) -> list[dict[str, object]]:
    return [
        json.loads(line)
        for line in (run_root / "dashboard.events.jsonl").read_text(
            encoding="utf-8",
        ).splitlines()
    ]


def wait_for_dashboard_action(
    run_root: Path,
    action: dict[str, object],
) -> dict[str, object]:
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        for event in read_dashboard_events(run_root):
            data = cast(dict[str, object], event["data"])
            if data.get("action") == action:
                return event
        time.sleep(0.05)
    raise AssertionError(f"dashboard action was not persisted: {action}")


def test_llm_request_validation_and_json_parser() -> None:
    request = OR.LLMRequest("hello", system="system", json_schema={"type": "object"})
    assert request.as_prompt() == "system\n\nhello"
    assert OR.LLMRequest("hello").as_prompt() == "hello"
    assert parse_json_object('{"ok": true}') == {"ok": True}

    with pytest.raises(OR.LLMRequestError, match="JSON serializable"):
        OR.LLMRequest("bad", json_schema={"x": object()})
    with pytest.raises(LLMBackendError, match="invalid JSON"):
        parse_json_object("{")
    with pytest.raises(LLMBackendError, match="not an object"):
        parse_json_object("[]")


def test_codex_backend_runs_local_command_without_schema(tmp_path: Path) -> None:
    command = executable(
        tmp_path,
        "plain_backend.py",
        """
        import sys

        print(sys.stdin.read().strip().upper())
        """,
    )
    result = OR.CodexBackend(command=command, model="local", timeout=5).complete(
        OR.LLMRequest("hello", system="system"),
    )

    assert result == OR.LLMResult("SYSTEM\n\nHELLO")


def test_codex_backend_reads_schema_output_from_local_command(
    tmp_path: Path,
) -> None:
    command = executable(
        tmp_path,
        "json_backend.py",
        """
        import json
        import sys
        from pathlib import Path

        schema_path = Path(sys.argv[sys.argv.index("--output-schema") + 1])
        output_path = Path(sys.argv[sys.argv.index("--output-last-message") + 1])
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        output_path.write_text(
            json.dumps({"schema": schema["type"], "prompt": sys.stdin.read()}),
            encoding="utf-8",
        )
        print("ignored stdout")
        """,
    )
    result = OR.CodexBackend(command=command, model="local", timeout=5).complete(
        OR.LLMRequest("return json", json_schema={"type": "object"}),
    )

    assert result.parsed_json == {"schema": "object", "prompt": "return json"}
    assert json.loads(result.text)["schema"] == "object"


def test_codex_backend_reports_process_failures(tmp_path: Path) -> None:
    stderr_command = executable(
        tmp_path,
        "stderr_failure.py",
        """
        import sys

        print("boom", file=sys.stderr)
        raise SystemExit(7)
        """,
    )
    stdout_command = executable(
        tmp_path,
        "stdout_failure.py",
        """
        print("bad stdout")
        raise SystemExit(3)
        """,
    )
    silent_command = executable(
        tmp_path,
        "silent_failure.py",
        """
        raise SystemExit(4)
        """,
    )

    with pytest.raises(LLMBackendError, match="boom") as stderr_error:
        OR.CodexBackend(command=stderr_command, model="local", timeout=5).complete(
            OR.LLMRequest("hello"),
        )
    with pytest.raises(LLMBackendError, match="bad stdout"):
        OR.CodexBackend(command=stdout_command, model="local", timeout=5).complete(
            OR.LLMRequest("hello"),
        )
    with pytest.raises(LLMBackendError, match="no output"):
        OR.CodexBackend(command=silent_command, model="local", timeout=5).complete(
            OR.LLMRequest("hello"),
        )

    assert stderr_error.value.returncode == 7


def test_codex_backend_requires_schema_output_file(tmp_path: Path) -> None:
    command = executable(
        tmp_path,
        "missing_output.py",
        """
        import sys

        sys.stdin.read()
        """,
    )

    with pytest.raises(LLMBackendError, match="did not write"):
        OR.CodexBackend(command=command, model="local", timeout=5).complete(
            OR.LLMRequest("return json", json_schema={"type": "object"}),
        )


def test_run_codex_reports_os_errors_and_timeouts(tmp_path: Path) -> None:
    sleeper = executable(
        tmp_path,
        "sleeper.py",
        """
        import time

        time.sleep(5)
        """,
    )

    with pytest.raises(LLMBackendError, match="No such file|not found"):
        run_codex(
            [str(tmp_path / "missing-command")],
            input_text="hello",
            cwd=None,
            timeout=1,
        )
    with pytest.raises(LLMBackendError, match="timed out"):
        run_codex(
            [str(sleeper)],
            input_text="hello",
            cwd=None,
            timeout=0.01,
        )


def test_reference_pack_can_build_with_local_llm_backend(tmp_path: Path) -> None:
    command = executable(
        tmp_path,
        "toy_backend.py",
        """
        import json
        import sys
        from pathlib import Path

        output_path = Path(sys.argv[sys.argv.index("--output-last-message") + 1])
        prompt = json.loads(sys.stdin.read().split("\\n\\n", 1)[1])
        if "task" in prompt:
            output = {
                "verifier_source": (
                    "def verify(state):\\n"
                    "    result = state.get('result', {})\\n"
                    "    world = state.get('world', {})\\n"
                    "    passed = result.get('flag') == world.get('flag')\\n"
                    "    passed = passed and world.get('flag') != ''\\n"
                    "    return {'passed': passed, "
                    "'score': 1.0 if passed else 0.0}\\n"
                ),
                "admission_source": (
                    "def admission_state(interface):\\n"
                    "    robots = interface['http_get']("
                    "'/robots.txt').decode()\\n"
                    "    path = ''\\n"
                    "    for line in robots.splitlines():\\n"
                    "        if line.startswith('Disallow:'):\\n"
                    "            path = line.split(':', 1)[1].strip()\\n"
                    "    data = interface['http_get_json'](path)\\n"
                    "    return {'result': {'flag': data['flag']}, "
                    "'requests': []}\\n"
                ),
            }
        else:
            output = {
                "service": "generated-webapp",
                "title": "generated portal",
                "flag": "ORANGE{generated}",
            }
        output_path.write_text(json.dumps(output), encoding="utf-8")
        """,
    )
    snapshot = OR.build(
        MANIFEST,
        prompt="use local backend",
        llm=OR.CodexBackend(command=command, model="local", timeout=5),
    )

    assert snapshot.world["service"] == "generated-webapp"
    assert snapshot.world["difficulty"] == "llm"
    snapshot_with_cwd = OR.build(
        MANIFEST,
        llm=OR.CodexBackend(command=command, model="local", cwd=tmp_path, timeout=5),
    )
    assert snapshot_with_cwd.world["service"] == "generated-webapp"


def test_dashboard_view_state_events_and_narration(tmp_path: Path) -> None:
    snapshot = OR.build(MANIFEST, llm=builder_llm(tmp_path))
    view = DashboardView(snapshot)

    assert view.topology()["snapshot_id"] == snapshot.id
    topology_world = cast(dict[str, object], view.topology()["world"])
    topology_services = cast(list[dict[str, object]], view.topology()["services"])
    topology_zones = cast(list[str], view.topology()["zones"])
    assert topology_world["title"] == "Ops Portal"
    assert topology_world["flag"] == "[redacted]"
    assert {service["id"] for service in topology_services} >= {
        "svc-web",
        "webapp",
    }
    assert {"dmz", "episode"}.issubset(topology_zones)
    assert public_world(
        {"api_token": "token-value", "password_hint": "hint", "service": "web"},
    ) == {
        "api_token": "[redacted]",
        "password_hint": "[redacted]",
        "service": "web",
    }
    assert view.lineage()["admission"] == snapshot.admission.as_dict()
    assert view.reset()["status"] == "ready"
    assert view.play() == {"status": "playing"}
    assert view.play() == {"status": "already running"}
    event = view.record_event(
        "agent_step",
        actor="red",
        target="webapp",
        data={"action": "browse"},
    )

    state = view.state()
    events = cast(tuple[dict[str, object], ...], state["events"])
    assert event.as_dict()["data"] == {"action": "browse"}
    assert events[0]["type"] == "agent_step"
    assert state["status"] == "playing"
    assert state["event_count"] == 1
    assert state["turn_count"] == 0
    assert state["latest_event"] == event.as_dict()
    assert state["health"] == {
        "uptime": 100.0,
        "defense": 100.0,
        "integrity": 100.0,
    }
    assert state["activity_summary"] == {
        "event_types": {"agent_step": 1},
        "actors": {"red": 1},
        "actor_kinds": {"event": 1},
    }
    assert activity_summary(({"type": "raw", "actor": "system", "data": "x"},)) == {
        "event_types": {"raw": 1},
        "actors": {"system": 1},
        "actor_kinds": {"event": 1},
    }
    assert actor_summaries(({"type": "raw", "actor": "system", "data": "x"},)) == [
        {
            "actor_id": "system",
            "actor_kind": "event",
            "event_count": 1,
            "targets": [""],
            "latest_event_type": "raw",
            "latest_action": None,
            "latest_observation": None,
            "history": [
                {
                    "event_type": "raw",
                    "target": "",
                    "action": None,
                    "observation": None,
                },
            ],
        },
    ]
    briefing_missions = cast(list[dict[str, object]], view.briefing()["missions"])
    assert briefing_missions[0] == {
        "task_id": "find_admin_flag",
        "instruction": snapshot.get_tasks()[0].instruction,
    }
    assert view.narration()["narration"] == "red agent_step webapp"
    assert view.pause() == {"status": "paused"}
    assert view.state()["running"] is False
    assert view.state()["status"] == "paused"
    assert fallback_narrate(()) == "No episode activity yet."


def test_dashboard_http_server_can_start_without_snapshot() -> None:
    view = DashboardView()

    assert view.topology() == {
        "snapshot_id": None,
        "world": {},
        "tasks": [],
        "artifact_paths": [],
        "services": [],
        "edges": [],
        "zones": [],
        "users": [],
        "green_personas": [],
    }
    assert view.lineage() == {"snapshot_id": None, "admission": None, "nodes": []}
    assert view.briefing() == {
        "snapshot_id": None,
        "title": "",
        "goal": "",
        "entrypoints": [],
        "missions": [],
    }

    with running_dashboard(view) as base_url:
        briefing = read_http_json(base_url + "/api/briefing")
        actors = cast(list[dict[str, object]], read_http_json(base_url + "/api/actors"))
        topology = read_http_json(base_url + "/api/topology")
        state = read_http_json(base_url + "/api/state")
        lineage = read_http_json(base_url + "/api/lineage")
        inspection = read_http_json(base_url + "/api/inspect")
        reset = read_http_json(base_url + "/api/episode/reset", method="POST")

        assert topology == {
            "snapshot_id": None,
            "world": {},
            "tasks": [],
            "artifact_paths": [],
            "services": [],
            "edges": [],
            "zones": [],
            "users": [],
            "green_personas": [],
        }
        assert briefing["snapshot_id"] is None
        assert actors == []
        assert state["snapshot_id"] is None
        assert state["status"] == "waiting_for_snapshot"
        assert state["latest_event"] is None
        assert lineage == {"snapshot_id": None, "admission": None, "nodes": []}
        assert inspection["topology"] == topology
        assert reset == {
            "status": "waiting_for_snapshot",
            "snapshot_id": None,
            "topology": topology,
        }


def test_dashboard_http_server_serves_documented_json_endpoints(
    tmp_path: Path,
) -> None:
    snapshot = OR.build(MANIFEST, llm=builder_llm(tmp_path))
    view = DashboardView(snapshot)
    view.record_event(
        "agent_step",
        actor="red",
        target="webapp",
        data={"action": "browse"},
    )

    with running_dashboard(view) as base_url:
        with urlopen(base_url + "/", timeout=5) as response:
            html = response.read().decode()

        briefing = read_http_json(base_url + "/api/briefing")
        actors = cast(list[dict[str, object]], read_http_json(base_url + "/api/actors"))
        topology = read_http_json(base_url + "/api/topology?ignored=1")
        lineage = read_http_json(base_url + "/api/lineage")
        state = read_http_json(base_url + "/api/state")
        narration = read_http_json(base_url + "/api/narrate")
        play = read_http_json(base_url + "/api/episode/play", method="POST")
        already_playing = read_http_json(
            base_url + "/api/episode/play",
            method="POST",
        )
        pause = read_http_json(base_url + "/api/episode/pause", method="POST")
        reset = read_http_json(base_url + "/api/episode/reset", method="POST")

        assert "OpenRange Dashboard" in html
        assert 'id="sim-canvas"' in html
        assert "THREE.WebGLRenderer" in html
        assert "Live Event Feed" in html
        assert "Episode Narrator" in html
        assert "sim-actor-panel" in html
        assert "sim-uptime-gauge" in html
        assert "Briefing" in html
        assert "Actors" in html
        assert "Admission" in html
        assert "Lineage" in html
        assert briefing["snapshot_id"] == snapshot.id
        assert briefing["title"] == "Ops Portal"
        assert cast(list[dict[str, object]], briefing["entrypoints"])[0] == {
            "task_id": "find_admin_flag",
            "kind": "http",
            "target": "webapp",
        }
        assert topology["snapshot_id"] == snapshot.id
        topology_services = cast(list[dict[str, object]], topology["services"])
        assert {service["id"] for service in topology_services} >= {
            "svc-web",
            "webapp",
        }
        assert "dmz" in cast(list[str], topology["zones"])
        assert topology["artifact_paths"] == [
            "app.py",
            "kind/README.md",
            "kind/kind-config.yaml",
            "kind/red-reference-plan.json",
            "kind/render_kind.py",
            "kind/topology.json",
            "pack.json",
        ]
        topology_world = cast(dict[str, object], topology["world"])
        assert topology_world["title"] == "Ops Portal"
        assert topology_world["flag"] == "[redacted]"
        assert lineage["admission"] == snapshot.admission.as_dict()
        assert cast(list[dict[str, object]], state["events"])[0]["data"] == {
            "action": "browse",
        }
        assert state["activity_summary"] == {
            "event_types": {"agent_step": 1},
            "actors": {"red": 1},
            "actor_kinds": {"event": 1},
        }
        assert actors[0]["actor_id"] == "red"
        assert actors[0]["history"] == [
            {
                "event_type": "agent_step",
                "target": "webapp",
                "action": "browse",
                "observation": None,
            },
        ]
        assert narration == {"narration": "red agent_step webapp"}
        assert play == {"status": "playing"}
        assert already_playing == {"status": "already running"}
        assert pause == {"status": "paused"}
        assert reset["status"] == "ready"
        assert reset["snapshot_id"] == snapshot.id

        for request in (
            Request(base_url + "/missing"),
            Request(base_url + "/api/episode/missing", method="POST"),
        ):
            with pytest.raises(HTTPError) as error:
                urlopen(request, timeout=5).read()
            assert error.value.code == 404
            assert json.loads(error.value.read().decode()) == {"error": "not found"}


def test_dashboard_http_server_streams_events_and_narration(
    tmp_path: Path,
) -> None:
    snapshot = OR.build(MANIFEST, llm=builder_llm(tmp_path))
    view = DashboardView(snapshot)
    first = view.record_event("agent_step", actor="red", target="webapp")

    with running_dashboard(view) as base_url:
        events = urlopen(base_url + "/api/events/stream", timeout=5)
        try:
            message = read_sse_message(events)
            second = view.record_event("env_turn", actor="agent", target="webapp")
            live_message = read_sse_message(events)
        finally:
            events.close()

        assert message["id"] == first.id
        assert message["event"] == "agent_step"
        assert json.loads(message["data"])["actor"] == "red"
        assert live_message["id"] == second.id
        assert json.loads(live_message["data"])["type"] == "env_turn"

        narration = urlopen(base_url + "/api/narrate/stream", timeout=5)
        try:
            narration_message = read_sse_message(narration)
        finally:
            narration.close()

        assert narration_message["id"] == first.id
        assert narration_message["event"] == "narration"
        assert json.loads(narration_message["data"]) == {
            "narration": "red agent_step webapp\nagent env_turn webapp",
        }


def test_dashboard_artifact_log_writes_builder_steps(tmp_path: Path) -> None:
    event_log = tmp_path / "dashboard.events.jsonl"
    state_path = tmp_path / "dashboard.json"
    log = DashboardArtifactLog(event_log, state_path, reset=True)

    first = log.record_builder_step(
        "build_started",
        {"pack_id": "cyber.webapp.offense"},
    )
    with event_log.open("a", encoding="utf-8") as handle:
        handle.write("not-json\n")
        handle.write("[]\n")
    reopened = DashboardArtifactLog(event_log, state_path, reset=False)
    second = reopened.record_builder_step("builder_finished")
    malformed = dashboard_event_from_mapping(
        {
            "id": "bad",
            "type": "builder_step",
            "actor": "builder",
            "target": "snapshot",
            "time": "later",
            "data": [],
        },
    )
    events = read_dashboard_artifact_events(event_log)
    state = json.loads(state_path.read_text(encoding="utf-8"))

    assert read_dashboard_artifact_events(tmp_path / "missing.events.jsonl") == []
    assert first.id == "1:builder_step"
    assert second.id == "2:builder_step"
    assert malformed.time == 0.0
    assert malformed.data == {}
    assert [event.data["step"] for event in events] == [
        "build_started",
        "builder_finished",
    ]
    assert state["builder"]["steps"] == [
        {"pack_id": "cyber.webapp.offense", "step": "build_started"},
        {"step": "builder_finished"},
    ]
    assert state["topology"] == {}

    live_event_log = tmp_path / "live-dashboard.events.jsonl"
    live_state = tmp_path / "live-dashboard.json"
    live_event_log.write_text(
        json.dumps(
            DashboardEvent("1:note", "note", "system", "dashboard", 0.0, {}).as_dict(),
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    view = DashboardView(
        event_log_path=live_event_log,
        state_path=live_state,
        reset_artifacts=False,
    )
    assert view.state()["event_count"] == 1


def test_dashboard_view_can_open_persisted_run_artifacts(
    tmp_path: Path,
) -> None:
    event_log = tmp_path / "dashboard.events.jsonl"
    state_path = tmp_path / "dashboard.json"
    event_log.write_text(
        json.dumps(
            DashboardEvent(
                "1:env_turn",
                "env_turn",
                "agent",
                "webapp",
                0.0,
                {
                    "actor_kind": "agent",
                    "action": {"method": "GET"},
                    "target": "webapp",
                },
            ).as_dict(),
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    state_path.write_text(
        json.dumps(
            {
                "topology": {
                    "snapshot_id": "saved",
                    "world": {"title": "Saved Ops", "goal": "inspect"},
                    "tasks": [
                        {
                            "id": "task-1",
                            "instruction": "Inspect the saved run",
                            "entrypoints": [{"kind": "http", "target": "webapp"}],
                        },
                    ],
                    "artifact_paths": [],
                    "services": [
                        {"id": "webapp", "kind": "http", "zone": "episode"},
                    ],
                    "edges": [],
                    "zones": ["episode"],
                    "users": [],
                    "green_personas": [],
                },
                "lineage": {
                    "snapshot_id": "saved",
                    "admission": None,
                    "nodes": [],
                },
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )

    view = DashboardView(
        event_log_path=event_log,
        state_path=state_path,
        reset_artifacts=False,
    )

    assert view.topology()["snapshot_id"] == "saved"
    assert view.briefing()["title"] == "Saved Ops"
    assert view.briefing()["entrypoints"] == [
        {"task_id": "task-1", "kind": "http", "target": "webapp"},
    ]
    assert view.lineage()["snapshot_id"] == "saved"
    assert view.state()["snapshot_id"] == "saved"
    assert view.state()["status"] == "paused"
    assert view.state()["event_count"] == 1

    state_path.write_text("{", encoding="utf-8")
    assert DashboardView(state_path=state_path, reset_artifacts=False).briefing() == {
        "snapshot_id": None,
        "title": "",
        "goal": "",
        "entrypoints": [],
        "missions": [],
    }

    state_path.write_text(
        json.dumps(
            {
                "topology": {
                    "snapshot_id": "sparse",
                    "world": {"title": "Sparse"},
                    "tasks": [
                        "bad",
                        {"id": "task-2", "entrypoints": "bad"},
                        {"id": "task-3", "entrypoints": ["bad"]},
                    ],
                },
            },
        ),
        encoding="utf-8",
    )
    assert DashboardView(state_path=state_path, reset_artifacts=False).briefing() == {
        "snapshot_id": "sparse",
        "title": "Sparse",
        "goal": "",
        "entrypoints": [],
        "missions": [
            {"task_id": "task-2", "instruction": ""},
            {"task_id": "task-3", "instruction": ""},
        ],
    }


def test_dashboard_normalizes_sparse_topology_and_health_edges(
    tmp_path: Path,
) -> None:
    snapshot = OR.build(MANIFEST, llm=builder_llm(tmp_path))
    no_artifact_topology = replace(
        snapshot,
        world=MappingProxyType({"title": "No service"}),
        artifacts=MappingProxyType({"not-topology.json": "{"}),
    )
    sparse_topology = DashboardView(no_artifact_topology).topology()

    assert sparse_topology["services"] == [
        {"id": "webapp", "kind": "http", "zone": "episode", "ports": []},
    ]
    assert sparse_topology["zones"] == ["episode"]

    mixed_artifact_topology = replace(
        snapshot,
        world=MappingProxyType({"title": "Mixed"}),
        artifacts=MappingProxyType(
            {
                "first/topology.json": "[]",
                "second/topology.json": json.dumps({"services": ["svc-a"]}),
            },
        ),
    )
    assert cast(
        list[dict[str, object]],
        DashboardView(mixed_artifact_topology).topology()["services"],
    )[0] == {"id": "svc-a"}

    world_topology = replace(
        snapshot,
        world=MappingProxyType(
            {
                "title": "Mapped",
                "topology": {
                    "services": {"svc-db": {"kind": "db", "zone": "data"}},
                    "zones": ["data"],
                },
                "services": ["svc-worker"],
                "zones": [],
                "users": ["analyst"],
                "green_personas": [{"id": "sarah", "department": "finance"}],
            },
        ),
        artifacts=MappingProxyType({}),
    )
    topology = DashboardView(world_topology).topology()

    assert topology["services"] == [
        {"id": "svc-worker"},
        {"id": "webapp", "kind": "http", "zone": "episode", "ports": []},
    ]
    assert topology["zones"] == ["episode"]
    assert topology["users"] == [{"id": "analyst"}]
    assert topology["green_personas"] == [
        {"id": "sarah", "department": "finance"},
    ]
    assert normalized_rows({"svc-db": {"kind": "db"}}) == [
        {"id": "svc-db", "kind": "db"},
    ]
    assert normalized_rows([1]) == []
    assert normalized_strings("dmz") == []
    assert percent_value(1.5) == 1.5
    assert health_summary(
        (
            {
                "data": {
                    "state": {
                        "uptime": 0.5,
                        "continuity": 0.9,
                        "defense": 150,
                        "blue_reward": 0.2,
                        "integrity": 1.5,
                        "red_reward": 0.3,
                    },
                },
            },
            {"data": "not-a-mapping"},
        ),
    ) == {"uptime": 50.0, "defense": 100.0, "integrity": 1.5}


def test_dashboard_records_actor_turns_from_env_actors(tmp_path: Path) -> None:
    snapshot = OR.build(MANIFEST, llm=builder_llm(tmp_path))
    view = DashboardView(snapshot)
    agent_turn = OR.ActorTurn(
        task_id="find_admin_flag",
        actor_id="agent",
        actor_kind="agent",
        target="webapp",
        action={"method": "GET", "path": "/robots.txt"},
        observation={"status": 200},
        state={"result": {}},
        metadata={"entrypoint": "http"},
    )
    npc_turn = OR.ActorTurn(
        task_id="find_admin_flag",
        actor_id="mentor",
        actor_kind="npc",
        target="agent",
        action={"say": "inspect public hints"},
    )
    system_turn = OR.ActorTurn(
        task_id="audit",
        actor_id="clock",
        actor_kind="system",
        target="world",
        action={"tick": 1},
        state={"time": 1, "continuity": 0.65, "blue_reward": 0.1, "red_reward": 0.25},
    )

    note = view.record_event("note", actor="system", target="dashboard")
    first = view.record_turn(agent_turn)
    second = view.record_turn(npc_turn)
    third = view.record_turn(system_turn)
    state = view.state()
    events = cast(list[dict[str, object]], state["events"])

    assert agent_turn.as_dict() == {
        "task_id": "find_admin_flag",
        "actor_id": "agent",
        "actor_kind": "agent",
        "target": "webapp",
        "action": {"method": "GET", "path": "/robots.txt"},
        "observation": {"status": 200},
        "state": {"result": {}},
        "metadata": {"entrypoint": "http"},
    }
    assert npc_turn.as_dict()["observation"] is None
    assert npc_turn.as_dict()["metadata"] == {}
    assert note.as_dict()["data"] == {}
    assert first.as_dict()["data"] == agent_turn.as_dict()
    assert second.id == "3:env_turn"
    assert third.actor == "clock"
    assert [event["type"] for event in events] == [
        "note",
        "env_turn",
        "env_turn",
        "env_turn",
    ]
    assert view.turns() == [
        agent_turn.as_dict(),
        npc_turn.as_dict(),
        system_turn.as_dict(),
    ]
    assert view.turns("find_admin_flag") == [
        agent_turn.as_dict(),
        npc_turn.as_dict(),
    ]
    assert view.turns("missing") == []
    assert state["health"] == {
        "uptime": 65.0,
        "defense": 90.0,
        "integrity": 75.0,
    }
    actors = view.actors()
    assert [actor["actor_id"] for actor in actors] == [
        "agent",
        "clock",
        "mentor",
        "system",
    ]
    assert actors[0]["actor_kind"] == "agent"
    assert actors[0]["latest_action"] == {"method": "GET", "path": "/robots.txt"}
    assert actors[0]["targets"] == ["webapp"]
    assert actors[-1]["latest_event_type"] == "note"
    inspection = view.inspect()
    assert inspection["actors"] == actors
    assert inspection["turns"] == view.turns()
    assert inspection["state"] == view.state()


def test_episode_runtime_records_env_owned_turns(tmp_path: Path) -> None:
    snapshot = OR.build(MANIFEST, llm=builder_llm(tmp_path))
    task = snapshot.get_tasks()[0]
    run_root = tmp_path / "episode"
    env = OR.EpisodeEnvironment(snapshot, task, run_root)
    episode = env.reset()
    try:
        initial_events = read_dashboard_events(run_root)
        initial_turns = [
            cast(dict[str, object], event["data"]) for event in initial_events
        ]
        dashboard_state = json.loads(
            (run_root / "dashboard.json").read_text(encoding="utf-8"),
        )

        assert [turn["action"] for turn in initial_turns] == [
            {"reset": True},
            {"start": "http_server"},
        ]
        assert dashboard_state["turns"] == initial_turns

        with env.serve_dashboard(port=0) as dashboard:
            state = read_http_json(dashboard.url + "/api/state")
            assert cast(list[dict[str, object]], state["events"])[0]["type"] == (
                "env_turn"
            )
            task_file = json.loads(
                (episode.agent_root / "OPENRANGE_TASK.json").read_text(
                    encoding="utf-8",
                ),
            )
            base_url = str(task_file["base_url"])
            urlopen(base_url + "/robots.txt", timeout=5).read()
            robots_event = wait_for_dashboard_action(
                run_root,
                {"method": "GET", "path": "/robots.txt"},
            )
            live_turns = wait_for_turn_count(episode.dashboard, task.id, 3)
            live_state = read_http_json(dashboard.url + "/api/state")
            assert live_turns[2]["action"] == {
                "method": "GET",
                "path": "/robots.txt",
            }
            assert any(
                event["actor"] == "agent"
                for event in cast(list[dict[str, object]], live_state["events"])
            )
            admin = json.loads(
                urlopen(base_url + "/admin/debug", timeout=5).read().decode(),
            )
            wait_for_dashboard_action(
                run_root,
                {"method": "GET", "path": "/admin/debug"},
            )
            (episode.agent_root / task_file["result_file"]).write_text(
                json.dumps({"flag": admin["flag"]}),
                encoding="utf-8",
            )
            report = env.finish(OR.LLMResult("agent done"))
    finally:
        env.close()

    turns = episode.dashboard.turns(task.id)

    assert task.verify(report.final_state)["passed"] is True
    assert report.as_dict()["agent_output"] == "agent done"
    assert cast(dict[str, object], robots_event["data"])["metadata"] == {
        "source": "http_access_log",
    }
    assert [turn["actor_kind"] for turn in turns] == [
        "system",
        "system",
        "agent",
        "agent",
        "system",
    ]
    assert turns[0]["action"] == {"reset": True}
    assert turns[2]["action"] == {"method": "GET", "path": "/robots.txt"}
    assert turns[3]["action"] == {"method": "GET", "path": "/admin/debug"}
    assert turns[-1]["state"] == report.final_state
    assert episode.dashboard.inspect()["turns"] == turns
    final_events = read_dashboard_events(run_root)
    final_state = json.loads(
        (run_root / "dashboard.json").read_text(encoding="utf-8"),
    )
    assert [event["data"] for event in final_events] == turns
    assert final_state["turns"] == turns
    assert final_state["state"]["events"] == final_events


def test_openrange_run_can_disable_dashboard_artifacts(tmp_path: Path) -> None:
    run_root = tmp_path / "run"
    run = OR.OpenRangeRun(OR.RunConfig(run_root, dashboard=False))
    snapshot = run.build(MANIFEST, llm=builder_llm(tmp_path))
    task = snapshot.get_tasks()[0]
    env = run.episode_environment(snapshot, task)

    try:
        episode = env.reset()
    finally:
        env.close()

    assert episode.run_root == run_root / task.id
    assert not (run_root / "dashboard.events.jsonl").exists()
    assert not (run_root / "dashboard.json").exists()


def test_run_config_starts_live_dashboard_internally(tmp_path: Path) -> None:
    run_root = tmp_path / "run"
    run = OR.OpenRangeRun(OR.RunConfig(run_root, dashboard_port=0))
    snapshot = run.build(MANIFEST, llm=builder_llm(tmp_path))
    task = snapshot.get_tasks()[0]
    env = run.episode_environment(snapshot, task)

    try:
        first = env.reset()
        second = env.reset()
        assert first.dashboard_url is not None
        assert first.dashboard_url == second.dashboard_url
        state = read_http_json(first.dashboard_url + "/api/state")
    finally:
        env.close()

    assert state["snapshot_id"] == snapshot.id
    assert state["turn_count"] == 2


def test_episode_reset_recreates_existing_roots(tmp_path: Path) -> None:
    snapshot = OR.build(MANIFEST, llm=builder_llm(tmp_path))
    task = snapshot.get_tasks()[0]
    env = OR.EpisodeEnvironment(snapshot, task, tmp_path / "episode")
    first = env.reset()
    marker = first.agent_root / "old.txt"
    marker.write_text("old", encoding="utf-8")
    try:
        second = env.reset()
    finally:
        env.close()

    assert second.agent_root.exists()
    assert not marker.exists()
    reset_actions = [
        cast(dict[str, object], event["data"])["action"]
        for event in read_dashboard_events(tmp_path / "episode")
    ]
    assert reset_actions == [
        {"reset": True},
        {"start": "http_server"},
    ]
    preserve_dashboard_events(tmp_path / "missing-dashboard.events.jsonl")


def test_runtime_error_and_reader_paths(tmp_path: Path) -> None:
    snapshot = OR.build(MANIFEST, llm=builder_llm(tmp_path))
    task = snapshot.get_tasks()[0]
    env = OR.EpisodeEnvironment(snapshot, task, tmp_path / "episode")

    assert env.sync_request_log() == ()
    with pytest.raises(OR.EpisodeRuntimeError, match="reset"):
        env.finish(OR.LLMResult("no episode"))
    with pytest.raises(OR.EpisodeRuntimeError, match="missing.py"):
        start_runtime_process(
            tmp_path / "missing.py",
            task.entrypoints[0],
            snapshot.world,
            tmp_path / "log.jsonl",
        )

    app = tmp_path / "app.py"
    app.write_text("", encoding="utf-8")
    bad_entrypoint = OR.Entrypoint(
        "http",
        "webapp",
        {"argv": [{"bad": "value"}]},
    )
    with pytest.raises(OR.EpisodeRuntimeError, match="argv"):
        start_runtime_process(app, bad_entrypoint, snapshot.world, tmp_path / "log")
    bad_argv_shape = OR.Entrypoint("http", "webapp", {"argv": "bad"})
    with pytest.raises(OR.EpisodeRuntimeError, match="argv"):
        start_runtime_process(app, bad_argv_shape, snapshot.world, tmp_path / "log")

    no_stdout = subprocess.Popen([sys.executable, "-c", ""], text=True)
    with pytest.raises(OR.EpisodeRuntimeError, match="stdout"):
        read_base_url(no_stdout)
    no_stdout.wait()

    no_line = subprocess.Popen(
        [sys.executable, "-c", ""],
        stdout=subprocess.PIPE,
        text=True,
    )
    with pytest.raises(OR.EpisodeRuntimeError, match="listening"):
        read_base_url(no_line)

    invalid_line = subprocess.Popen(
        [sys.executable, "-c", "print('[]')"],
        stdout=subprocess.PIPE,
        text=True,
    )
    with pytest.raises(OR.EpisodeRuntimeError, match="invalid"):
        read_base_url(invalid_line)

    assert read_result(tmp_path, "result.json") == {}
    (tmp_path / "result.json").write_text("{", encoding="utf-8")
    assert read_result(tmp_path, "result.json") == {}
    (tmp_path / "result.json").write_text("[]", encoding="utf-8")
    assert read_result(tmp_path, "result.json") == {}
    (tmp_path / "result.json").write_text('{"flag": "FLAG"}', encoding="utf-8")
    assert read_result(tmp_path, "result.json") == {"flag": "FLAG"}

    requests_path = tmp_path / "requests.jsonl"
    assert read_requests(requests_path) == ()
    requests_path.write_text(
        '[]\n{\n{"path": "/admin/debug"}\n',
        encoding="utf-8",
    )
    assert read_requests(requests_path) == ({"path": "/admin/debug"},)

    blocker = executable(
        tmp_path,
        "ignore_term.py",
        """
        import signal
        import time

        signal.signal(signal.SIGTERM, lambda *_: None)
        print("ready", flush=True)
        while True:
            time.sleep(1)
        """,
    )
    process = subprocess.Popen([str(blocker)], stdout=subprocess.PIPE, text=True)
    assert process.stdout is not None
    assert process.stdout.readline().strip() == "ready"
    try:
        stop_process(process)
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()
    assert process.poll() is not None


def test_event_bridge_replays_live_events_and_closes() -> None:
    with pytest.raises(ValueError, match="max_buffer"):
        EventBridge(max_buffer=0)

    bridge = EventBridge(max_buffer=2)
    bridge.push(DashboardEvent("1", "old", "red", "a", 0.0, {}))
    bridge.push(DashboardEvent("2", "backlog", "red", "b", 1.0, {}))
    bridge.push(DashboardEvent("3", "latest", "blue", "c", 2.0, {}))

    assert [event.id for event in bridge.snapshot_buffer()] == ["2", "3"]

    async def run() -> list[str]:
        received: list[str] = []
        stream = bridge.subscribe()
        received.append((await stream.__anext__()).id)
        received.append((await stream.__anext__()).id)
        bridge.push(DashboardEvent("4", "live", "green", "d", 3.0, {}))
        received.append((await stream.__anext__()).id)
        bridge.close()
        async for event in stream:
            received.append(event.id)
        return received

    assert asyncio.run(run()) == ["2", "3", "4"]

    sync_stream = bridge.subscribe_sync()
    assert [next(sync_stream).id, next(sync_stream).id] == ["3", "4"]
    bridge.close()
    with pytest.raises(StopIteration):
        next(sync_stream)


def test_dashboard_reset_can_swap_snapshot(tmp_path: Path) -> None:
    llm = builder_llm(tmp_path)
    first = OR.build(MANIFEST, llm=llm)
    second = OR.evolve(first, {"edit": "harder"}, llm=llm)
    view = DashboardView(first)

    reset = view.reset(second)
    topology = cast(dict[str, object], view.topology())
    world = cast(dict[str, object], topology["world"])

    assert reset["snapshot_id"] == second.id
    assert world["difficulty"] == "hard"
    assert json.loads(json.dumps(reset["topology"]))["snapshot_id"] == second.id
