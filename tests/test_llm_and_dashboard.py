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
from pathlib import Path
from typing import Protocol, cast
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import pytest

import openrange as OR
from openrange.core.runtime_helpers import (
    read_base_url,
    read_requests,
    read_result,
    start_runtime_process,
    stop_process,
)
from openrange.dashboard import (
    DashboardArtifactLog,
    DashboardEvent,
    DashboardHTTPServer,
    DashboardView,
    EventBridge,
    dashboard_event_from_mapping,
)
from openrange.dashboard import (
    read_dashboard_events as read_dashboard_artifact_events,
)
from openrange.llm import LLMBackendError, parse_json_object, run_codex

MANIFEST = {
    "world": {"goal": "find the admin flag", "title": "Ops Portal"},
    "pack": {"id": "cyber.webapp.offense.v1"},
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


def test_dashboard_http_server_serves_static_assets_and_routes(
    tmp_path: Path,
) -> None:
    snapshot = OR.build(MANIFEST)
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
        with urlopen(base_url + "/static/dashboard.css", timeout=5) as response:
            css = response.read().decode()
        with urlopen(base_url + "/static/dashboard.js", timeout=5) as response:
            dashboard_js = response.read().decode()

        briefing = read_http_json(base_url + "/api/briefing")
        topology = read_http_json(base_url + "/api/topology?ignored=1")
        lineage = read_http_json(base_url + "/api/lineage")
        state = read_http_json(base_url + "/api/state")
        narration = read_http_json(base_url + "/api/narrate")
        play = read_http_json(base_url + "/api/episode/play", method="POST")

        assert "OpenRange Dashboard" in html
        assert 'id="sim-canvas"' in html
        assert "/static/dashboard.css" in html
        assert "/static/dashboard.js" in html
        assert "Live Event Feed" in html
        assert "Episode Narrator" in html
        assert "sim-actor-panel" in html
        assert "sim-uptime-gauge" in html
        assert "Tasks" in html
        assert "Admission" in html
        assert "Lineage" in html
        assert "Artifacts" in html
        assert "THREE.WebGLRenderer" in dashboard_js
        assert ".sim-actor-panel" in css
        assert briefing["snapshot_id"] == snapshot.id
        assert topology["snapshot_id"] == snapshot.id
        assert lineage["admission"] == snapshot.admission.as_dict()
        assert cast(list[dict[str, object]], state["events"])[0]["data"] == {
            "action": "browse",
        }
        assert narration == {"narration": "red agent_step webapp"}
        assert play == {"status": "playing"}

        for request in (
            Request(base_url + "/missing"),
            Request(base_url + "/static/missing.css"),
            Request(base_url + "/static/../events.py"),
            Request(base_url + "/api/episode/missing", method="POST"),
        ):
            with pytest.raises(HTTPError) as error:
                urlopen(request, timeout=5).read()
            assert error.value.code == 404
            assert json.loads(error.value.read().decode()) == {"error": "not found"}


def test_dashboard_http_server_streams_events_and_narration(
    tmp_path: Path,
) -> None:
    snapshot = OR.build(MANIFEST)
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
        {"pack_id": "cyber.webapp.offense.v1"},
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
        {"pack_id": "cyber.webapp.offense.v1", "step": "build_started"},
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


def test_dashboard_records_actor_turns_from_env_actors(tmp_path: Path) -> None:
    snapshot = OR.build(MANIFEST)
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


def test_openrange_run_can_disable_dashboard_artifacts(tmp_path: Path) -> None:
    run_root = tmp_path / "run"
    run = OR.OpenRangeRun(OR.RunConfig(run_root, dashboard=False))
    snapshot = run.build(MANIFEST)
    task = snapshot.get_tasks()[0]
    svc = run.episode_service(snapshot)

    try:
        handle = svc.start_episode(snapshot, task.id)
        agent_root = svc.agent_root(handle)
    finally:
        svc.close()

    assert agent_root.parent.parent == run_root
    assert not (run_root / "dashboard.events.jsonl").exists()
    assert not (run_root / "dashboard.json").exists()


def test_run_config_starts_live_dashboard_internally(tmp_path: Path) -> None:
    run_root = tmp_path / "run"
    run = OR.OpenRangeRun(OR.RunConfig(run_root, dashboard_port=0))
    snapshot = run.build(MANIFEST)
    task = snapshot.get_tasks()[0]
    svc = run.episode_service(snapshot)
    dashboard_handle = run.serve_dashboard(snapshot, port=0)

    try:
        svc.start_episode(snapshot, task.id)
        svc.start_episode(snapshot, task.id)
        state = read_http_json(dashboard_handle.url + "/api/state")
    finally:
        svc.close()
        dashboard_handle.close()

    assert state["snapshot_id"] == snapshot.id
    # Two start_episode calls × 2 system turns each = 4 turns
    assert state["turn_count"] >= 2


def test_episode_each_start_gives_fresh_roots(tmp_path: Path) -> None:
    from openrange.dashboard import DashboardView

    snapshot = OR.build(MANIFEST)
    task = snapshot.get_tasks()[0]
    run_root = tmp_path / "episode"
    run_root.mkdir()
    dashboard = DashboardView(
        snapshot,
        event_log_path=run_root / "dashboard.events.jsonl",
        state_path=run_root / "dashboard.json",
        reset_artifacts=True,
    )
    svc = OR.EpisodeService(run_root, dashboard=dashboard)
    first = svc.start_episode(snapshot, task.id)
    first_root = svc.agent_root(first)
    marker = first_root / "old.txt"
    marker.write_text("old", encoding="utf-8")
    try:
        second = svc.start_episode(snapshot, task.id)
        second_root = svc.agent_root(second)
    finally:
        svc.close()

    assert second_root.exists()
    assert first_root != second_root
    assert marker.exists()  # first episode's root still has its marker


def test_runtime_error_and_reader_paths(tmp_path: Path) -> None:
    snapshot = OR.build(MANIFEST)
    task = snapshot.get_tasks()[0]
    svc = OR.EpisodeService(tmp_path / "episode")

    bogus_handle = OR.EpisodeHandle("missing", snapshot.id, task.id)
    with pytest.raises(OR.EpisodeError, match="unknown episode"):
        svc.stop_episode(bogus_handle)
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


