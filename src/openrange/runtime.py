"""Episode runtime for admitted OpenRange snapshots."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import threading
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import TYPE_CHECKING, cast

from openrange.core import (
    ActorTurn,
    Entrypoint,
    Manifest,
    OpenRangeError,
    Snapshot,
    Task,
)
from openrange.core import (
    build as core_build,
)
from openrange.dashboard import (
    DashboardArtifactLog,
    DashboardHTTPServer,
    DashboardView,
    read_dashboard_events,
)

if TYPE_CHECKING:
    from openrange.llm import LLMResult


class EpisodeRuntimeError(OpenRangeError):
    """Raised when an episode cannot be reset or finished."""


@dataclass(frozen=True, slots=True)
class RunConfig:
    root: Path
    dashboard: bool = True
    reset_dashboard: bool = True
    dashboard_host: str = "127.0.0.1"
    dashboard_port: int | None = None


class OpenRangeRun:
    def __init__(self, config: str | Path | RunConfig) -> None:
        self.config = (
            config if isinstance(config, RunConfig) else RunConfig(Path(config))
        )
        self.root = self.config.root
        self.root.mkdir(parents=True, exist_ok=True)
        self._dashboard = (
            None
            if not self.config.dashboard
            else DashboardArtifactLog(
                self.root / "dashboard.events.jsonl",
                self.root / "dashboard.json",
                reset=self.config.reset_dashboard,
            )
        )

    def build(
        self,
        manifest: str | Path | Mapping[str, object] | Manifest,
        *,
        prompt: str = "",
        llm: object | None = None,
        max_repairs: int = 3,
    ) -> Snapshot:
        snapshot = core_build(
            manifest,
            prompt=prompt,
            llm=llm,
            max_repairs=max_repairs,
            event_sink=(
                None if self._dashboard is None else self._dashboard.record_builder_step
            ),
        )
        if self._dashboard is not None:
            self._dashboard.record_builder_step(
                "builder_finished",
                {"snapshot_id": snapshot.id, "task_count": len(snapshot.tasks)},
            )
        return snapshot

    def episode_environment(self, snapshot: Snapshot, task: Task) -> EpisodeEnvironment:
        return EpisodeEnvironment(snapshot, task, self.config)


@dataclass(frozen=True, slots=True)
class Episode:
    snapshot: Snapshot
    task: Task
    run_root: Path
    env_root: Path
    agent_root: Path
    dashboard: DashboardView
    base_url: str
    dashboard_url: str | None = None


@dataclass(frozen=True, slots=True)
class EpisodeReport:
    snapshot_id: str
    task_id: str
    agent_output: str
    final_state: Mapping[str, object]

    def as_dict(self) -> dict[str, object]:
        return {
            "snapshot_id": self.snapshot_id,
            "task_id": self.task_id,
            "agent_output": self.agent_output,
            "final_state": dict(self.final_state),
        }


@dataclass(frozen=True, slots=True)
class DashboardServerHandle:
    server: DashboardHTTPServer
    thread: threading.Thread

    @property
    def url(self) -> str:
        host = str(self.server.server_address[0])
        return f"http://{host}:{self.server.server_address[1]}"

    def close(self) -> None:
        self.server.view.bridge.close()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)

    def __enter__(self) -> DashboardServerHandle:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()


class EpisodeEnvironment:
    def __init__(
        self,
        snapshot: Snapshot,
        task: Task,
        run_root: str | Path | RunConfig,
    ) -> None:
        self.snapshot = snapshot
        self.task = task
        self.config = run_config_from(run_root, reset_dashboard=False)
        self.run_root = self.config.root
        self.run_root.mkdir(parents=True, exist_ok=True)
        self.dashboard = self._dashboard_view(snapshot)
        self._episode: Episode | None = None
        self._process: subprocess.Popen[str] | None = None
        self._request_log: Path | None = None
        self._request_count = 0
        self._request_lock = threading.Lock()
        self._request_stop: threading.Event | None = None
        self._request_thread: threading.Thread | None = None
        self._dashboard_server: DashboardServerHandle | None = None

    def reset(self) -> Episode:
        self._close_episode_process()
        episode_root = self.run_root / self.task.id
        env_root = episode_root / "env"
        agent_root = episode_root / "agent"
        if episode_root.exists():
            shutil.rmtree(episode_root)
        env_root.mkdir(parents=True)
        agent_root.mkdir()
        if self.config.dashboard:
            preserve_dashboard_events(self.run_root / "dashboard.events.jsonl")
        self.dashboard = self._dashboard_view(self.snapshot)
        dashboard_url = self._ensure_dashboard_server()

        app_root = env_root / "pack"
        materialize_artifacts(self.snapshot.artifacts, app_root)
        entrypoint = self.task.entrypoints[0]
        request_log = env_root / str(entrypoint.metadata["request_log"])
        process = start_runtime_process(
            app_root / runtime_artifact(entrypoint),
            entrypoint,
            self.snapshot.world,
            request_log,
        )
        self._process = process
        self._request_log = request_log
        base_url = read_base_url(process)
        write_task_file(agent_root, self.task, entrypoint, base_url)

        episode = Episode(
            self.snapshot,
            self.task,
            episode_root,
            env_root,
            agent_root,
            self.dashboard,
            base_url,
            dashboard_url,
        )
        self._episode = episode
        self.record_system(
            {"reset": True},
            state={"env_root": str(env_root), "agent_root": str(agent_root)},
        )
        self.record_system(
            {"start": "http_server"},
            observation={"base_url": base_url},
        )
        self._start_request_watcher()
        return episode

    def finish(self, agent_result: LLMResult) -> EpisodeReport:
        if self._episode is None or self._request_log is None:
            raise EpisodeRuntimeError("episode has not been reset")
        stop_process(self._process)
        self._process = None
        self._stop_request_watcher()
        requests = self.sync_request_log()
        entrypoint = self.task.entrypoints[0]
        validate_public_interface_interaction(entrypoint, requests)
        final_state = final_state_from_episode(
            self._episode.agent_root,
            entrypoint,
            self.snapshot.world,
            requests,
        )
        self.record_system({"finish": True}, state=final_state)
        return EpisodeReport(
            self.snapshot.id,
            self.task.id,
            agent_result.text,
            final_state,
        )

    def close(self) -> None:
        self._close_episode_process()
        self._close_auto_dashboard()

    def _close_episode_process(self) -> None:
        stop_process(self._process)
        self._process = None
        self._stop_request_watcher()

    def serve_dashboard(
        self,
        host: str = "127.0.0.1",
        port: int = 0,
    ) -> DashboardServerHandle:
        server = DashboardHTTPServer((host, port), self.dashboard)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        return DashboardServerHandle(server, thread)

    def _ensure_dashboard_server(self) -> str | None:
        if not self.config.dashboard or self.config.dashboard_port is None:
            return None
        if self._dashboard_server is None:
            self._dashboard_server = self.serve_dashboard(
                self.config.dashboard_host,
                self.config.dashboard_port,
            )
        else:
            self._dashboard_server.server.view.bridge.close()
            self._dashboard_server.server.view = self.dashboard
        return self._dashboard_server.url

    def _close_auto_dashboard(self) -> None:
        if self._dashboard_server is None:
            return
        self._dashboard_server.close()
        self._dashboard_server = None

    def sync_request_log(self) -> tuple[Mapping[str, object], ...]:
        if self._request_log is None:
            return ()
        with self._request_lock:
            requests = read_requests(self._request_log)
            entrypoint = self.task.entrypoints[0]
            for row in requests[self._request_count :]:
                self.record_agent_request(entrypoint, row)
            self._request_count = len(requests)
        return requests

    def record_agent_request(
        self,
        entrypoint: Entrypoint,
        row: Mapping[str, object],
    ) -> None:
        self.dashboard.record_turn(
            ActorTurn(
                self.task.id,
                "agent",
                "agent",
                entrypoint.target,
                {
                    "method": str(row.get("method", "")),
                    "path": str(row.get("path", "")),
                },
                observation={"status": row.get("status", 0)},
                metadata={"source": "http_access_log"},
            ),
        )

    def record_system(
        self,
        action: Mapping[str, object],
        *,
        observation: Mapping[str, object] | None = None,
        state: Mapping[str, object] | None = None,
    ) -> None:
        self.dashboard.record_turn(
            ActorTurn(
                self.task.id,
                "runtime",
                "system",
                "environment",
                action,
                observation=observation,
                state=state,
            ),
        )

    def _dashboard_view(self, snapshot: Snapshot) -> DashboardView:
        if not self.config.dashboard:
            return DashboardView(snapshot)
        return DashboardView(
            snapshot,
            event_log_path=self.run_root / "dashboard.events.jsonl",
            state_path=self.run_root / "dashboard.json",
            reset_artifacts=False,
        )

    def _start_request_watcher(self) -> None:
        self._request_count = 0
        self._request_stop = threading.Event()
        self._request_thread = threading.Thread(
            target=self._watch_request_log,
            args=(self._request_stop,),
            daemon=True,
        )
        self._request_thread.start()

    def _watch_request_log(self, request_stop: threading.Event) -> None:
        while not request_stop.wait(0.05):
            self.sync_request_log()

    def _stop_request_watcher(self) -> None:
        if self._request_thread is None:
            return
        cast(threading.Event, self._request_stop).set()
        self._request_thread.join(timeout=5)
        self._request_thread = None
        self._request_stop = None


def run_config_from(
    value: str | Path | RunConfig,
    *,
    reset_dashboard: bool,
) -> RunConfig:
    if isinstance(value, RunConfig):
        return RunConfig(
            value.root,
            value.dashboard,
            reset_dashboard,
            value.dashboard_host,
            value.dashboard_port,
        )
    return RunConfig(Path(value), reset_dashboard=reset_dashboard)


def materialize_artifacts(artifacts: Mapping[str, str], root: Path) -> None:
    root.mkdir(parents=True, exist_ok=True)
    for relative_path, content in artifacts.items():
        path = root / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")


def preserve_dashboard_events(path: Path) -> None:
    if not path.exists():
        return
    builder_events = [
        event for event in read_dashboard_events(path) if event.type == "builder_step"
    ]
    lines = [
        json.dumps(event.as_dict(), sort_keys=True) + "\n"
        for event in builder_events
    ]
    path.write_text(
        "".join(lines),
        encoding="utf-8",
    )


def start_runtime_process(
    app_path: Path,
    entrypoint: Entrypoint,
    world: Mapping[str, object],
    request_log: Path,
) -> subprocess.Popen[str]:
    if not app_path.exists():
        raise EpisodeRuntimeError(f"runtime artifact is missing: {app_path.name}")
    return subprocess.Popen(
        [
            sys.executable,
            str(app_path),
            *runtime_argv(entrypoint.metadata, world, request_log),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )


def runtime_artifact(entrypoint: Entrypoint) -> str:
    return str(entrypoint.metadata.get("artifact", "app.py"))


def runtime_argv(
    metadata: Mapping[str, object],
    world: Mapping[str, object],
    request_log: Path,
) -> list[str]:
    argv: list[str] = []
    configured = metadata.get("argv", ())
    if not isinstance(configured, list | tuple):
        raise EpisodeRuntimeError("runtime argv must be a list")
    for item in configured:
        if isinstance(item, str):
            argv.append(item)
        elif isinstance(item, Mapping) and "world" in item:
            argv.append(str(world[str(item["world"])]))
        elif isinstance(item, Mapping) and item.get("run") == "request_log":
            argv.append(str(request_log))
        else:
            raise EpisodeRuntimeError("runtime argv item is invalid")
    return argv


def read_base_url(process: subprocess.Popen[str]) -> str:
    if process.stdout is None:
        raise EpisodeRuntimeError("runtime stdout is not available")
    line = process.stdout.readline()
    if not line:
        stop_process(process)
        raise EpisodeRuntimeError("runtime did not report a listening address")
    data = json.loads(line)
    if not isinstance(data, dict):
        raise EpisodeRuntimeError("runtime reported invalid listening address")
    return f"http://{data['host']}:{data['port']}"


def write_task_file(
    agent_root: Path,
    task: Task,
    entrypoint: Entrypoint,
    base_url: str,
) -> None:
    task_file = str(entrypoint.metadata.get("task_file", "OPENRANGE_TASK.json"))
    result_file = str(entrypoint.metadata.get("result_file", "result.json"))
    (agent_root / task_file).write_text(
        json.dumps(
            {
                "task_id": task.id,
                "base_url": base_url,
                "result_schema": entrypoint.metadata.get("result_schema", {}),
                "result_file": result_file,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )


def read_result(agent_root: Path, result_file: str) -> Mapping[str, object]:
    try:
        data = json.loads((agent_root / result_file).read_text(encoding="utf-8"))
    except OSError, json.JSONDecodeError:
        return MappingProxyType({})
    if not isinstance(data, Mapping):
        return MappingProxyType({})
    return MappingProxyType(dict(data))


def read_requests(path: Path) -> tuple[Mapping[str, object], ...]:
    if not path.exists():
        return ()
    rows: list[Mapping[str, object]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(data, Mapping):
            rows.append(MappingProxyType(dict(data)))
    return tuple(rows)


def final_state_from_episode(
    agent_root: Path,
    entrypoint: Entrypoint,
    world: Mapping[str, object],
    requests: tuple[Mapping[str, object], ...],
) -> Mapping[str, object]:
    final_state = cast_final_state(entrypoint.metadata["final_state"])
    collectors: Mapping[str, Callable[[Mapping[str, object]], object]] = {
        "json_file": lambda spec: dict(read_result(agent_root, str(spec["path"]))),
        "world": lambda _: dict(world),
        "request_log": lambda _: [dict(row) for row in requests],
    }
    return MappingProxyType(
        {
            str(name): collectors[str(spec["kind"])](spec)
            for name, spec in final_state.items()
        },
    )


def validate_public_interface_interaction(
    entrypoint: Entrypoint,
    requests: tuple[Mapping[str, object], ...],
) -> None:
    final_state = cast_final_state(entrypoint.metadata["final_state"])
    if not requests and any(
        spec.get("kind") == "request_log" for spec in final_state.values()
    ):
        raise EpisodeRuntimeError(
            "episode recorded no agent interaction with the public interface",
        )


def cast_final_state(value: object) -> Mapping[str, Mapping[str, object]]:
    return cast(Mapping[str, Mapping[str, object]], value)


def stop_process(process: subprocess.Popen[str] | None) -> None:
    if process is None or process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()
