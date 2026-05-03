"""Episode runtime: helper functions used by ``core.episode.EpisodeService``.

This module owns the cyber-pack-shaped helpers that materialize artifacts,
spawn the HTTP server subprocess, parse its stdout for the bind address,
write the agent task file, and collect final state. ``EpisodeService``
calls into these from ``core.episode``.

OpenRangeRun is the convenience wrapper that ties together build +
episode + dashboard for the example scripts and CLI.
"""

from __future__ import annotations

import json
import subprocess
import sys
import threading
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import cast

from openrange.core import (
    Entrypoint,
    Manifest,
    OpenRangeError,
    Snapshot,
    Task,
)
from openrange.core import (
    build as core_build,
)
from openrange.core.episode import EpisodeService
from openrange.dashboard import (
    DashboardArtifactLog,
    DashboardHTTPServer,
    DashboardView,
)
from openrange.llm import LLMBackend


class EpisodeRuntimeError(OpenRangeError):
    """Raised when a runtime helper cannot proceed."""


@dataclass(frozen=True, slots=True)
class RunConfig:
    root: Path
    dashboard: bool = True
    reset_dashboard: bool = True
    dashboard_host: str = "127.0.0.1"
    dashboard_port: int | None = None


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


class OpenRangeRun:
    """Convenience wrapper: build + episode + optional dashboard."""

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
        self._dashboard_view: DashboardView | None = None

    def build(
        self,
        manifest: str | Path | Mapping[str, object] | Manifest,
        *,
        prompt: str = "",
        llm: LLMBackend | None = None,
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

    def _ensure_dashboard_view(self, snapshot: Snapshot) -> DashboardView | None:
        if not self.config.dashboard:
            return None
        if self._dashboard_view is None:
            self._dashboard_view = DashboardView(
                snapshot,
                event_log_path=self.root / "dashboard.events.jsonl",
                state_path=self.root / "dashboard.json",
                reset_artifacts=False,
            )
        return self._dashboard_view

    def episode_service(self, snapshot: Snapshot) -> EpisodeService:
        view = self._ensure_dashboard_view(snapshot)
        return EpisodeService(self.root, dashboard=view)

    def serve_dashboard(
        self,
        snapshot: Snapshot,
        host: str = "127.0.0.1",
        port: int = 0,
    ) -> DashboardServerHandle:
        view = self._ensure_dashboard_view(snapshot) or DashboardView(snapshot)
        server = DashboardHTTPServer((host, port), view)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        return DashboardServerHandle(server, thread)


def materialize_artifacts(artifacts: Mapping[str, str], root: Path) -> None:
    root.mkdir(parents=True, exist_ok=True)
    for relative_path, content in artifacts.items():
        path = root / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")


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
