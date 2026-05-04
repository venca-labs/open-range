"""Runtime helper primitives used by EpisodeService and built-in backings.

These functions own the mechanics of materializing artifacts, spawning
runtime processes, parsing their bind addresses, writing the agent task
file, polling request logs, and assembling the post-episode final state.

They live in core (not openrange.runtime) so the per-kind ``RuntimeBacking``
implementations can call into them without inverting the layering. The
shapes some of them speak (OPENRANGE_TASK.json, requests.jsonl, result.json,
``{"host", "port"}`` stdout) are *cyber-pack-shaped conventions* — they
work today because the cyber pack's HTTP entrypoint follows them. A
follow-up will move those convention-bound helpers into a backing-level
finalization hook so non-HTTP packs can pick their own conventions.
"""

from __future__ import annotations

import json
import subprocess
import sys
from collections.abc import Callable, Mapping
from pathlib import Path
from types import MappingProxyType
from typing import TYPE_CHECKING, cast

from openrange.core.errors import OpenRangeError

if TYPE_CHECKING:
    from openrange.core.pack import Entrypoint, Task


class EpisodeRuntimeError(OpenRangeError):
    """Raised when a runtime helper cannot proceed."""


def materialize_artifacts(artifacts: Mapping[str, str], root: Path) -> None:
    """Write a path → content mapping to disk under ``root``."""
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
    """Spawn a Python subprocess for the entrypoint's runtime artifact."""
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
    """Resolve the entrypoint's argv template against the world + log path."""
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
    """Read the runtime process's first stdout line and parse ``{host, port}``."""
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
    """Write the cyber convention OPENRANGE_TASK.json into the agent's workspace."""
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
    """Assemble the final state dict the verifier consumes.

    Reads the agent's result file, snapshots the world dict, and surfaces
    the request log. Cyber-pack convention; future packs may shape their
    final state differently.
    """
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
