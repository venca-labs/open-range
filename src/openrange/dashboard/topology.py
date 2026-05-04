"""Snapshot topology normalization and world redaction."""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from typing import cast

from openrange.core import Snapshot
from openrange.core.snapshot import json_safe


def empty_runtime_topology() -> dict[str, object]:
    return {
        "services": [],
        "edges": [],
        "zones": [],
        "users": [],
        "green_personas": [],
    }


def normalized_runtime_topology(snapshot: Snapshot) -> dict[str, object]:
    raw = embedded_topology(snapshot)
    services = normalized_rows(raw.get("services"))
    known_services = {str(service.get("id", "")) for service in services}

    world_service = snapshot.world.get("service")
    if isinstance(world_service, str) and world_service not in known_services:
        services.append(
            {
                "id": world_service,
                "kind": "service",
                "zone": "episode",
                "ports": [],
            },
        )
        known_services.add(world_service)

    for task in snapshot.tasks:
        for entrypoint in task.entrypoints:
            if entrypoint.target in known_services:
                continue
            services.append(
                {
                    "id": entrypoint.target,
                    "kind": entrypoint.kind,
                    "zone": "episode",
                    "ports": [],
                },
            )
            known_services.add(entrypoint.target)

    zones = normalized_strings(raw.get("zones"))
    service_zones = sorted(
        {
            str(service["zone"])
            for service in services
            if isinstance(service.get("zone"), str)
        },
    )
    if not zones:
        zones = service_zones
    else:
        zones.extend(zone for zone in service_zones if zone not in zones)

    return {
        "services": services,
        "edges": normalized_rows(raw.get("edges")),
        "zones": zones,
        "users": normalized_rows(raw.get("users")),
        "green_personas": normalized_rows(raw.get("green_personas")),
    }


def embedded_topology(snapshot: Snapshot) -> dict[str, object]:
    raw: dict[str, object] = {}
    for path, content in snapshot.artifacts.items():
        if not path.endswith("topology.json"):
            continue
        try:
            loaded = json.loads(content)
        except json.JSONDecodeError:
            continue
        if isinstance(loaded, Mapping):
            raw.update(loaded)
            break

    world_topology = snapshot.world.get("topology")
    if isinstance(world_topology, Mapping):
        raw.update(world_topology)
    for key in ("services", "edges", "zones", "users", "green_personas"):
        value = snapshot.world.get(key)
        if value is not None:
            raw[key] = value
    return raw


def normalized_rows(value: object) -> list[dict[str, object]]:
    if isinstance(value, Mapping):
        iterable = tuple(value.items())
    elif isinstance(value, Sequence) and not isinstance(value, str | bytes):
        iterable = tuple((None, item) for item in value)
    else:
        return []

    rows: list[dict[str, object]] = []
    for key, item in iterable:
        if isinstance(item, Mapping):
            row = dict(cast(Mapping[str, object], json_safe(item)))
            if "id" not in row:
                row["id"] = "" if key is None else str(key)
            rows.append(row)
        elif isinstance(item, str):
            rows.append({"id": item})
    return rows


def normalized_strings(value: object) -> list[str]:
    if not isinstance(value, Sequence) or isinstance(value, str | bytes):
        return []
    return [item for item in value if isinstance(item, str)]


def public_world(world: Mapping[str, object]) -> dict[str, object]:
    redacted: dict[str, object] = {}
    for key, value in world.items():
        if sensitive_world_key(key):
            redacted[key] = "[redacted]"
        else:
            redacted[key] = value
    return redacted


def sensitive_world_key(key: str) -> bool:
    normalized = key.lower()
    return normalized == "flag" or any(
        marker in normalized for marker in ("secret", "password", "token")
    )


def stored_entrypoints(tasks: Sequence[object]) -> list[dict[str, object]]:
    entrypoints: list[dict[str, object]] = []
    for task in tasks:
        if not isinstance(task, Mapping):
            continue
        task_id = task.get("id")
        for entrypoint in stored_task_entrypoints(task):
            entrypoints.append({"task_id": str(task_id), **entrypoint})
    return entrypoints


def stored_missions(tasks: Sequence[object]) -> list[dict[str, object]]:
    missions: list[dict[str, object]] = []
    for task in tasks:
        if not isinstance(task, Mapping):
            continue
        missions.append(
            {
                "task_id": str(task.get("id", "")),
                "instruction": str(task.get("instruction", "")),
            },
        )
    return missions


def stored_task_entrypoints(task: Mapping[str, object]) -> list[dict[str, object]]:
    rows = task.get("entrypoints")
    if not isinstance(rows, list):
        return []
    entrypoints: list[dict[str, object]] = []
    for row in rows:
        if not isinstance(row, Mapping):
            continue
        entrypoints.append(
            {
                "kind": str(row.get("kind", "")),
                "target": str(row.get("target", "")),
            },
        )
    return entrypoints
