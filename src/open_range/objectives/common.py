"""Shared objective helper functions."""

from __future__ import annotations

import shlex
from collections.abc import Mapping


def db_query_command(snapshot: object, query: str) -> str:
    if snapshot_mtls_enabled(snapshot):
        return mtls_mysql_query_command(query)
    return "mysql -uapp -papp-pass app -Nse " + shlex.quote(query)


def snapshot_mtls_enabled(snapshot: object) -> bool:
    world = getattr(snapshot, "world", None)
    security_runtime = getattr(world, "security_runtime", None)
    mtls = getattr(security_runtime, "mtls", None)
    if isinstance(mtls, Mapping):
        return bool(mtls.get("enabled"))
    return False


def mtls_mysql_query_command(query: str) -> str:
    return shlex.join(
        [
            "mysql",
            "--protocol=TCP",
            "-h",
            "127.0.0.1",
            "--ssl-mode=VERIFY_CA",
            "--ssl-ca=/etc/mtls/ca.pem",
            "--ssl-cert=/etc/mtls/cert.pem",
            "--ssl-key=/etc/mtls/key.pem",
            "-uapp",
            "-papp-pass",
            "app",
            "-Nse",
            query,
        ]
    )


def snapshot_mapping(snapshot: object, attr: str) -> dict[str, object]:
    value = getattr(snapshot, attr, {})
    if isinstance(value, dict):
        return value
    return {}


def event_type(event: object) -> str:
    if isinstance(event, Mapping):
        return str(event.get("event_type", ""))
    return str(getattr(event, "event_type", ""))


def event_target(event: object) -> str:
    if isinstance(event, Mapping):
        return str(event.get("target_entity", ""))
    return str(getattr(event, "target_entity", ""))


def event_linked_predicates(event: object) -> tuple[str, ...]:
    if isinstance(event, Mapping):
        value = event.get("linked_objective_predicates", ())
    else:
        value = getattr(event, "linked_objective_predicates", ())
    if isinstance(value, tuple):
        return tuple(str(item) for item in value)
    if isinstance(value, list):
        return tuple(str(item) for item in value)
    return ()
