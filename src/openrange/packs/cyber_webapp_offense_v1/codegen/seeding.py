"""Project a v1 world graph into the seed dicts ``app.py`` loads at start.

The generated runtime expects four dicts at module top:
  - ``_FLAG``     — the flag string
  - ``_ACCOUNTS`` — username -> {role, password}
  - ``_SECRETS``  — kind -> value (always includes ``flag`` and ``value``)
  - ``_RECORDS``  — record-key -> {column: value}

This module owns the projection: walk the graph once, populate the
dicts, raise if no flag is present (the orchestrator should reject
flagless graphs upstream).
"""

from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType

from openrange.core.errors import PackError
from openrange.core.graph import Node, WorldGraph


def project_seed(graph: WorldGraph) -> Mapping[str, object]:
    """Walk ``graph`` and project the runtime seed dicts.

    Returns a mapping with keys: ``flag`` (string), ``accounts``,
    ``secrets``, ``records``. Raises ``PackError`` if no flag-kind
    secret exists.
    """
    flag = ""
    accounts: dict[str, dict[str, object]] = {}
    secrets: dict[str, str] = {}
    records: dict[str, dict[str, object]] = {}

    creds_by_account: dict[str, str] = {}
    for edge in graph.edges:
        if edge.relation == "has_credential":
            creds_by_account[edge.source] = edge.target
    cred_by_id: dict[str, Node] = {
        n.id: n for n in graph.nodes if n.type == "credential"
    }

    for node in graph.nodes:
        if node.type == "secret" and node.attrs.get("kind") == "flag":
            flag = str(node.attrs.get("value_ref", ""))
            secrets["flag"] = flag
            secrets["value"] = flag
        elif node.type == "secret":
            secrets[str(node.attrs.get("kind", node.id))] = str(
                node.attrs.get("value_ref", ""),
            )
        elif node.type == "account":
            cred_id = creds_by_account.get(node.id)
            password = ""
            if cred_id is not None:
                cred = cred_by_id.get(cred_id)
                if cred is not None:
                    password = str(cred.attrs.get("value_ref", ""))
            accounts[str(node.attrs.get("username", node.id))] = {
                "role": str(node.attrs.get("role", "user")),
                "password": password,
            }
        elif node.type == "record":
            fields = node.attrs.get("fields", {})
            if isinstance(fields, Mapping):
                records[str(node.attrs.get("key", node.id))] = {
                    str(k): str(v) for k, v in fields.items()
                }
            else:
                records[str(node.attrs.get("key", node.id))] = {}

    if not flag:
        raise PackError("graph has no flag-kind secret; codegen needs one")
    return MappingProxyType(
        {
            "flag": flag,
            "accounts": accounts,
            "secrets": secrets,
            "records": records,
        },
    )


__all__ = ["project_seed"]
