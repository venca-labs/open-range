"""Training-facing trace export helpers."""

from __future__ import annotations

import json
from urllib.parse import urlencode

from open_range.contracts.runtime import (
    Action,
    RuntimeEvent,
    control_directive,
    finding_event_type,
)
from open_range.contracts.snapshot import RuntimeSnapshot
from open_range.training.data import TraceWeakness

_HIDDEN_ACTION_PAYLOAD_KEYS = frozenset({"service_command"})


def public_trace_action(action: Action) -> Action:
    payload = {
        key: value
        for key, value in action.payload.items()
        if key not in _HIDDEN_ACTION_PAYLOAD_KEYS
    }
    return action.model_copy(update={"payload": payload})


def render_action_text(action: Action) -> str:
    target = str(action.payload.get("target", ""))
    if action.kind == "api":
        path = str(action.payload.get("path", "/") or "/")
        if not path.startswith("/"):
            path = f"/{path}"
        method = str(action.payload.get("method", "GET") or "GET").upper()
        headers = action.payload.get("headers")
        user_agent = str(action.payload.get("user_agent", "")).strip()
        body = str(action.payload.get("body", "")).strip()
        query = action.payload.get("query")
        query_text = ""
        if isinstance(query, dict) and query:
            query_text = "?" + urlencode(
                [(str(key), str(value)) for key, value in query.items()], doseq=True
            )
        parts = ["curl", "-s"]
        if method != "GET":
            parts.extend(["-X", method])
        if user_agent:
            parts.extend(["-A", json.dumps(user_agent)])
        if isinstance(headers, dict):
            for key, value in headers.items():
                parts.extend(["-H", json.dumps(f"{key}: {value}")])
        if body:
            parts.extend(["--data-raw", json.dumps(body)])
        parts.append(f"http://{target}{path}{query_text}")
        return " ".join(parts)
    if action.kind == "shell":
        command = str(action.payload.get("command", "")).strip()
        if command:
            return command
        path = str(action.payload.get("path", "")).strip()
        return f"cat {path}" if path else f"sh -lc 'echo probe {target}'"
    if action.kind == "mail":
        to = str(action.payload.get("to", target or "user@corp.local"))
        subject = str(action.payload.get("subject", "openrange"))
        return f"send mail to {to} subject={subject}"
    if action.kind == "control":
        directive = control_directive(action, default="contain")
        return f"{directive} {target}".strip()
    if action.kind == "submit_finding":
        event_type = finding_event_type(action, default="InitialAccess")
        return f"submit_finding event={event_type} target={target}".strip()
    if action.kind == "sleep":
        return "sleep 1"
    return json.dumps({"kind": action.kind, "payload": action.payload}, sort_keys=True)


def trace_weaknesses(snapshot: RuntimeSnapshot) -> tuple[TraceWeakness, ...]:
    return tuple(
        TraceWeakness(
            weakness_id=weakness.id,
            family=weakness.family,
            kind=weakness.kind,
            target=weakness.target,
            benchmark_tags=tuple(weakness.benchmark_tags),
            objective_tags=tuple(weakness.objective_tags),
        )
        for weakness in snapshot.world.weaknesses
    )


def trace_benchmark_tags(snapshot: RuntimeSnapshot) -> tuple[str, ...]:
    tags = {
        tag for weakness in snapshot.world.weaknesses for tag in weakness.benchmark_tags
    }
    return tuple(sorted(tags))


def grounded_effects_for_result(
    *,
    stdout: str,
    emitted_events: tuple[RuntimeEvent, ...],
) -> tuple[str, ...]:
    labels = {
        event.event_type
        for event in emitted_events
        if event.event_type
        in {
            "CredentialObtained",
            "UnauthorizedCredentialUse",
            "PrivilegeEscalation",
            "SensitiveAssetRead",
            "PersistenceEstablished",
            "ServiceDegraded",
        }
    }
    labels.update(
        token
        for token in stdout.split()
        if token.startswith("OPENRANGE-EFFECT:")
        or token.startswith("OPENRANGE-FOOTHOLD:")
    )
    return tuple(sorted(labels))


def mitigation_effects_for_result(
    *,
    action: Action,
    stdout: str,
    emitted_events: tuple[RuntimeEvent, ...],
) -> tuple[str, ...]:
    labels = {
        event.event_type
        for event in emitted_events
        if event.event_type
        in {"ContainmentApplied", "PatchApplied", "RecoveryCompleted"}
    }
    if action.kind == "control":
        directive = str(action.payload.get("action", "")).lower()
        target = str(action.payload.get("target", ""))
        if (
            directive in {"contain", "patch", "mitigate", "recover", "restore"}
            and target
        ):
            labels.add(f"{directive}:{target}")
    if "mitigation applied to " in stdout:
        labels.add("mitigation_applied")
    if "patch applied to " in stdout:
        labels.add("patch_applied")
    if "containment applied to " in stdout:
        labels.add("containment_applied")
    return tuple(sorted(labels))
