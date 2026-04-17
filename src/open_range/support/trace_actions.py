"""Shared trace-action normalization helpers."""

from __future__ import annotations

from open_range.contracts.runtime import Action
from open_range.contracts.snapshot import RuntimeSnapshot


def normalize_trace_action(snapshot: RuntimeSnapshot, action: Action) -> Action:
    """Keep exported control semantics honest for non-service-native mitigations."""

    if action.kind != "control":
        return action
    directive = str(action.payload.get("action", "")).lower()
    target = str(action.payload.get("target", ""))
    if directive != "patch":
        return action
    if _supports_service_native_patch(snapshot, target):
        return action
    payload = dict(action.payload)
    payload["action"] = "mitigate"
    return action.model_copy(update={"payload": payload})


def _supports_service_native_patch(snapshot: RuntimeSnapshot, target: str) -> bool:
    return any(
        weakness.target == target
        and (
            weakness.family == "code_web"
            or (
                weakness.remediation_kind == "shell"
                and bool(weakness.remediation_command.strip())
            )
        )
        for weakness in snapshot.world.weaknesses
    )
