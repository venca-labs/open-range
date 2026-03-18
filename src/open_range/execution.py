"""Live pod execution bridge for the runtime."""

from __future__ import annotations

import json
import shlex
from dataclasses import dataclass, field
from typing import Any, Protocol
from urllib.parse import urlencode

from open_range.async_utils import run_async
from open_range.cluster import BootedRelease
from open_range.code_web import code_web_cleanup_commands, code_web_guard_path
from open_range.effect_markers import effect_marker_cleanup_command
from open_range.runtime_events import action_target
from open_range.runtime_types import Action
from open_range.snapshot import RuntimeSnapshot
from open_range.world_ir import ServiceSpec, WeaknessSpec


@dataclass(frozen=True, slots=True)
class ActionExecution:
    """Concrete execution result for one runtime action."""

    stdout: str = ""
    stderr: str = ""
    ok: bool = True
    service_health: dict[str, float] = field(default_factory=dict)
    containment_applied: bool = False
    patch_applied: bool = False
    recovery_applied: bool = False


class ActionBackend(Protocol):
    def bind(self, snapshot: RuntimeSnapshot, release: BootedRelease) -> None: ...
    def clear(self) -> None: ...
    def execute(self, action: Action) -> ActionExecution: ...
    def service_health(self) -> dict[str, float]: ...
    def record_event(self, event: Any) -> None: ...


class PodActionBackend:
    """Execute runtime actions against live actor sandboxes and service pods."""

    def __init__(self) -> None:
        self._snapshot: RuntimeSnapshot | None = None
        self._release: BootedRelease | None = None
        self._service_by_id: dict[str, ServiceSpec] = {}

    def bind(self, snapshot: RuntimeSnapshot, release: BootedRelease) -> None:
        self._snapshot = snapshot
        self._release = release
        self._service_by_id = {
            service.id: service for service in snapshot.world.services
        }

    def clear(self) -> None:
        self._snapshot = None
        self._release = None
        self._service_by_id = {}

    def record_event(self, event: Any) -> None:
        if self._release is None or "svc-siem" not in self._service_by_id:
            return
        payload = json.dumps(
            {
                "id": getattr(event, "id", ""),
                "event_type": getattr(event, "event_type", ""),
                "actor": getattr(event, "actor", ""),
                "time": getattr(event, "time", 0.0),
                "source_entity": getattr(event, "source_entity", ""),
                "target_entity": getattr(event, "target_entity", ""),
                "malicious": getattr(event, "malicious", False),
                "observability_surfaces": list(
                    getattr(event, "observability_surfaces", ())
                ),
                "linked_objective_predicates": list(
                    getattr(event, "linked_objective_predicates", ())
                ),
            },
            sort_keys=True,
        )
        cmd = f"printf '%s\\n' {shlex.quote(payload)} >> /srv/http/siem/all.log"
        run_async(self._release.pods.exec("svc-siem", cmd, timeout=5.0))

    def execute(self, action: Action) -> ActionExecution:
        if self._release is None or self._snapshot is None:
            return ActionExecution()

        if action.kind == "sleep" or action.kind == "submit_finding":
            return ActionExecution(service_health=self.service_health())
        if action.kind == "control":
            return self._execute_control(action)
        if action.kind == "shell":
            service_command = str(action.payload.get("service_command", "")).strip()
            if service_command:
                return self._run_on_target_service(action, service_command)
            return self._run_in_runner(action, self._shell_command(action))
        if action.kind == "mail":
            return self._run_in_runner(action, self._mail_command(action))
        if action.kind == "api":
            return self._run_in_runner(action, self._api_command(action))
        return ActionExecution(
            stdout="",
            stderr=f"unsupported live action kind: {action.kind}",
            ok=False,
            service_health=self.service_health(),
        )

    def service_health(self) -> dict[str, float]:
        if self._release is None:
            return {}
        return {
            service_id: 1.0
            if run_async(self._release.pods.is_healthy(service_id))
            else 0.0
            for service_id in sorted(self._service_by_id)
        }

    def _execute_control(self, action: Action) -> ActionExecution:
        release = self._require_release()
        target = action_target(action)
        directive = str(action.payload.get("action", "contain")).lower()
        if target not in self._service_by_id:
            return ActionExecution(
                stderr=f"unknown control target: {target}",
                ok=False,
                service_health=self.service_health(),
            )
        if directive in {"recover", "restore"}:
            command = self._recovery_command_for(target)
        elif directive in {"patch", "mitigate"}:
            command = self._patch_command_for(target)
        else:
            command = "touch /tmp/openrange-contained"
        result = run_async(release.pods.exec(target, command, timeout=action.timeout_s))
        return ActionExecution(
            stdout=result.stdout.strip(),
            stderr=result.stderr.strip(),
            ok=result.ok,
            service_health=self.service_health(),
            containment_applied=result.ok
            and directive not in {"recover", "restore", "patch", "mitigate"},
            patch_applied=result.ok and directive in {"patch", "mitigate"},
            recovery_applied=result.ok and directive in {"recover", "restore"},
        )

    def _run_in_runner(self, action: Action, command: str) -> ActionExecution:
        release = self._require_release()
        if not command:
            return ActionExecution(
                stderr="no command provided",
                ok=False,
                service_health=self.service_health(),
            )
        target = action_target(action)
        if target and target in self._service_by_id:
            if self._is_contained(target):
                return ActionExecution(
                    stderr=f"target {target} is contained",
                    ok=False,
                    service_health=self.service_health(),
                )
            if self._is_patched(target):
                return ActionExecution(
                    stderr=f"target {target} is patched",
                    ok=False,
                    service_health=self.service_health(),
                )
        runner = self._runner_for(action)
        result = run_async(release.pods.exec(runner, command, timeout=action.timeout_s))
        return ActionExecution(
            stdout=result.stdout.strip(),
            stderr=result.stderr.strip(),
            ok=result.ok,
            service_health=self.service_health(),
        )

    def _run_on_target_service(self, action: Action, command: str) -> ActionExecution:
        release = self._require_release()
        target = action_target(action)
        if not target or target not in self._service_by_id:
            return ActionExecution(
                stderr="missing or unknown target service",
                ok=False,
                service_health=self.service_health(),
            )
        if self._is_contained(target):
            return ActionExecution(
                stderr=f"target {target} is contained",
                ok=False,
                service_health=self.service_health(),
            )
        if self._is_patched(target):
            return ActionExecution(
                stderr=f"target {target} is patched",
                ok=False,
                service_health=self.service_health(),
            )
        result = run_async(release.pods.exec(target, command, timeout=action.timeout_s))
        return ActionExecution(
            stdout=result.stdout.strip(),
            stderr=result.stderr.strip(),
            ok=result.ok,
            service_health=self.service_health(),
        )

    def _runner_for(self, action: Action) -> str:
        if action.role == "red":
            origin = action.payload.get("origin")
            if isinstance(origin, str) and origin:
                if origin in self._service_by_id or origin.startswith("sandbox-"):
                    return origin
            return "sandbox-red"
        if action.role == "blue":
            return "sandbox-blue"
        if action.role == "green":
            return _green_sandbox_name(action.actor_id)
        raise ValueError(f"unsupported runner role: {action.role}")

    def _api_command(self, action: Action) -> str:
        target = action_target(action)
        service = self._service_by_id.get(target)
        if service is None:
            return f"echo unknown target {target}; exit 1"
        port = service.ports[0] if service.ports else 80
        if service.kind == "web_app":
            path = str(action.payload.get("path", "/") or "/")
            if not path.startswith("/"):
                path = f"/{path}"
            query = action.payload.get("query", {})
            suffix = ""
            if isinstance(query, dict) and query:
                suffix = "?" + urlencode(
                    [(str(key), str(value)) for key, value in query.items()],
                    doseq=True,
                )
            return f"wget -qO- http://{target}:{port}{path}{suffix} | head -c 2048"
        if service.kind == "db":
            return f"nc -z -w 3 {target} {port}"
        return f"nc -z -w 3 {target} {port}"

    def _shell_command(self, action: Action) -> str:
        command = str(action.payload.get("command", "")).strip()
        if command:
            return command
        target = action_target(action)
        if action.role == "blue" and target == "svc-siem":
            return "wget -qO- http://svc-siem:9200/all.log | tail -n 20"
        if target in self._service_by_id:
            service = self._service_by_id[target]
            port = service.ports[0] if service.ports else 80
            if service.kind == "web_app":
                return f"wget -qO- http://{target}:{port}/ | head -c 512"
            if service.kind == "siem":
                return "wget -qO- http://svc-siem:9200/all.log | tail -n 20"
            return f"nc -z -w 3 {target} {port}"
        return "true"

    def _mail_command(self, action: Action) -> str:
        target = action_target(action) or "svc-email"
        service = self._service_by_id.get(target)
        if service is None:
            return f"echo unknown mail target {target}; exit 1"
        port = service.ports[0] if service.ports else 25
        sender = str(action.payload.get("from", action.actor_id))
        recipient = str(action.payload.get("to", "noreply@corp.local"))
        subject = str(action.payload.get("subject", "routine update"))
        payload = (
            "HELO corp.local\n"
            f"MAIL FROM:<{sender}>\n"
            f"RCPT TO:<{recipient}>\n"
            "DATA\n"
            f"Subject: {subject}\n\n"
            "OpenRange test mail.\n"
            ".\n"
            "QUIT\n"
        )
        return (
            f"printf %s {shlex.quote(payload)} | nc -w 3 {shlex.quote(target)} {port}"
        )

    def _is_contained(self, target: str) -> bool:
        release = self._require_release()
        result = run_async(
            release.pods.exec(target, "test ! -f /tmp/openrange-contained", timeout=5.0)
        )
        return not result.ok

    def _is_patched(self, target: str) -> bool:
        release = self._require_release()
        weakness = self._weakness_for(target)
        if weakness is not None and weakness.family == "code_web":
            result = run_async(
                release.pods.exec(
                    target,
                    f"test ! -f {shlex.quote(code_web_guard_path(weakness))}",
                    timeout=5.0,
                )
            )
            return not result.ok
        result = run_async(
            release.pods.exec(target, "test ! -f /tmp/openrange-patched", timeout=5.0)
        )
        return not result.ok

    def _patch_command_for(self, target: str) -> str:
        weakness = self._weakness_for(target)
        if (
            weakness is not None
            and weakness.remediation_kind == "shell"
            and weakness.remediation_command
        ):
            cleanup = effect_marker_cleanup_command(weakness)
            if cleanup:
                return f"{weakness.remediation_command}\n{cleanup}"
            return weakness.remediation_command
        return "touch /tmp/openrange-patched"

    def _recovery_command_for(self, target: str) -> str:
        cleanup = ["rm -f /tmp/openrange-contained /tmp/openrange-patched"]
        weakness = self._weakness_for(target)
        if weakness is not None and weakness.family == "code_web":
            cleanup.extend(code_web_cleanup_commands(weakness))
        if weakness is not None:
            effect_cleanup = effect_marker_cleanup_command(weakness)
            if effect_cleanup:
                cleanup.append(effect_cleanup)
        return " && ".join(cleanup)

    def _weakness_for(self, target: str) -> WeaknessSpec | None:
        snapshot = self._require_snapshot()
        return next(
            (weak for weak in snapshot.world.weaknesses if weak.target == target), None
        )

    def _require_release(self) -> BootedRelease:
        if self._release is None:
            raise RuntimeError("no live release is bound")
        return self._release

    def _require_snapshot(self) -> RuntimeSnapshot:
        if self._snapshot is None:
            raise RuntimeError("no active snapshot is bound")
        return self._snapshot


def _green_sandbox_name(persona_id: str) -> str:
    safe = "".join(ch.lower() if ch.isalnum() else "-" for ch in persona_id).strip("-")
    return f"sandbox-green-{safe}"
