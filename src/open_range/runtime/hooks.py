"""Private runtime hooks for audit and event side effects."""

from __future__ import annotations

from open_range.config import AuditConfig
from open_range.runtime.audit import (
    ActionAuditObservation,
    ActionAuditor,
    command_text_for_action,
)
from open_range.runtime.events import EmitEvent
from open_range.runtime.execution import ActionBackend, ActionExecution
from open_range.runtime.green import GreenScheduler
from open_range.runtime_types import (
    Action,
    EpisodeAudit,
    IntegritySample,
    RuntimeEvent,
    action_target,
)
from open_range.snapshot import RuntimeSnapshot


class RuntimeHooks:
    """Own runtime-side audit and event sink hooks."""

    def __init__(
        self,
        *,
        green_scheduler: GreenScheduler,
        action_backend: ActionBackend | None,
    ) -> None:
        self.green_scheduler = green_scheduler
        self.action_backend = action_backend
        self._auditor: ActionAuditor | None = None

    def set_action_backend(self, action_backend: ActionBackend | None) -> None:
        self.action_backend = action_backend

    def reset(self, snapshot: RuntimeSnapshot, audit_config: AuditConfig) -> None:
        self._auditor = ActionAuditor(audit_config)
        self._auditor.bind_snapshot(snapshot)
        self._auditor.capture_baseline(self.capture_integrity)

    def close(self) -> None:
        self._auditor = None

    def build_audit_summary(self) -> EpisodeAudit | None:
        if self._auditor is None:
            return None
        return self._auditor.build_summary(self.capture_integrity)

    def observe_action(
        self,
        action: Action,
        live: ActionExecution,
        *,
        sim_time: float,
        controlled: bool,
    ) -> ActionAuditObservation | None:
        if self._auditor is None:
            return None
        return self._auditor.observe(
            action=action,
            executed_command=live.executed_command,
            audit_command=command_text_for_action(action),
            sim_time=sim_time,
            controlled=controlled,
        )

    def emit_event(
        self,
        audit: ActionAuditObservation | None,
        emit_event: EmitEvent,
    ) -> EmitEvent:
        if audit is None or not audit.suspicious:
            return emit_event

        def suspicious_emit_event(**kwargs):
            return emit_event(
                **kwargs,
                suspicious=True,
                suspicious_reasons=audit.matched_patterns,
            )

        return suspicious_emit_event

    def finalize_action(
        self,
        audit: ActionAuditObservation | None,
        *,
        action: Action,
        emitted: list[RuntimeEvent],
        emit_event: EmitEvent,
    ) -> None:
        if audit is not None and audit.suspicious and not emitted:
            emitted.append(
                emit_event(
                    event_type="SuspiciousActionObserved",
                    actor=action.role,
                    source_entity=action.actor_id,
                    target_entity=action_target(action) or action.kind,
                    malicious=action.role == "red",
                    observability_surfaces=(),
                    suspicious=True,
                    suspicious_reasons=audit.matched_patterns,
                    green_reactive=False,
                )
            )
        if self._auditor is None:
            return
        self._auditor.record(
            audit,
            emitted_event_ids=tuple(event.id for event in emitted),
        )

    def publish_event(self, event: RuntimeEvent, *, green_reactive: bool) -> None:
        if green_reactive:
            self.green_scheduler.record_event(event)
        if self.action_backend is not None:
            self.action_backend.record_event(event)

    def capture_integrity(
        self, service_paths: dict[str, tuple[str, ...]]
    ) -> tuple[IntegritySample, ...]:
        if self.action_backend is None:
            return ()
        capture_integrity = getattr(self.action_backend, "capture_integrity", None)
        if not callable(capture_integrity):
            return ()
        return capture_integrity(service_paths)
