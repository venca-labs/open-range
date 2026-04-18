"""Live necessity validation helpers."""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from open_range.admission.models import ValidatorCheckReport
from open_range.contracts.snapshot import RuntimeSnapshot
from open_range.objectives.effects import effect_marker_service
from open_range.runtime.execution import PodActionBackend
from open_range.support.async_utils import run_async

if TYPE_CHECKING:
    from open_range.render.live import BootedRelease


@dataclass(slots=True)
class LiveNecessityRunner:
    snapshot: RuntimeSnapshot
    release: BootedRelease
    backend: PodActionBackend
    trace_bindings: tuple[tuple[int, Any, tuple[Any, ...]], ...]
    remediation_for_weakness: Callable[[Any], str]
    run_red_reference: Callable[..., tuple[Any, Any, Any, Any]]
    clear_reference_markers: Callable[[BootedRelease, RuntimeSnapshot], None]

    def report(self) -> ValidatorCheckReport:
        if not self.trace_bindings:
            return ValidatorCheckReport(
                name="live_necessity",
                passed=False,
                details={"reason": "no reference-relevant weakness"},
                error=(
                    "no reference-relevant weakness available for live necessity check"
                ),
            )
        checks = [
            self._check_weakness(trace_index, trace, weakness)
            for trace_index, trace, weaknesses in self.trace_bindings
            for weakness in weaknesses
        ]
        passed = all(check["passed"] for check in checks)
        return ValidatorCheckReport(
            name="live_necessity",
            passed=passed,
            details={"checks": checks},
            error="" if passed else "live remediation did not break the reference path",
        )

    def _check_weakness(
        self, trace_index: int, trace: Any, weakness: Any
    ) -> dict[str, Any]:
        command = self.remediation_for_weakness(weakness)
        if not command:
            return {
                "trace_id": trace.id,
                "trace_index": trace_index,
                "weakness_id": weakness.id,
                "target": weakness.target,
                "remediation": weakness.remediation,
                "remediation_kind": weakness.remediation_kind,
                "passed": False,
                "error": "weakness remediation is not executable",
            }
        restored_before = self._restore_state(weakness)
        apply_result = run_async(
            self.release.pods.exec(weakness.target, command, timeout=10.0)
        )
        score, _events, _health, outputs = self.run_red_reference(
            self.snapshot,
            self.backend,
            trace_index=trace_index,
        )
        restored_after = self._restore_state(weakness)
        passed = (
            restored_before
            and apply_result.ok
            and score.winner != "red"
            and restored_after
        )
        return {
            "trace_id": trace.id,
            "trace_index": trace_index,
            "weakness_id": weakness.id,
            "target": weakness.target,
            "winner_after_remediation": score.winner,
            "restored_before": restored_before,
            "restored_after": restored_after,
            "outputs": outputs,
            "passed": passed,
        }

    def _restore_state(self, weakness: Any) -> bool:
        self.clear_reference_markers(self.release, self.snapshot)
        restarted = self._restart_services(self._services_for(weakness))
        self.clear_reference_markers(self.release, self.snapshot)
        return restarted

    def _services_for(self, weakness: Any) -> tuple[str, ...]:
        services = {
            str(getattr(weakness, "target", "")),
            effect_marker_service(weakness),
            *(
                str(getattr(realization, "service", ""))
                for realization in getattr(weakness, "realization", ())
            ),
        }
        return tuple(sorted(service for service in services if service))

    def _restart_services(self, services: tuple[str, ...]) -> bool:
        restart = getattr(self.release.pods, "restart", None)
        if restart is None:
            return True
        pod_ids = set(getattr(self.release.pods, "pod_ids", {}))
        restarted = True
        for service in services:
            if pod_ids and service not in pod_ids:
                continue
            run_async(restart(service, timeout=30.0))
            restarted = self._wait_for_service(service) and restarted
        return restarted

    def _wait_for_service(self, service: str, *, timeout_s: float = 60.0) -> bool:
        deadline = time.monotonic() + timeout_s
        while time.monotonic() < deadline:
            if run_async(self.release.pods.is_healthy(service)):
                return True
            time.sleep(1.0)
        return False
