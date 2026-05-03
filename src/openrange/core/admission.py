"""Admission checks for generated worlds."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import TYPE_CHECKING, Literal, cast

from openrange.core.errors import AdmissionError, OpenRangeError, StoreError
from openrange.core.pack import VerifierResult

if TYPE_CHECKING:
    from openrange.core.builder import BuildState


FailureStage = Literal["world", "tasks", "verifier", "generation", "probe"]


@dataclass(frozen=True, slots=True)
class AdmissionFailure:
    """One structured reason a build failed admission.

    ``stage`` is one of: 'world', 'tasks', 'verifier', 'generation', 'probe'.
    ``task_id`` is set when the failure is attributable to a specific task.
    ``details`` is a free-form mapping for builders to inspect during repair.
    """

    reason: str
    stage: FailureStage
    task_id: str | None = None
    details: Mapping[str, object] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class AdmissionResult:
    """The outcome of running admission against a BuildState.

    ``accepted`` is True iff ``failures`` is empty. ``verifier_results``
    surfaces per-task verifier output for the success path; populated as
    soon as verifiers ran (even if some failed).
    """

    accepted: bool
    failures: tuple[AdmissionFailure, ...] = ()
    verifier_results: Mapping[str, VerifierResult] = field(default_factory=dict)
    checks: tuple[str, ...] = ()


class BuildFailed(OpenRangeError):
    """Raised when admission fails after the repair budget is exhausted.

    Carries the final ``AdmissionResult`` so callers can inspect the
    structured failures that the builder could not repair.
    """

    def __init__(self, result: AdmissionResult, attempts: int) -> None:
        self.result = result
        self.attempts = attempts
        reasons = "; ".join(f.reason for f in result.failures) or "no detail"
        super().__init__(f"build failed admission after {attempts} attempts: {reasons}")


@dataclass(frozen=True, slots=True)
class AdmissionReport:
    passed: bool
    checks: tuple[str, ...]
    verifier_results: Mapping[str, VerifierResult]
    errors: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, object]:
        return {
            "passed": self.passed,
            "checks": list(self.checks),
            "verifier_results": {
                key: dict(value) for key, value in self.verifier_results.items()
            },
            "errors": list(self.errors),
        }

    @classmethod
    def from_mapping(cls, data: Mapping[str, object]) -> AdmissionReport:
        passed = data.get("passed")
        checks = data.get("checks")
        verifier_results = data.get("verifier_results")
        errors = data.get("errors", ())
        if not isinstance(passed, bool):
            raise StoreError("stored admission passed flag is invalid")
        if not isinstance(checks, list) or not all(
            isinstance(check, str) for check in checks
        ):
            raise StoreError("stored admission checks are invalid")
        if not isinstance(verifier_results, Mapping):
            raise StoreError("stored verifier results are invalid")
        if not isinstance(errors, list) or not all(
            isinstance(error, str) for error in errors
        ):
            raise StoreError("stored admission errors are invalid")
        return cls(
            passed,
            tuple(checks),
            MappingProxyType(
                {
                    str(key): MappingProxyType(dict(cast(Mapping[str, object], value)))
                    for key, value in verifier_results.items()
                    if isinstance(value, Mapping)
                },
            ),
            tuple(errors),
        )


def admit(state: BuildState) -> AdmissionResult:
    """Validate a BuildState and return a structured AdmissionResult.

    Never raises for admission-level failures; instead populates
    ``failures``. Reserves exceptions for shape errors that indicate the
    pipeline is broken (not the world).
    """
    failures: list[AdmissionFailure] = []
    if state.world_graph is None or not state.world_graph.nodes:
        failures.append(AdmissionFailure("world is empty", stage="world"))
    if not state.tasks:
        failures.append(AdmissionFailure("no tasks generated", stage="tasks"))
    if failures:
        return AdmissionResult(accepted=False, failures=tuple(failures))
    probe = state.admission_probe or {}
    verifier_results: dict[str, VerifierResult] = {}
    for task in state.tasks:
        result = MappingProxyType(dict(task.verify(probe)))
        verifier_results[task.id] = result
        if result.get("passed") is not True:
            failures.append(
                AdmissionFailure(
                    reason=f"task {task.id!r} verifier did not pass admission probe",
                    stage="verifier",
                    task_id=task.id,
                    details=MappingProxyType(dict(result)),
                ),
            )
    return AdmissionResult(
        accepted=not failures,
        failures=tuple(failures),
        verifier_results=MappingProxyType(verifier_results),
        checks=("world_present", "tasks_present", "verifier_probes"),
    )


def report_from_result(result: AdmissionResult) -> AdmissionReport:
    """Project an accepted ``AdmissionResult`` into a snapshot ``AdmissionReport``."""
    if not result.accepted:
        raise AdmissionError("cannot build report from a non-accepted result")
    return AdmissionReport(
        passed=True,
        checks=result.checks,
        verifier_results=result.verifier_results,
    )
