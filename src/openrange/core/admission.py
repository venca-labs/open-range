"""Admission checks for generated worlds."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import TYPE_CHECKING, cast

from openrange.core.errors import AdmissionError, StoreError
from openrange.core.pack import VerifierResult

if TYPE_CHECKING:
    from openrange.core.builder import BuildState


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


def admit(state: BuildState) -> AdmissionReport:
    errors: list[str] = []
    if state.world_graph is None or not state.world_graph.nodes:
        errors.append("world is empty")
    if not state.tasks:
        errors.append("no tasks generated")
    if errors:
        raise AdmissionError("; ".join(errors))
    probe = state.admission_probe or {}
    verifier_results = {
        task.id: MappingProxyType(dict(task.verify(probe)))
        for task in state.tasks
    }
    for task_id, result in verifier_results.items():
        if result.get("passed") is not True:
            errors.append(f"task {task_id!r} verifier did not pass admission probe")
    if errors:
        raise AdmissionError("; ".join(errors))
    return AdmissionReport(
        True,
        ("world_present", "tasks_present", "verifier_probes"),
        MappingProxyType(verifier_results),
    )
