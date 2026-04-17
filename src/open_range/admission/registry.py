"""Admission check registration helpers."""

from __future__ import annotations

from collections.abc import Callable

from open_range.admission.checks import BUILTIN_ADMISSION_CHECKS
from open_range.admission.models import ReferenceBundle, ValidatorCheckReport
from open_range.contracts.snapshot import KindArtifacts
from open_range.contracts.world import WorldIR

CheckFunc = Callable[
    [WorldIR, KindArtifacts, ReferenceBundle | None], ValidatorCheckReport
]

_REGISTERED_CHECKS: dict[str, CheckFunc] = {
    spec.name: spec.fn for spec in BUILTIN_ADMISSION_CHECKS
}


def register_admission_check(name: str, fn: CheckFunc) -> None:
    """Register one admission check by plan name."""

    existing = _REGISTERED_CHECKS.get(name)
    if existing is not None and existing is not fn:
        raise ValueError(f"admission check {name!r} already registered")
    _REGISTERED_CHECKS[name] = fn


def get_admission_check(name: str) -> CheckFunc:
    try:
        return _REGISTERED_CHECKS[name]
    except KeyError as exc:
        raise KeyError(f"unknown admission check {name!r}") from exc


def registered_admission_checks() -> tuple[str, ...]:
    return tuple(sorted(_REGISTERED_CHECKS))
