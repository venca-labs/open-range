"""Admission check registration helpers."""

from __future__ import annotations

from collections.abc import Callable

from open_range.admission.models import ReferenceBundle, ValidatorCheckReport
from open_range.contracts.snapshot import KindArtifacts
from open_range.contracts.world import WorldIR

CheckFunc = Callable[
    [WorldIR, KindArtifacts, ReferenceBundle | None], ValidatorCheckReport
]

_REGISTERED_CHECKS: dict[str, CheckFunc] = {}
_BUILTIN_CHECKS_REGISTERED = False


def register_admission_check(name: str, fn: CheckFunc) -> None:
    """Register one admission check by plan name."""

    existing = _REGISTERED_CHECKS.get(name)
    if existing is not None and existing is not fn:
        raise ValueError(f"admission check {name!r} already registered")
    _REGISTERED_CHECKS[name] = fn


def get_admission_check(name: str) -> CheckFunc:
    _ensure_builtin_admission_checks()
    try:
        return _REGISTERED_CHECKS[name]
    except KeyError as exc:
        raise KeyError(f"unknown admission check {name!r}") from exc


def registered_admission_checks() -> tuple[str, ...]:
    _ensure_builtin_admission_checks()
    return tuple(sorted(_REGISTERED_CHECKS))


def _ensure_builtin_admission_checks() -> None:
    global _BUILTIN_CHECKS_REGISTERED
    if _BUILTIN_CHECKS_REGISTERED:
        return
    from open_range.admission.checks import builtin_admission_check_specs

    for spec in builtin_admission_check_specs():
        register_admission_check(spec.name, spec.fn)
    _BUILTIN_CHECKS_REGISTERED = True
