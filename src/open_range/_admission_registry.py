"""Internal admission check registration helpers."""

from __future__ import annotations

from collections.abc import Callable

from open_range.admission import ReferenceBundle, ValidatorCheckReport
from open_range.snapshot import KindArtifacts
from open_range.world_ir import WorldIR

CheckFunc = Callable[
    [WorldIR, KindArtifacts, ReferenceBundle | None], ValidatorCheckReport
]

_REGISTERED_CHECKS: dict[str, CheckFunc] = {}


def admission_check(name: str) -> Callable[[CheckFunc], CheckFunc]:
    """Register one admission check by plan name."""

    def wrap(fn: CheckFunc) -> CheckFunc:
        existing = _REGISTERED_CHECKS.get(name)
        if existing is not None and existing is not fn:
            raise ValueError(f"admission check {name!r} already registered")
        _REGISTERED_CHECKS[name] = fn
        return fn

    return wrap


def get_admission_check(name: str) -> CheckFunc:
    try:
        return _REGISTERED_CHECKS[name]
    except KeyError as exc:
        raise KeyError(f"unknown admission check {name!r}") from exc


def registered_admission_checks() -> tuple[str, ...]:
    return tuple(sorted(_REGISTERED_CHECKS))
