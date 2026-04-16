"""Admission check registration helpers."""

from __future__ import annotations

import importlib
from collections.abc import Callable

from open_range.admission.models import ReferenceBundle, ValidatorCheckReport
from open_range.snapshot import KindArtifacts
from open_range.world_ir import WorldIR

CheckFunc = Callable[
    [WorldIR, KindArtifacts, ReferenceBundle | None], ValidatorCheckReport
]

_REGISTERED_CHECKS: dict[str, CheckFunc] = {}
_BUILTIN_CHECKS_LOADED = False


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
    _load_builtin_admission_checks()
    try:
        return _REGISTERED_CHECKS[name]
    except KeyError as exc:
        raise KeyError(f"unknown admission check {name!r}") from exc


def registered_admission_checks() -> tuple[str, ...]:
    _load_builtin_admission_checks()
    return tuple(sorted(_REGISTERED_CHECKS))


def _load_builtin_admission_checks() -> None:
    global _BUILTIN_CHECKS_LOADED
    if _BUILTIN_CHECKS_LOADED:
        return
    _BUILTIN_CHECKS_LOADED = True
    try:
        importlib.import_module("open_range.admission.checks")
    except Exception:
        _BUILTIN_CHECKS_LOADED = False
        raise
