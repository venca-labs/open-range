"""Compatibility shim for admission registry imports."""

from open_range.admission.registry import (
    admission_check,
    get_admission_check,
    registered_admission_checks,
)

__all__ = [
    "admission_check",
    "get_admission_check",
    "registered_admission_checks",
]
