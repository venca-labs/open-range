"""Compatibility shim for admission stage planning helpers."""

from open_range.admission.plan import (
    AdmissionStagePlan,
    admission_stages,
    profile_requires_live,
)

__all__ = ["AdmissionStagePlan", "admission_stages", "profile_requires_live"]
