"""Compatibility shim for admission controller imports."""

from open_range.admission import controller as _controller
from open_range.admission.controller import (
    AdmissionController,
    LocalAdmissionController,
)
from open_range.admission.registry import CheckFunc

shutil = _controller.shutil
subprocess = _controller.subprocess

__all__ = [
    "AdmissionController",
    "CheckFunc",
    "LocalAdmissionController",
    "shutil",
    "subprocess",
]
