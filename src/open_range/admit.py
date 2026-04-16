"""Compatibility shim for admission controller imports."""

from open_range.admission import controller as _controller
from open_range.admission.controller import (
    AdmissionController,
    LocalAdmissionController,
)

shutil = _controller.shutil
subprocess = _controller.subprocess

__all__ = [
    "AdmissionController",
    "LocalAdmissionController",
    "shutil",
    "subprocess",
]
