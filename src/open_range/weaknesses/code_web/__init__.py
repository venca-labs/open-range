"""Parameterized exact-code web flaw subsystem facade."""

from __future__ import annotations

from .remediation import code_web_cleanup_commands, code_web_guard_path
from .specs import code_web_payload

__all__ = [
    "code_web_cleanup_commands",
    "code_web_guard_path",
    "code_web_payload",
]
