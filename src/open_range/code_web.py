"""Parameterized exact-code web flaw subsystem facade."""

from __future__ import annotations

from open_range._code_web_common import CodeWebTemplate
from open_range._code_web_remediation import (
    code_web_cleanup_commands,
    code_web_guard_path,
    code_web_remediation_command,
)
from open_range._code_web_render import code_web_realization_content
from open_range._code_web_specs import (
    code_web_payload,
    code_web_realizations,
    code_web_template,
)

__all__ = [
    "CodeWebTemplate",
    "code_web_cleanup_commands",
    "code_web_guard_path",
    "code_web_payload",
    "code_web_realization_content",
    "code_web_realizations",
    "code_web_remediation_command",
    "code_web_template",
]
