"""Parameterized exact-code web flaw subsystem facade."""

from __future__ import annotations

from open_range.code_web.common import CodeWebTemplate
from open_range.code_web.remediation import (
    code_web_cleanup_commands,
    code_web_guard_path,
    code_web_remediation_command,
)
from open_range.code_web.render import code_web_realization_content
from open_range.code_web.specs import (
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
