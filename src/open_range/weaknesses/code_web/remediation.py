"""Exact-code web flaw remediation and guard helpers."""

from __future__ import annotations

import shlex

from open_range.contracts.world import WeaknessSpec

from .common import guard_path


def code_web_remediation_command(weakness: WeaknessSpec) -> str:
    target_guard_path = guard_path(weakness)
    guard_dir = target_guard_path.rsplit("/", 1)[0]
    return (
        f"mkdir -p {shlex.quote(guard_dir)} && touch {shlex.quote(target_guard_path)}"
    )


def code_web_cleanup_commands(weakness: WeaknessSpec) -> tuple[str, ...]:
    return (f"rm -f {shlex.quote(guard_path(weakness))}",)


def code_web_guard_path(weakness: WeaknessSpec) -> str:
    return guard_path(weakness)
