"""Counterfactual helpers for admission necessity checks."""

from __future__ import annotations

import asyncio

from open_range.code_web import code_web_cleanup_commands
from open_range.world_ir import WeaknessSpec, WorldIR


def remediation_command(weakness: WeaknessSpec) -> str:
    if weakness.remediation_kind == "shell" and weakness.remediation_command:
        return weakness.remediation_command.strip()
    if weakness.remediation.startswith("shell:"):
        return weakness.remediation.split("shell:", 1)[1].strip()
    return ""


def clear_runtime_markers(release, world: WorldIR) -> None:
    for service in world.services:
        asyncio.run(
            release.pods.exec(
                service.id,
                "rm -f /tmp/openrange-contained /tmp/openrange-patched",
                timeout=5.0,
            )
        )
    for weakness in world.weaknesses:
        for command in _cleanup_commands(weakness):
            asyncio.run(release.pods.exec(weakness.target, command, timeout=5.0))


def _cleanup_commands(weakness: WeaknessSpec) -> tuple[str, ...]:
    if weakness.family == "code_web":
        return code_web_cleanup_commands(weakness)
    return ()
