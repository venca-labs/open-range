"""Admission-owned remediation and live cleanup helpers."""

from __future__ import annotations

from open_range.runtime.async_utils import run_async
from open_range.weaknesses import cleanup_steps_for_weakness
from open_range.world_ir import WeaknessSpec, WorldIR


def remediation_command(weakness: WeaknessSpec) -> str:
    if weakness.remediation_kind == "shell" and weakness.remediation_command:
        return weakness.remediation_command.strip()
    if weakness.remediation.startswith("shell:"):
        return weakness.remediation.split("shell:", 1)[1].strip()
    return ""


def clear_runtime_markers(release, world: WorldIR) -> None:
    for service in world.services:
        run_async(
            release.pods.exec(
                service.id,
                "rm -f /tmp/openrange-contained /tmp/openrange-patched /srv/http/siem/egress-canary.log",
                timeout=5.0,
            )
        )
    for weakness in world.weaknesses:
        for target, command in cleanup_steps_for_weakness(weakness):
            run_async(release.pods.exec(target, command, timeout=5.0))
