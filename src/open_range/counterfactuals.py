"""Counterfactual helpers for admission necessity checks."""

from __future__ import annotations

from open_range.async_utils import run_async
from open_range.code_web import code_web_cleanup_commands
from open_range.effect_markers import (
    effect_marker_cleanup_command,
    effect_marker_service,
)
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
        cleanup_target = effect_marker_service(weakness) or weakness.target
        cleanup = effect_marker_cleanup_command(weakness)
        if cleanup:
            run_async(release.pods.exec(cleanup_target, cleanup, timeout=5.0))
        for command in _cleanup_commands(weakness):
            run_async(release.pods.exec(weakness.target, command, timeout=5.0))


def _cleanup_commands(weakness: WeaknessSpec) -> tuple[str, ...]:
    if weakness.family == "code_web":
        return code_web_cleanup_commands(weakness)
    return ()
