"""Episode orchestration loop.

``run_episode`` connects to an OpenRange environment and alternates
Red / Blue turns until the episode ends or ``max_steps`` is reached.
Agents only see observations -- they cannot control episode lifecycle.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from open_range.agents.protocol import EpisodeMetrics, EpisodeResult

if TYPE_CHECKING:
    from open_range.agents.protocol import RangeAgent
    from open_range.training.curriculum import CurriculumTracker

logger = logging.getLogger(__name__)


def _determine_outcome(
    flags_found: list[str],
    total_flags: int,
    steps: int,
    max_steps: int,
) -> str:
    """Determine episode outcome from final state."""
    if flags_found and len(flags_found) >= total_flags > 0:
        return "red_win"
    if steps >= max_steps:
        return "timeout"
    # If done without all flags and not timeout, Blue held
    return "blue_win"


def _compute_metrics(
    result: EpisodeResult,
    total_flags: int,
) -> EpisodeMetrics:
    """Compute episode metrics from trajectories."""
    metrics = EpisodeMetrics()

    # Flag capture rate
    if total_flags > 0:
        metrics.flag_capture_rate = len(result.flags_found) / total_flags

    # Steps to first flag
    for i, step in enumerate(result.red_trajectory):
        stdout = step.get("stdout", "")
        if "Flag accepted" in stdout or "Correct" in stdout:
            metrics.steps_to_first_flag = i + 1
            break

    # Stealth: 1 - (detected_actions / total_red_actions)
    total_red = len(result.red_trajectory)
    if total_red > 0:
        # Count Blue findings that overlap with Red actions
        blue_findings = sum(
            1 for s in result.blue_trajectory if s.get("command", "").startswith("submit_finding")
        )
        detected = min(blue_findings, total_red)
        metrics.stealth = 1.0 - (detected / total_red)
    else:
        metrics.stealth = 1.0

    # Detection TP: how many Red actions Blue detected
    if total_red > 0:
        blue_findings = sum(
            1 for s in result.blue_trajectory if s.get("command", "").startswith("submit_finding")
        )
        metrics.detection_tp = min(blue_findings / total_red, 1.0)

    return metrics


def run_episode(
    env: object,
    red: RangeAgent,
    blue: RangeAgent,
    max_steps: int = 100,
    red_model: str = "",
    blue_model: str = "",
    curriculum: CurriculumTracker | None = None,
) -> EpisodeResult:
    """Run one tandem Red + Blue episode.

    The orchestration layer calls ``reset()`` and alternates agent turns.
    Agents only see observations -- they cannot control episode lifecycle.

    This function works with the ``RangeEnvironment`` directly (no HTTP).
    For remote environments, use the async variant or call through the client.

    Args:
        env: A ``RangeEnvironment`` instance (or anything with ``reset``/``step``/``state``).
        red: Red team agent (satisfies ``RangeAgent`` protocol).
        blue: Blue team agent (satisfies ``RangeAgent`` protocol).
        max_steps: Maximum total steps (Red + Blue combined).
        red_model: Model identifier for logging.
        blue_model: Model identifier for logging.

    Returns:
        ``EpisodeResult`` with trajectories, metrics, and outcome.
    """
    from open_range.server.models import RangeAction

    # Reset environment
    obs = env.reset()
    briefing = obs.stdout

    # Initialize agents
    red.reset(briefing=briefing, role="red")
    blue.reset(briefing=briefing, role="blue")

    red_trajectory: list[dict] = []
    blue_trajectory: list[dict] = []
    step = 0

    while not obs.done and step < max_steps:
        # Red's turn
        red_cmd = red.act(obs.stdout)
        obs = env.step(RangeAction(command=red_cmd, mode="red"))
        red_trajectory.append({
            "command": red_cmd,
            "stdout": obs.stdout,
            "stderr": getattr(obs, "stderr", ""),
            "reward": obs.reward,
        })
        step += 1

        if obs.done:
            break

        # Blue's turn
        blue_cmd = blue.act(obs.stdout)
        obs = env.step(RangeAction(command=blue_cmd, mode="blue"))
        blue_trajectory.append({
            "command": blue_cmd,
            "stdout": obs.stdout,
            "stderr": getattr(obs, "stderr", ""),
            "reward": obs.reward,
        })
        step += 1

    # Gather final state
    env_state = env.state
    flags_found = getattr(env_state, "flags_found", [])
    tier = getattr(env_state, "tier", 1)
    snapshot_id = getattr(env_state, "episode_id", "")

    # Determine total flags available
    snapshot = getattr(env, "snapshot", None) or getattr(env, "_snapshot", None)
    total_flags = len(snapshot.flags) if snapshot and hasattr(snapshot, "flags") else 0

    outcome = _determine_outcome(flags_found, total_flags, step, max_steps)

    result = EpisodeResult(
        red_trajectory=red_trajectory,
        blue_trajectory=blue_trajectory,
        flags_found=list(flags_found),
        steps=step,
        tier=tier,
        snapshot_id=snapshot_id,
        red_model=red_model or getattr(red, "model", ""),
        blue_model=blue_model or getattr(blue, "model", ""),
        outcome=outcome,
    )

    result.metrics = _compute_metrics(result, total_flags)

    logger.info(
        "Episode %s complete: outcome=%s, steps=%d, flags=%d/%d",
        snapshot_id,
        outcome,
        step,
        len(flags_found),
        total_flags,
    )

    # Curriculum feedback wiring (#34)
    if curriculum is not None:
        # Extract vuln classes from snapshot truth graph if available
        vuln_classes: list[str] = []
        if snapshot and hasattr(snapshot, "truth_graph") and snapshot.truth_graph:
            tg = snapshot.truth_graph
            vulns = getattr(tg, "vulns", [])
            vuln_classes = [getattr(v, "type", "") for v in vulns if getattr(v, "type", "")]

        curriculum.update_from_result({
            "snapshot_id": snapshot_id,
            "vuln_classes": vuln_classes,
            "outcome": outcome,
            "flags_found": list(flags_found),
            "steps": step,
            "tier": tier,
            "red_model": red_model or getattr(red, "model", ""),
            "blue_model": blue_model or getattr(blue, "model", ""),
        })

    return result
