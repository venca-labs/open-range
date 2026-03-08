"""Simple evaluation harness for Red + Blue agents.

Run N episodes, aggregate metrics, and return a summary dict.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from open_range.agents.episode import run_episode
from open_range.agents.protocol import EpisodeResult

if TYPE_CHECKING:
    from open_range.agents.protocol import RangeAgent

logger = logging.getLogger(__name__)


def _mean(values: list[float]) -> float:
    """Compute mean, returning 0.0 for empty lists."""
    return sum(values) / len(values) if values else 0.0


def evaluate(
    env: object,
    red: RangeAgent,
    blue: RangeAgent,
    n_episodes: int = 50,
    max_steps: int = 100,
    red_model: str = "",
    blue_model: str = "",
) -> dict:
    """Run *n_episodes* and compute aggregate metrics.

    Args:
        env: A ``RangeEnvironment`` instance (or compatible object).
        red: Red team agent.
        blue: Blue team agent.
        n_episodes: Number of episodes to run.
        max_steps: Maximum steps per episode.
        red_model: Model identifier for logging.
        blue_model: Model identifier for logging.

    Returns:
        Dict with aggregate metrics::

            {
                "n_episodes": int,
                "red_solve_rate": float,
                "blue_detect_rate": float,
                "avg_steps": float,
                "avg_stealth": float,
                "avg_availability": float,
                "false_positive_rate": float,
                "avg_flag_capture_rate": float,
                "outcomes": {"red_win": int, "blue_win": int, "timeout": int},
                "results": [EpisodeResult, ...],
            }
    """
    results: list[EpisodeResult] = []

    for i in range(n_episodes):
        logger.info("Running episode %d/%d", i + 1, n_episodes)
        result = run_episode(
            env=env,
            red=red,
            blue=blue,
            max_steps=max_steps,
            red_model=red_model,
            blue_model=blue_model,
        )
        results.append(result)

    # Aggregate
    outcomes = {"red_win": 0, "blue_win": 0, "timeout": 0}
    for r in results:
        if r.outcome in outcomes:
            outcomes[r.outcome] += 1

    return {
        "n_episodes": n_episodes,
        "red_solve_rate": _mean([1.0 if r.outcome == "red_win" else 0.0 for r in results]),
        "blue_detect_rate": _mean([r.metrics.detection_tp for r in results]),
        "avg_steps": _mean([float(r.steps) for r in results]),
        "avg_stealth": _mean([r.metrics.stealth for r in results]),
        "avg_availability": _mean([r.metrics.availability for r in results]),
        "false_positive_rate": _mean([r.metrics.false_positives for r in results]),
        "avg_flag_capture_rate": _mean([r.metrics.flag_capture_rate for r in results]),
        "outcomes": outcomes,
        "results": results,
    }
