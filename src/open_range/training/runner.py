"""Curriculum runner for OpenRange training evaluation.

Orchestrates a matrix of (manifest x seed x episode) runs, collects
results, and saves them as JSONL for downstream analysis.

Usage::

    python -m open_range.training.runner \\
        --manifest manifests/tier1_basic.yaml \\
        --seeds 1-5 \\
        --episodes 3
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Protocols for pluggable environment and agents
# ---------------------------------------------------------------------------


@runtime_checkable
class RunnerEnvironment(Protocol):
    """Minimal environment interface for the curriculum runner."""

    def reset(self, seed: int | None = None, **kwargs: Any) -> Any:
        """Reset the environment, optionally with a seed."""
        ...

    def step(self, action: Any) -> Any:
        """Execute one step."""
        ...

    @property
    def state(self) -> Any:
        """Current environment state."""
        ...


@runtime_checkable
class RunnerAgent(Protocol):
    """Minimal agent interface for the curriculum runner."""

    def reset(self, briefing: str, role: str) -> None:
        ...

    def act(self, observation: Any) -> str:
        ...


# ---------------------------------------------------------------------------
# Run config and result types
# ---------------------------------------------------------------------------


@dataclass
class RunConfig:
    """Configuration for a curriculum run."""

    manifests: list[str]
    seeds: list[int]
    episodes_per_seed: int = 1
    max_steps: int = 100

    @classmethod
    def from_cli(
        cls,
        manifests: list[str],
        seeds_str: str,
        episodes: int = 1,
        max_steps: int = 100,
    ) -> RunConfig:
        """Parse CLI seed range (e.g. '1-5') into a RunConfig."""
        seeds = _parse_seed_range(seeds_str)
        return cls(
            manifests=manifests,
            seeds=seeds,
            episodes_per_seed=episodes,
            max_steps=max_steps,
        )


@dataclass
class EpisodeRecord:
    """Result of a single episode run."""

    manifest: str
    seed: int
    episode: int
    outcome: str = "timeout"
    steps: int = 0
    flags_found: list[str] = field(default_factory=list)
    reward: float = 0.0
    duration_s: float = 0.0
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "manifest": self.manifest,
            "seed": self.seed,
            "episode": self.episode,
            "outcome": self.outcome,
            "steps": self.steps,
            "flags_found": self.flags_found,
            "reward": round(self.reward, 4),
            "duration_s": round(self.duration_s, 2),
            **self.metadata,
        }


def _parse_seed_range(seeds_str: str) -> list[int]:
    """Parse a seed range like '1-5' or '1,3,5' into a list of ints."""
    seeds: list[int] = []
    for part in seeds_str.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-", 1)
            seeds.extend(range(int(start), int(end) + 1))
        else:
            seeds.append(int(part))
    return seeds


# ---------------------------------------------------------------------------
# Curriculum Runner
# ---------------------------------------------------------------------------


class CurriculumRunner:
    """Orchestrate a matrix of (manifest x seed x episode) runs.

    Args:
        env: Environment instance (or factory callable).
        red: Red team agent.
        blue: Blue team agent.
        config: Run configuration specifying the matrix.
    """

    def __init__(
        self,
        env: Any,
        red: RunnerAgent,
        blue: RunnerAgent,
        config: RunConfig,
    ) -> None:
        self.env = env
        self.red = red
        self.blue = blue
        self.config = config
        self._results: list[EpisodeRecord] = []

    @property
    def results(self) -> list[EpisodeRecord]:
        """All episode results collected so far."""
        return list(self._results)

    def run(self) -> list[EpisodeRecord]:
        """Run the full (manifest x seed x episode) matrix.

        Returns:
            List of EpisodeRecord for each completed episode.
        """
        self._results = []
        total = (
            len(self.config.manifests)
            * len(self.config.seeds)
            * self.config.episodes_per_seed
        )
        run_idx = 0

        for manifest_path in self.config.manifests:
            for seed in self.config.seeds:
                for ep in range(self.config.episodes_per_seed):
                    run_idx += 1
                    logger.info(
                        "Run %d/%d: manifest=%s seed=%d episode=%d",
                        run_idx,
                        total,
                        manifest_path,
                        seed,
                        ep + 1,
                    )
                    record = self._run_episode(manifest_path, seed, ep + 1)
                    self._results.append(record)

        return list(self._results)

    def _run_episode(
        self, manifest_path: str, seed: int, episode_num: int
    ) -> EpisodeRecord:
        """Run a single episode and return an EpisodeRecord."""
        from open_range.models import RangeAction

        start = time.time()

        try:
            obs = self.env.reset(seed=seed)
        except Exception as exc:
            logger.error("Reset failed: %s", exc)
            return EpisodeRecord(
                manifest=manifest_path,
                seed=seed,
                episode=episode_num,
                outcome="error",
                metadata={"error": str(exc)},
            )

        briefing = getattr(obs, "stdout", str(obs))
        self.red.reset(briefing=briefing, role="red")
        self.blue.reset(briefing=briefing, role="blue")

        step = 0
        total_reward = 0.0
        done = getattr(obs, "done", False)

        while not done and step < self.config.max_steps:
            # Red turn
            try:
                red_cmd = self.red.act(obs)
                obs = self.env.step(RangeAction(command=red_cmd, mode="red"))
                total_reward += getattr(obs, "reward", 0.0) or 0.0
                step += 1
                done = getattr(obs, "done", False)
            except Exception as exc:
                logger.warning("Red step failed: %s", exc)
                break

            if done:
                break

            # Blue turn
            try:
                blue_cmd = self.blue.act(obs)
                obs = self.env.step(RangeAction(command=blue_cmd, mode="blue"))
                total_reward += getattr(obs, "reward", 0.0) or 0.0
                step += 1
                done = getattr(obs, "done", False)
            except Exception as exc:
                logger.warning("Blue step failed: %s", exc)
                break

        duration = time.time() - start

        # Gather state
        env_state = self.env.state
        flags_found = list(getattr(env_state, "flags_found", []))

        # Determine outcome
        if flags_found:
            outcome = "flag_captured"
        elif step >= self.config.max_steps:
            outcome = "timeout"
        elif done:
            outcome = "done"
        else:
            outcome = "error"

        return EpisodeRecord(
            manifest=manifest_path,
            seed=seed,
            episode=episode_num,
            outcome=outcome,
            steps=step,
            flags_found=flags_found,
            reward=total_reward,
            duration_s=duration,
        )

    def save_results(self, path: str | Path) -> int:
        """Save results to a JSONL file.

        Args:
            path: Output file path.

        Returns:
            Number of records written.
        """
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w") as f:
            for record in self._results:
                f.write(json.dumps(record.to_dict()) + "\n")
        return len(self._results)

    def results_summary(self) -> dict[str, Any]:
        """Aggregate pass/fail and reward statistics.

        Returns:
            Dict with:
            - total_runs: total episodes run
            - outcomes: outcome -> count
            - avg_reward: mean reward
            - avg_steps: mean steps
            - avg_duration_s: mean duration
            - by_manifest: per-manifest stats
            - by_seed: per-seed stats
        """
        if not self._results:
            return {
                "total_runs": 0,
                "outcomes": {},
                "avg_reward": 0.0,
                "avg_steps": 0.0,
                "avg_duration_s": 0.0,
                "by_manifest": {},
                "by_seed": {},
            }

        outcomes: dict[str, int] = {}
        rewards: list[float] = []
        steps: list[int] = []
        durations: list[float] = []
        by_manifest: dict[str, list[EpisodeRecord]] = {}
        by_seed: dict[int, list[EpisodeRecord]] = {}

        for r in self._results:
            outcomes[r.outcome] = outcomes.get(r.outcome, 0) + 1
            rewards.append(r.reward)
            steps.append(r.steps)
            durations.append(r.duration_s)

            by_manifest.setdefault(r.manifest, []).append(r)
            by_seed.setdefault(r.seed, []).append(r)

        def _agg(records: list[EpisodeRecord]) -> dict[str, Any]:
            oc: dict[str, int] = {}
            for rec in records:
                oc[rec.outcome] = oc.get(rec.outcome, 0) + 1
            return {
                "count": len(records),
                "outcomes": oc,
                "avg_reward": round(
                    sum(rec.reward for rec in records) / len(records), 4
                ),
                "avg_steps": round(
                    sum(rec.steps for rec in records) / len(records), 2
                ),
            }

        return {
            "total_runs": len(self._results),
            "outcomes": outcomes,
            "avg_reward": round(sum(rewards) / len(rewards), 4),
            "avg_steps": round(sum(steps) / len(steps), 2),
            "avg_duration_s": round(sum(durations) / len(durations), 2),
            "by_manifest": {m: _agg(recs) for m, recs in sorted(by_manifest.items())},
            "by_seed": {s: _agg(recs) for s, recs in sorted(by_seed.items())},
        }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run OpenRange curriculum evaluation matrix",
    )
    parser.add_argument(
        "--manifest",
        nargs="+",
        required=True,
        help="One or more manifest YAML paths",
    )
    parser.add_argument(
        "--seeds",
        default="1-3",
        help="Seed range, e.g. '1-5' or '1,3,7' (default: 1-3)",
    )
    parser.add_argument(
        "--episodes",
        type=int,
        default=1,
        help="Episodes per (manifest, seed) pair (default: 1)",
    )
    parser.add_argument(
        "--max-steps",
        type=int,
        default=100,
        help="Maximum steps per episode (default: 100)",
    )
    parser.add_argument(
        "--output",
        default="results.jsonl",
        help="Output JSONL path (default: results.jsonl)",
    )
    args = parser.parse_args()

    config = RunConfig.from_cli(
        manifests=args.manifest,
        seeds_str=args.seeds,
        episodes=args.episodes,
        max_steps=args.max_steps,
    )

    print(
        f"Curriculum run: {len(config.manifests)} manifests x "
        f"{len(config.seeds)} seeds x {config.episodes_per_seed} episodes "
        f"= {len(config.manifests) * len(config.seeds) * config.episodes_per_seed} total runs"
    )
    print(f"Max steps per episode: {config.max_steps}")
    print(f"Output: {args.output}")
    print()

    # In CLI mode, we need a real environment and agents.
    # For now, report the config and exit -- actual runs require
    # a running environment instance.
    print(
        "Note: CLI mode requires a running environment. "
        "Use CurriculumRunner programmatically with your environment and agents."
    )
    print(f"Config: manifests={config.manifests}, seeds={config.seeds}, "
          f"episodes={config.episodes_per_seed}")
    sys.exit(0)


if __name__ == "__main__":
    main()
