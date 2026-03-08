"""Tests for the curriculum runner (issue #23)."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest

from open_range.training.runner import (
    CurriculumRunner,
    EpisodeRecord,
    RunConfig,
    _parse_seed_range,
)


# ---------------------------------------------------------------------------
# Mock environment and agents
# ---------------------------------------------------------------------------


@dataclass
class _MockObs:
    stdout: str = "Range ready."
    stderr: str = ""
    done: bool = False
    reward: float = 0.0


@dataclass
class _MockState:
    flags_found: list[str] = field(default_factory=list)
    episode_id: str = "mock-ep"
    tier: int = 1
    step_count: int = 0


class MockEnvironment:
    """Minimal environment that ends after a configurable number of steps."""

    def __init__(self, max_env_steps: int = 4, flags: list[str] | None = None):
        self._max_env_steps = max_env_steps
        self._flags = flags or []
        self._step_count = 0
        self._state = _MockState()
        self.reset_calls: list[dict[str, Any]] = []

    def reset(self, seed: int | None = None, **kwargs: Any) -> _MockObs:
        self._step_count = 0
        self._state = _MockState()
        self.reset_calls.append({"seed": seed, **kwargs})
        return _MockObs(stdout=f"Range ready. Seed={seed}")

    def step(self, action: Any) -> _MockObs:
        self._step_count += 1
        done = self._step_count >= self._max_env_steps
        if done and self._flags:
            self._state.flags_found = list(self._flags)
        return _MockObs(
            stdout=f"Step {self._step_count} result",
            done=done,
            reward=0.1,
        )

    @property
    def state(self) -> _MockState:
        return self._state


class MockAgent:
    """Minimal agent that returns fixed commands."""

    def __init__(self, commands: list[str] | None = None):
        self._commands = commands or ["nmap -sV web"]
        self._idx = 0

    def reset(self, briefing: str, role: str) -> None:
        self._idx = 0

    def act(self, observation: str) -> str:
        cmd = self._commands[self._idx % len(self._commands)]
        self._idx += 1
        return cmd


# ---------------------------------------------------------------------------
# Tests: seed range parsing
# ---------------------------------------------------------------------------


class TestSeedParsing:
    def test_range(self):
        assert _parse_seed_range("1-5") == [1, 2, 3, 4, 5]

    def test_single(self):
        assert _parse_seed_range("3") == [3]

    def test_comma_separated(self):
        assert _parse_seed_range("1,3,5") == [1, 3, 5]

    def test_mixed(self):
        assert _parse_seed_range("1-3,7,10-12") == [1, 2, 3, 7, 10, 11, 12]


# ---------------------------------------------------------------------------
# Tests: RunConfig
# ---------------------------------------------------------------------------


class TestRunConfig:
    def test_from_cli(self):
        config = RunConfig.from_cli(
            manifests=["tier1.yaml"],
            seeds_str="1-3",
            episodes=2,
            max_steps=50,
        )
        assert config.manifests == ["tier1.yaml"]
        assert config.seeds == [1, 2, 3]
        assert config.episodes_per_seed == 2
        assert config.max_steps == 50


# ---------------------------------------------------------------------------
# Tests: CurriculumRunner
# ---------------------------------------------------------------------------


class TestCurriculumRunner:
    def test_run_returns_results(self):
        env = MockEnvironment(max_env_steps=4)
        red = MockAgent()
        blue = MockAgent(commands=["tail /var/log/syslog"])
        config = RunConfig(
            manifests=["tier1.yaml"],
            seeds=[1, 2],
            episodes_per_seed=1,
            max_steps=100,
        )
        runner = CurriculumRunner(env, red, blue, config)
        results = runner.run()
        # 1 manifest x 2 seeds x 1 episode = 2 runs
        assert len(results) == 2
        assert all(isinstance(r, EpisodeRecord) for r in results)

    def test_results_have_correct_seeds(self):
        env = MockEnvironment(max_env_steps=2)
        red = MockAgent()
        blue = MockAgent()
        config = RunConfig(
            manifests=["m.yaml"],
            seeds=[10, 20],
            episodes_per_seed=1,
        )
        runner = CurriculumRunner(env, red, blue, config)
        results = runner.run()
        assert {r.seed for r in results} == {10, 20}

    def test_results_have_correct_manifests(self):
        env = MockEnvironment(max_env_steps=2)
        red = MockAgent()
        blue = MockAgent()
        config = RunConfig(
            manifests=["a.yaml", "b.yaml"],
            seeds=[1],
            episodes_per_seed=1,
        )
        runner = CurriculumRunner(env, red, blue, config)
        results = runner.run()
        assert {r.manifest for r in results} == {"a.yaml", "b.yaml"}

    def test_flag_capture_outcome(self):
        env = MockEnvironment(max_env_steps=2, flags=["FLAG{test}"])
        red = MockAgent()
        blue = MockAgent()
        config = RunConfig(
            manifests=["m.yaml"],
            seeds=[1],
            episodes_per_seed=1,
        )
        runner = CurriculumRunner(env, red, blue, config)
        results = runner.run()
        assert results[0].outcome == "flag_captured"
        assert results[0].flags_found == ["FLAG{test}"]

    def test_timeout_outcome(self):
        env = MockEnvironment(max_env_steps=9999)  # never ends
        red = MockAgent()
        blue = MockAgent()
        config = RunConfig(
            manifests=["m.yaml"],
            seeds=[1],
            episodes_per_seed=1,
            max_steps=4,
        )
        runner = CurriculumRunner(env, red, blue, config)
        results = runner.run()
        assert results[0].outcome == "timeout"
        assert results[0].steps == 4

    def test_multiple_episodes_per_seed(self):
        env = MockEnvironment(max_env_steps=2)
        red = MockAgent()
        blue = MockAgent()
        config = RunConfig(
            manifests=["m.yaml"],
            seeds=[1],
            episodes_per_seed=3,
        )
        runner = CurriculumRunner(env, red, blue, config)
        results = runner.run()
        assert len(results) == 3
        assert all(r.episode in (1, 2, 3) for r in results)

    def test_manifest_axis_is_passed_to_reset_with_snapshot(self):
        root = Path(__file__).resolve().parent.parent
        manifests = [
            str(root / "manifests" / "tier1_basic.yaml"),
            str(root / "manifests" / "tier2_corporate.yaml"),
        ]
        env = MockEnvironment(max_env_steps=1)
        red = MockAgent()
        blue = MockAgent()
        config = RunConfig(
            manifests=manifests,
            seeds=[7],
            episodes_per_seed=1,
            max_steps=1,
        )
        runner = CurriculumRunner(env, red, blue, config)
        runner.run()

        assert len(env.reset_calls) == 2
        assert env.reset_calls[0]["manifest_path"].endswith("tier1_basic.yaml")
        assert env.reset_calls[1]["manifest_path"].endswith("tier2_corporate.yaml")
        assert env.reset_calls[0]["snapshot"].topology["tier"] == 1
        assert env.reset_calls[1]["snapshot"].topology["tier"] == 2


# ---------------------------------------------------------------------------
# Tests: results collection
# ---------------------------------------------------------------------------


class TestResultsCollection:
    def test_save_and_load(self, tmp_path):
        env = MockEnvironment(max_env_steps=2)
        red = MockAgent()
        blue = MockAgent()
        config = RunConfig(
            manifests=["m.yaml"],
            seeds=[1, 2],
            episodes_per_seed=1,
        )
        runner = CurriculumRunner(env, red, blue, config)
        runner.run()

        output_path = tmp_path / "results.jsonl"
        count = runner.save_results(output_path)
        assert count == 2

        # Verify JSONL is loadable
        with open(output_path) as f:
            lines = [json.loads(line) for line in f if line.strip()]
        assert len(lines) == 2
        assert lines[0]["seed"] == 1
        assert lines[1]["seed"] == 2

    def test_results_summary(self):
        env = MockEnvironment(max_env_steps=2, flags=["FLAG{x}"])
        red = MockAgent()
        blue = MockAgent()
        config = RunConfig(
            manifests=["a.yaml", "b.yaml"],
            seeds=[1, 2],
            episodes_per_seed=1,
        )
        runner = CurriculumRunner(env, red, blue, config)
        runner.run()

        summary = runner.results_summary()
        assert summary["total_runs"] == 4
        assert "flag_captured" in summary["outcomes"]
        assert summary["avg_reward"] > 0
        assert "a.yaml" in summary["by_manifest"]
        assert "b.yaml" in summary["by_manifest"]
        assert 1 in summary["by_seed"]
        assert 2 in summary["by_seed"]

    def test_empty_results_summary(self):
        env = MockEnvironment()
        red = MockAgent()
        blue = MockAgent()
        config = RunConfig(manifests=[], seeds=[], episodes_per_seed=1)
        runner = CurriculumRunner(env, red, blue, config)
        summary = runner.results_summary()
        assert summary["total_runs"] == 0
        assert summary["avg_reward"] == 0.0

    def test_episode_record_to_dict(self):
        record = EpisodeRecord(
            manifest="m.yaml",
            seed=42,
            episode=1,
            outcome="flag_captured",
            steps=5,
            flags_found=["FLAG{x}"],
            reward=1.5,
            duration_s=3.14,
            metadata={"extra": "info"},
        )
        d = record.to_dict()
        assert d["manifest"] == "m.yaml"
        assert d["seed"] == 42
        assert d["outcome"] == "flag_captured"
        assert d["extra"] == "info"
