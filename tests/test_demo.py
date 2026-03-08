"""Tests for the end-to-end scripted demo."""

import json
from pathlib import Path

import pytest

from examples.demo import (
    ScriptedAgent,
    make_demo_snapshot,
    run_demo,
)
from open_range.server.environment import RangeEnvironment
from open_range.server.models import RangeAction


# ---------------------------------------------------------------------------
# ScriptedAgent
# ---------------------------------------------------------------------------


class TestScriptedAgent:
    def test_follows_script(self):
        agent = ScriptedAgent(["cmd1", "cmd2", "cmd3"])
        assert agent.act("obs") == "cmd1"
        assert agent.act("obs") == "cmd2"
        assert agent.act("obs") == "cmd3"

    def test_exhausted(self):
        agent = ScriptedAgent(["cmd1"])
        assert not agent.exhausted
        agent.act("obs")
        assert agent.exhausted

    def test_fallback_after_exhausted(self):
        agent = ScriptedAgent(["cmd1"])
        agent.act("obs")
        assert agent.act("obs") == "echo done"

    def test_reset(self):
        agent = ScriptedAgent(["cmd1", "cmd2"])
        agent.act("obs")
        agent.reset(briefing="new episode", role="red")
        assert agent.act("obs") == "cmd1"
        assert not agent.exhausted


# ---------------------------------------------------------------------------
# Demo snapshot
# ---------------------------------------------------------------------------


class TestDemoSnapshot:
    def test_snapshot_has_flags(self):
        snap = make_demo_snapshot()
        assert len(snap.flags) == 1
        assert snap.flags[0].value == "FLAG{test_sqli_123}"

    def test_snapshot_has_golden_path(self):
        snap = make_demo_snapshot()
        assert len(snap.golden_path) >= 3

    def test_snapshot_has_vulnerability(self):
        snap = make_demo_snapshot()
        assert len(snap.truth_graph.vulns) == 1
        assert snap.truth_graph.vulns[0].type == "sqli"

    def test_snapshot_has_task(self):
        snap = make_demo_snapshot()
        assert snap.task.red_briefing
        assert snap.task.blue_briefing


# ---------------------------------------------------------------------------
# Full demo run (mocked, no Docker)
# ---------------------------------------------------------------------------


class TestRunDemo:
    def test_demo_completes(self):
        result = run_demo(quiet=True)
        assert result["outcome"] in ("flag_captured", "timeout", "completed")
        assert result["steps"] > 0

    def test_demo_captures_flag(self):
        result = run_demo(quiet=True)
        assert "FLAG{test_sqli_123}" in result["flags_found"]
        assert result["outcome"] == "flag_captured"

    def test_demo_produces_trajectories(self):
        result = run_demo(quiet=True)
        episode = result["episode"]
        assert len(episode.red_turns) > 0
        assert len(episode.blue_turns) > 0

    def test_demo_trajectory_export(self, tmp_path: Path):
        result = run_demo(quiet=True)
        traj = result["trajectory_logger"]
        out = tmp_path / "demo.jsonl"
        count = traj.export_jsonl(out)
        assert count >= 2  # at least red + blue
        lines = out.read_text().strip().split("\n")
        for line in lines:
            record = json.loads(line)
            assert record["episode_id"] == "demo-001"
            assert record["messages"][0]["role"] == "system"

    def test_demo_with_custom_env(self):
        env = RangeEnvironment(docker_available=False, max_steps=50)
        result = run_demo(env=env, quiet=True)
        assert result["outcome"] == "flag_captured"

    def test_demo_rewards_are_numeric(self):
        result = run_demo(quiet=True)
        episode = result["episode"]
        for turn in episode.turns:
            assert isinstance(turn.reward, (int, float))

    def test_demo_red_and_blue_alternate(self):
        """Verify Red and Blue take alternating turns."""
        result = run_demo(quiet=True)
        episode = result["episode"]
        # The first turn should be Red
        assert episode.turns[0].role == "red"
        # After the first Red turn, turns should alternate (with some
        # flexibility since Red might finish before Blue exhausts)
        for i in range(1, min(len(episode.turns), 8)):
            # Alternation pattern: even index = red, odd = blue
            # (within the interleaved portion)
            expected = "blue" if i % 2 == 1 else "red"
            assert episode.turns[i].role == expected, (
                f"Turn {i}: expected {expected}, got {episode.turns[i].role}"
            )
