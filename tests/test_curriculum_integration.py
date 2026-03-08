"""Tests for curriculum feedback wiring (#34).

Verifies that CurriculumTracker.update_from_result() works correctly
and that run_episode() feeds results into the tracker.
"""

import pytest

from open_range.training.curriculum import CurriculumTracker


class TestUpdateFromResult:
    """CurriculumTracker.update_from_result() parses episode results."""

    def test_basic_update(self):
        tracker = CurriculumTracker()
        tracker.update_from_result({
            "snapshot_id": "snap-001",
            "vuln_classes": ["sqli", "xss"],
            "red_solved": True,
            "blue_detected": False,
            "tier": 1,
        })
        assert len(tracker.episode_history) == 1
        assert tracker.vuln_stats["sqli"]["attempts"] == 1
        assert tracker.vuln_stats["sqli"]["red_solves"] == 1
        assert tracker.vuln_stats["xss"]["blue_detects"] == 0

    def test_infer_red_solved_from_outcome(self):
        tracker = CurriculumTracker()
        tracker.update_from_result({
            "snapshot_id": "snap-002",
            "vuln_classes": ["sqli"],
            "outcome": "red_win",
            "tier": 1,
        })
        assert tracker.episode_history[-1]["red_solved"] is True

    def test_infer_red_solved_from_flags(self):
        tracker = CurriculumTracker()
        tracker.update_from_result({
            "snapshot_id": "snap-003",
            "vuln_classes": ["idor"],
            "flags_found": ["FLAG{gotcha}"],
            "tier": 2,
        })
        assert tracker.episode_history[-1]["red_solved"] is True

    def test_infer_blue_detected_from_outcome(self):
        tracker = CurriculumTracker()
        tracker.update_from_result({
            "snapshot_id": "snap-004",
            "vuln_classes": ["xss"],
            "outcome": "blue_win",
            "tier": 1,
        })
        assert tracker.episode_history[-1]["blue_detected"] is True

    def test_timeout_outcome(self):
        tracker = CurriculumTracker()
        tracker.update_from_result({
            "snapshot_id": "snap-005",
            "vuln_classes": ["ssrf"],
            "outcome": "timeout",
            "tier": 1,
        })
        ep = tracker.episode_history[-1]
        assert ep["red_solved"] is False
        assert ep["blue_detected"] is False

    def test_explicit_flags_override_inference(self):
        tracker = CurriculumTracker()
        tracker.update_from_result({
            "snapshot_id": "snap-006",
            "vuln_classes": ["sqli"],
            "red_solved": False,
            "blue_detected": True,
            "outcome": "red_win",  # Would infer True, but explicit False wins
            "tier": 1,
        })
        ep = tracker.episode_history[-1]
        assert ep["red_solved"] is False
        assert ep["blue_detected"] is True

    def test_extra_metadata_passed_through(self):
        tracker = CurriculumTracker()
        tracker.update_from_result({
            "snapshot_id": "snap-007",
            "vuln_classes": ["weak_creds"],
            "red_solved": True,
            "blue_detected": False,
            "tier": 1,
            "steps": 42,
            "outcome": "red_win",
            "red_model": "gpt-4",
            "blue_model": "llama-3",
        })
        ep = tracker.episode_history[-1]
        assert ep.get("steps") == 42
        assert ep.get("outcome") == "red_win"

    def test_empty_result_defaults(self):
        tracker = CurriculumTracker()
        tracker.update_from_result({})
        assert len(tracker.episode_history) == 1
        ep = tracker.episode_history[-1]
        assert ep["red_solved"] is False
        assert ep["blue_detected"] is False
        assert ep["tier"] == 1


class TestCurriculumStatsUpdate:
    """Verify that update_from_result correctly updates aggregate stats."""

    def test_vuln_stats_accumulate(self):
        tracker = CurriculumTracker()
        for i in range(5):
            tracker.update_from_result({
                "snapshot_id": f"snap-{i}",
                "vuln_classes": ["sqli"],
                "red_solved": i % 2 == 0,  # solved on 0, 2, 4
                "blue_detected": i % 3 == 0,  # detected on 0, 3
                "tier": 1,
            })
        assert tracker.vuln_stats["sqli"]["attempts"] == 5
        assert tracker.vuln_stats["sqli"]["red_solves"] == 3
        assert tracker.vuln_stats["sqli"]["blue_detects"] == 2

    def test_tier_stats_accumulate(self):
        tracker = CurriculumTracker()
        tracker.update_from_result({
            "snapshot_id": "a",
            "vuln_classes": ["sqli"],
            "red_solved": True,
            "blue_detected": False,
            "tier": 2,
        })
        tracker.update_from_result({
            "snapshot_id": "b",
            "vuln_classes": ["xss"],
            "red_solved": False,
            "blue_detected": True,
            "tier": 2,
        })
        assert tracker.tier_stats[2]["episodes"] == 2
        assert tracker.tier_stats[2]["red_solves"] == 1
        assert tracker.tier_stats[2]["blue_detects"] == 1

    def test_build_context_after_updates(self):
        tracker = CurriculumTracker()
        for i in range(3):
            tracker.update_from_result({
                "snapshot_id": f"s{i}",
                "vuln_classes": ["sqli"],
                "red_solved": True,
                "blue_detected": False,
                "tier": 1,
            })
        ctx = tracker.get_build_context()
        assert ctx["episode_count"] == 3
        assert ctx["red_solve_rate"] == 1.0
        assert ctx["blue_detect_rate"] == 0.0
        assert "sqli" in ctx["previous_vuln_classes"]

    def test_attack_surfaces_passed(self):
        tracker = CurriculumTracker()
        tracker.update_from_result({
            "snapshot_id": "s1",
            "vuln_classes": ["sqli"],
            "red_solved": True,
            "blue_detected": False,
            "tier": 1,
            "attack_surfaces": ["/search?q="],
        })
        ctx = tracker.get_build_context()
        assert "/search?q=" in ctx["recent_attack_surfaces"]


class TestRunEpisodeCurriculumWiring:
    """run_episode() calls curriculum.update_from_result() when provided."""

    def test_run_episode_updates_curriculum(self):
        from open_range.protocols import (
            FlagSpec,
            SnapshotSpec,
            TaskSpec,
            TruthGraph,
            Vulnerability,
        )
        from open_range.server.environment import RangeEnvironment
        from open_range.agents.episode import run_episode

        class ScriptedAgent:
            """Minimal agent that runs a fixed script."""

            def __init__(self, commands):
                self._commands = list(commands)
                self._idx = 0

            def reset(self, briefing, role):
                self._idx = 0

            def act(self, observation):
                if self._idx < len(self._commands):
                    cmd = self._commands[self._idx]
                    self._idx += 1
                    return cmd
                return "noop"

        env = RangeEnvironment(docker_available=False, max_steps=4)
        snapshot = SnapshotSpec(
            topology={
                "hosts": ["attacker", "web"],
                "tier": 1,
            },
            flags=[FlagSpec(id="f1", value="FLAG{x}", path="/f.txt", host="web")],
            golden_path=[],
            truth_graph=TruthGraph(
                vulns=[Vulnerability(id="v1", type="sqli", host="web")],
            ),
            task=TaskSpec(red_briefing="Go.", blue_briefing="Watch."),
        )
        env.reset(snapshot=snapshot)
        # Patch _select_snapshot to always return our snapshot
        env._select_snapshot = lambda **kw: snapshot

        red = ScriptedAgent(["submit_flag FLAG{x}", "noop"])
        blue = ScriptedAgent(["submit_finding attack found", "noop"])

        tracker = CurriculumTracker()
        result = run_episode(env, red, blue, max_steps=4, curriculum=tracker)

        assert len(tracker.episode_history) == 1
        ep = tracker.episode_history[0]
        assert ep["red_solved"] is True  # flag was captured -> red_win
        assert "sqli" in ep["vuln_classes"]

    def test_run_episode_without_curriculum(self):
        """run_episode still works when no curriculum is provided."""
        from open_range.protocols import SnapshotSpec, TaskSpec
        from open_range.server.environment import RangeEnvironment
        from open_range.agents.episode import run_episode

        class NoopAgent:
            def reset(self, briefing, role):
                pass

            def act(self, observation):
                return "noop"

        env = RangeEnvironment(docker_available=False, max_steps=2)
        snapshot = SnapshotSpec(
            topology={"hosts": ["attacker", "siem"]},
            flags=[],
            golden_path=[],
            task=TaskSpec(red_briefing="Test.", blue_briefing="Test."),
        )
        env._select_snapshot = lambda **kw: snapshot
        result = run_episode(env, NoopAgent(), NoopAgent(), max_steps=2)
        assert result.outcome in ("red_win", "blue_win", "timeout")
