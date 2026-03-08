"""Tests for the baseline solver suite.

Covers:
- Each solver produces non-empty command lists
- get_solver factory returns correct types
- All solvers implement the RangeAgent protocol
- Running a solver through a mock episode
"""

from __future__ import annotations

import pytest

from open_range.agents.protocol import RangeAgent
from open_range.agents.scripted_agent import ScriptedAgent
from open_range.agents.solvers import (
    BLUE_DEFENSE_COMMANDS,
    TIER1_RED_COMMANDS,
    TIER2_RED_COMMANDS,
    TIER3_RED_COMMANDS,
    BlueSolver,
    Tier1Solver,
    Tier2Solver,
    Tier3Solver,
    get_solver,
)


# ===================================================================
# Command list content
# ===================================================================


class TestCommandLists:
    """Each solver's command list is non-empty and realistic."""

    def test_tier1_commands_non_empty(self):
        assert len(TIER1_RED_COMMANDS) > 0

    def test_tier2_commands_non_empty(self):
        assert len(TIER2_RED_COMMANDS) > 0

    def test_tier3_commands_non_empty(self):
        assert len(TIER3_RED_COMMANDS) > 0

    def test_blue_commands_non_empty(self):
        assert len(BLUE_DEFENSE_COMMANDS) > 0

    def test_tier1_has_nmap(self):
        assert any("nmap" in cmd for cmd in TIER1_RED_COMMANDS)

    def test_tier1_has_sqli(self):
        assert any("UNION" in cmd or "OR 1=1" in cmd for cmd in TIER1_RED_COMMANDS)

    def test_tier1_has_flag_submission(self):
        assert any(cmd.startswith("submit_flag") for cmd in TIER1_RED_COMMANDS)

    def test_tier2_has_nmap(self):
        assert any("nmap" in cmd for cmd in TIER2_RED_COMMANDS)

    def test_tier2_has_credential_pivot(self):
        assert any("psql" in cmd or "mysql" in cmd for cmd in TIER2_RED_COMMANDS)

    def test_tier2_has_flag_submission(self):
        assert any(cmd.startswith("submit_flag") for cmd in TIER2_RED_COMMANDS)

    def test_tier3_has_nmap(self):
        assert any("nmap" in cmd for cmd in TIER3_RED_COMMANDS)

    def test_tier3_has_cicd_recon(self):
        assert any("ci_cd" in cmd or "jenkins" in cmd.lower() for cmd in TIER3_RED_COMMANDS)

    def test_tier3_has_flag_submission(self):
        assert any(cmd.startswith("submit_flag") for cmd in TIER3_RED_COMMANDS)

    def test_blue_has_log_grep(self):
        assert any("grep" in cmd for cmd in BLUE_DEFENSE_COMMANDS)

    def test_blue_has_findings(self):
        assert any(cmd.startswith("submit_finding") for cmd in BLUE_DEFENSE_COMMANDS)

    def test_tier3_longer_than_tier1(self):
        assert len(TIER3_RED_COMMANDS) > len(TIER1_RED_COMMANDS)

    def test_all_commands_are_strings(self):
        for cmd_list in [TIER1_RED_COMMANDS, TIER2_RED_COMMANDS,
                         TIER3_RED_COMMANDS, BLUE_DEFENSE_COMMANDS]:
            for cmd in cmd_list:
                assert isinstance(cmd, str)
                assert len(cmd.strip()) > 0


# ===================================================================
# RangeAgent protocol compliance
# ===================================================================


class TestProtocolCompliance:
    """All solvers satisfy the RangeAgent protocol."""

    def test_tier1_solver_is_range_agent(self):
        assert isinstance(Tier1Solver(), RangeAgent)

    def test_tier2_solver_is_range_agent(self):
        assert isinstance(Tier2Solver(), RangeAgent)

    def test_tier3_solver_is_range_agent(self):
        assert isinstance(Tier3Solver(), RangeAgent)

    def test_blue_solver_is_range_agent(self):
        assert isinstance(BlueSolver(), RangeAgent)

    def test_all_solvers_are_scripted_agents(self):
        for cls in [Tier1Solver, Tier2Solver, Tier3Solver, BlueSolver]:
            assert issubclass(cls, ScriptedAgent)


# ===================================================================
# get_solver factory
# ===================================================================


class TestGetSolver:
    """get_solver returns the correct solver for tier + role."""

    def test_tier1_red(self):
        solver = get_solver(tier=1, role="red")
        assert isinstance(solver, Tier1Solver)

    def test_tier2_red(self):
        solver = get_solver(tier=2, role="red")
        assert isinstance(solver, Tier2Solver)

    def test_tier3_red(self):
        solver = get_solver(tier=3, role="red")
        assert isinstance(solver, Tier3Solver)

    def test_blue_any_tier(self):
        for tier in [1, 2, 3]:
            solver = get_solver(tier=tier, role="blue")
            assert isinstance(solver, BlueSolver)

    def test_invalid_tier_raises(self):
        with pytest.raises(ValueError, match="tier"):
            get_solver(tier=99, role="red")

    def test_invalid_role_raises(self):
        with pytest.raises(ValueError, match="role"):
            get_solver(tier=1, role="purple")


# ===================================================================
# Solver behavior (reset + act)
# ===================================================================


class TestSolverBehavior:
    """Solvers replay their commands correctly."""

    @pytest.mark.parametrize("cls", [Tier1Solver, Tier2Solver, Tier3Solver])
    def test_red_solver_produces_commands(self, cls):
        solver = cls()
        solver.reset("Test briefing", "red")
        # First act should return the first command
        cmd = solver.act("observation")
        assert isinstance(cmd, str)
        assert len(cmd) > 0

    def test_blue_solver_produces_commands(self):
        solver = BlueSolver()
        solver.reset("Test briefing", "blue")
        cmd = solver.act("observation")
        assert isinstance(cmd, str)
        assert len(cmd) > 0

    def test_solver_exhaustion_uses_fallback(self):
        solver = Tier1Solver()
        solver.reset("briefing", "red")
        # Exhaust all commands
        for _ in range(len(TIER1_RED_COMMANDS) + 5):
            cmd = solver.act("obs")
        assert cmd == "echo done"

    def test_blue_solver_fallback(self):
        solver = BlueSolver()
        solver.reset("briefing", "blue")
        for _ in range(len(BLUE_DEFENSE_COMMANDS) + 5):
            cmd = solver.act("obs")
        assert cmd == "check_services"

    def test_reset_restarts_commands(self):
        solver = Tier1Solver()
        solver.reset("b1", "red")
        first_cmd = solver.act("obs")
        solver.reset("b2", "red")
        assert solver.act("obs") == first_cmd


# ===================================================================
# Mock episode integration
# ===================================================================


class TestSolverEpisode:
    """Solvers can run through a mock episode."""

    def _mock_env(self):
        """Return a minimal mock environment."""
        from open_range.protocols import FlagSpec, SnapshotSpec, TaskSpec
        from open_range.server.models import RangeObservation

        class MockEnv:
            def __init__(self):
                self._step_count = 0
                self._flags_found: list[str] = []
                self._snapshot = SnapshotSpec(
                    flags=[
                        FlagSpec(
                            id="f1",
                            value="FLAG{test}",
                            path="/flag.txt",
                            host="db",
                        ),
                    ],
                    task=TaskSpec(
                        red_briefing="Test red briefing",
                        blue_briefing="Test blue briefing",
                    ),
                )

            def reset(self, **kwargs):
                self._step_count = 0
                self._flags_found = []
                return RangeObservation(stdout="Episode started.")

            def step(self, action):
                self._step_count += 1
                done = self._step_count >= 10
                if action.command.startswith("submit_flag"):
                    flag = action.command.split(maxsplit=1)[-1]
                    if flag == "FLAG{test}":
                        self._flags_found.append(flag)
                        return RangeObservation(
                            stdout=f"Correct! Flag accepted: {flag}",
                            done=True,
                            reward=1.0,
                        )
                return RangeObservation(
                    stdout=f"[mock] {action.command}",
                    done=done,
                    reward=0.0,
                )

            @property
            def state(self):
                class _S:
                    pass
                s = _S()
                s.flags_found = list(self._flags_found)
                s.tier = 1
                s.episode_id = "test"
                s.step_count = self._step_count
                return s

            @property
            def snapshot(self):
                return self._snapshot

        return MockEnv()

    def test_tier1_solver_runs_episode(self):
        from open_range.agents.episode import run_episode
        from open_range.agents.protocol import EpisodeResult

        env = self._mock_env()
        red = Tier1Solver()
        blue = BlueSolver()

        result = run_episode(env, red, blue, max_steps=10)
        assert isinstance(result, EpisodeResult)
        assert result.steps > 0
        assert len(result.red_trajectory) > 0
        assert len(result.blue_trajectory) > 0

    def test_tier2_solver_runs_episode(self):
        from open_range.agents.episode import run_episode
        from open_range.agents.protocol import EpisodeResult

        env = self._mock_env()
        red = Tier2Solver()
        blue = BlueSolver()

        result = run_episode(env, red, blue, max_steps=10)
        assert isinstance(result, EpisodeResult)
        assert result.steps > 0

    def test_tier3_solver_runs_episode(self):
        from open_range.agents.episode import run_episode
        from open_range.agents.protocol import EpisodeResult

        env = self._mock_env()
        red = Tier3Solver()
        blue = BlueSolver()

        result = run_episode(env, red, blue, max_steps=10)
        assert isinstance(result, EpisodeResult)
        assert result.steps > 0
