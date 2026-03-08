"""Tests for the Red & Blue agent layer.

Covers:
- RangeAgent protocol compliance for all agent types
- ScriptedAgent command replay and fallback
- extract_command parsing of various LLM output formats
- run_episode orchestration with a mocked environment
- evaluate harness with multiple episodes
- EpisodeResult and EpisodeMetrics dataclasses
"""

from __future__ import annotations

import pytest

from open_range.agents.protocol import (
    EpisodeMetrics,
    EpisodeResult,
    RangeAgent,
)
from open_range.agents.parsing import extract_command
from open_range.agents.scripted_agent import (
    ScriptedAgent,
    ScriptedBlueAgent,
    ScriptedRedAgent,
)
from open_range.agents.human_agent import HumanAgent
from open_range.agents.llm_agent import LLMRangeAgent
from open_range.agents.prompts import BLUE_SYSTEM_PROMPT, RED_SYSTEM_PROMPT


# ===================================================================
# Protocol compliance
# ===================================================================


class TestProtocolCompliance:
    """All agent implementations satisfy the RangeAgent protocol."""

    def test_scripted_agent_satisfies_protocol(self):
        agent = ScriptedAgent(commands=["echo hi"])
        assert isinstance(agent, RangeAgent)

    def test_scripted_red_agent_satisfies_protocol(self):
        agent = ScriptedRedAgent()
        assert isinstance(agent, RangeAgent)

    def test_scripted_blue_agent_satisfies_protocol(self):
        agent = ScriptedBlueAgent()
        assert isinstance(agent, RangeAgent)

    def test_human_agent_satisfies_protocol(self):
        agent = HumanAgent()
        assert isinstance(agent, RangeAgent)

    def test_llm_agent_satisfies_protocol(self):
        agent = LLMRangeAgent(model="anthropic/claude-sonnet-4-20250514")
        assert isinstance(agent, RangeAgent)

    def test_custom_class_satisfies_protocol(self):
        """A plain class with reset/act methods satisfies the protocol."""

        class MyAgent:
            def reset(self, briefing, role):
                pass

            def act(self, observation):
                return "echo ok"

        assert isinstance(MyAgent(), RangeAgent)

    def test_incomplete_class_fails_protocol(self):
        """A class missing act() does NOT satisfy the protocol."""

        class Incomplete:
            def reset(self, briefing, role):
                pass

        assert not isinstance(Incomplete(), RangeAgent)


# ===================================================================
# ScriptedAgent
# ===================================================================


class TestScriptedAgent:
    """ScriptedAgent replays commands and handles edge cases."""

    def test_replays_commands_in_order(self):
        agent = ScriptedAgent(commands=["cmd1", "cmd2", "cmd3"])
        agent.reset("briefing", "red")
        assert agent.act("obs0") == "cmd1"
        assert agent.act("obs1") == "cmd2"
        assert agent.act("obs2") == "cmd3"

    def test_fallback_after_exhausted(self):
        agent = ScriptedAgent(commands=["cmd1"], fallback="fallback_cmd")
        agent.reset("briefing", "red")
        assert agent.act("obs0") == "cmd1"
        assert agent.act("obs1") == "fallback_cmd"
        assert agent.act("obs2") == "fallback_cmd"

    def test_default_fallback(self):
        agent = ScriptedAgent(commands=[])
        agent.reset("briefing", "blue")
        assert agent.act("obs") == "echo done"

    def test_reset_resets_counter(self):
        agent = ScriptedAgent(commands=["cmd1", "cmd2"])
        agent.reset("b1", "red")
        assert agent.act("obs") == "cmd1"
        agent.reset("b2", "red")
        assert agent.act("obs") == "cmd1"

    def test_role_is_set(self):
        agent = ScriptedAgent(commands=["x"])
        agent.reset("briefing", "blue")
        assert agent.role == "blue"

    def test_scripted_red_has_commands(self):
        agent = ScriptedRedAgent()
        agent.reset("briefing", "red")
        assert agent.act("obs").startswith("nmap")

    def test_scripted_blue_has_commands(self):
        agent = ScriptedBlueAgent()
        agent.reset("briefing", "blue")
        assert agent.act("obs").startswith("grep")


# ===================================================================
# extract_command
# ===================================================================


class TestExtractCommand:
    """extract_command parses various LLM output formats."""

    def test_bare_command(self):
        assert extract_command("nmap -sV 10.0.1.0/24") == "nmap -sV 10.0.1.0/24"

    def test_fenced_code_block_bash(self):
        text = "Here's the command:\n```bash\nnmap -sV 10.0.1.0/24\n```"
        assert extract_command(text) == "nmap -sV 10.0.1.0/24"

    def test_fenced_code_block_no_lang(self):
        text = "```\ncurl http://web/\n```"
        assert extract_command(text) == "curl http://web/"

    def test_single_backtick(self):
        text = "Run `nmap -sV 10.0.1.0/24` to scan"
        assert extract_command(text) == "nmap -sV 10.0.1.0/24"

    def test_command_prefix(self):
        text = "Command: nmap -sV 10.0.1.0/24"
        assert extract_command(text) == "nmap -sV 10.0.1.0/24"

    def test_empty_string(self):
        assert extract_command("") == ""

    def test_multiline_takes_first_command(self):
        text = "nmap -sV 10.0.1.0/24\ncurl http://web/"
        assert extract_command(text) == "nmap -sV 10.0.1.0/24"

    def test_fenced_block_skips_comments(self):
        text = "```bash\n# scan the network\nnmap -sV 10.0.1.0/24\n```"
        assert extract_command(text) == "nmap -sV 10.0.1.0/24"

    def test_submit_flag(self):
        assert extract_command("submit_flag FLAG{test}") == "submit_flag FLAG{test}"

    def test_whitespace_stripped(self):
        assert extract_command("  nmap -sV 10.0.1.0/24  \n") == "nmap -sV 10.0.1.0/24"


# ===================================================================
# LLMRangeAgent (unit tests -- no actual API calls)
# ===================================================================


class TestLLMRangeAgent:
    """LLMRangeAgent initializes correctly (no LLM calls)."""

    def test_default_model(self):
        agent = LLMRangeAgent()
        assert agent.model == "anthropic/claude-sonnet-4-20250514"

    def test_custom_model(self):
        agent = LLMRangeAgent(model="openai/gpt-4o", temperature=0.5)
        assert agent.model == "openai/gpt-4o"
        assert agent.temperature == 0.5

    def test_reset_sets_red_system_prompt(self):
        agent = LLMRangeAgent()
        agent.reset("test briefing", "red")
        assert agent.role == "red"
        assert agent.messages[0]["role"] == "system"
        assert agent.messages[0]["content"] == RED_SYSTEM_PROMPT
        assert agent.messages[1]["content"] == "test briefing"

    def test_reset_sets_blue_system_prompt(self):
        agent = LLMRangeAgent()
        agent.reset("blue briefing", "blue")
        assert agent.role == "blue"
        assert agent.messages[0]["content"] == BLUE_SYSTEM_PROMPT

    def test_extra_kwargs_stored(self):
        agent = LLMRangeAgent(model="test", api_base="http://localhost:8000/v1")
        assert agent.litellm_kwargs["api_base"] == "http://localhost:8000/v1"


# ===================================================================
# HumanAgent
# ===================================================================


class TestHumanAgent:
    """HumanAgent reset/act basics (no actual stdin)."""

    def test_reset_sets_role(self):
        agent = HumanAgent()
        agent.reset("briefing", "red")
        assert agent.role == "red"

    def test_custom_prompt(self):
        agent = HumanAgent(prompt="cmd> ")
        assert agent.prompt == "cmd> "


# ===================================================================
# EpisodeResult and EpisodeMetrics
# ===================================================================


class TestDataclasses:
    """EpisodeResult and EpisodeMetrics dataclasses."""

    def test_episode_result_defaults(self):
        r = EpisodeResult()
        assert r.red_trajectory == []
        assert r.blue_trajectory == []
        assert r.flags_found == []
        assert r.steps == 0
        assert r.outcome == "timeout"

    def test_episode_metrics_defaults(self):
        m = EpisodeMetrics()
        assert m.flag_capture_rate == 0.0
        assert m.steps_to_first_flag is None
        assert m.availability == 1.0

    def test_episode_result_with_data(self):
        r = EpisodeResult(
            flags_found=["FLAG{1}"],
            steps=10,
            outcome="red_win",
            red_model="test/model",
        )
        assert len(r.flags_found) == 1
        assert r.outcome == "red_win"


# ===================================================================
# Episode orchestration (mocked environment)
# ===================================================================


class MockRangeEnvironment:
    """Minimal mock environment for testing run_episode."""

    def __init__(self, max_steps: int = 6):
        from open_range.protocols import FlagSpec, SnapshotSpec, TaskSpec

        self._step_count = 0
        self._max_steps = max_steps
        self._flags_found: list[str] = []
        self._snapshot = SnapshotSpec(
            flags=[
                FlagSpec(id="f1", value="FLAG{test}", path="/flag.txt", host="db"),
            ],
            task=TaskSpec(
                red_briefing="Test red briefing",
                blue_briefing="Test blue briefing",
            ),
        )

    def reset(self, **kwargs):
        from open_range.server.models import RangeObservation

        self._step_count = 0
        self._flags_found = []
        return RangeObservation(stdout="Episode started. Range ready.")

    def step(self, action):
        from open_range.server.models import RangeObservation

        self._step_count += 1

        # Handle flag submission
        if action.command.startswith("submit_flag"):
            flag_val = action.command.split(maxsplit=1)[1] if " " in action.command else ""
            if flag_val == "FLAG{test}":
                self._flags_found.append(flag_val)
                return RangeObservation(
                    stdout=f"Correct! Flag accepted: {flag_val}",
                    done=True,
                    reward=1.0,
                )
            return RangeObservation(
                stdout=f"Invalid flag: {flag_val}",
                reward=-0.3,
            )

        done = self._step_count >= self._max_steps
        return RangeObservation(
            stdout=f"[mock] output for: {action.command}",
            alerts=["scan detected"] if getattr(action, "mode", "") == "red" else [],
            done=done,
            reward=0.0,
        )

    @property
    def state(self):
        """Return a state-like object."""

        class _State:
            pass

        s = _State()
        s.flags_found = list(self._flags_found)
        s.tier = 1
        s.episode_id = "test-episode"
        s.step_count = self._step_count
        return s

    @property
    def snapshot(self):
        return self._snapshot


class TestRunEpisode:
    """run_episode orchestrates Red + Blue turns correctly."""

    def test_basic_episode_runs(self):
        from open_range.agents.episode import run_episode

        red = ScriptedAgent(commands=["nmap -sV 10.0.1.0/24", "curl http://web/", "echo done"])
        blue = ScriptedAgent(commands=["grep attack /var/log/siem/", "check_services"])
        env = MockRangeEnvironment(max_steps=6)

        result = run_episode(env, red, blue, max_steps=6)
        assert isinstance(result, EpisodeResult)
        assert result.steps > 0
        assert result.outcome == "timeout"

    def test_red_wins_with_flag(self):
        from open_range.agents.episode import run_episode

        red = ScriptedAgent(commands=["submit_flag FLAG{test}"])
        blue = ScriptedAgent(commands=["check_services"])
        env = MockRangeEnvironment()

        result = run_episode(env, red, blue, max_steps=50)
        assert result.outcome == "red_win"
        assert "FLAG{test}" in result.flags_found
        assert result.steps == 1  # Red found flag on first step

    def test_trajectories_captured(self):
        from open_range.agents.episode import run_episode

        red = ScriptedAgent(commands=["nmap scan", "curl web"])
        blue = ScriptedAgent(commands=["grep logs"])
        env = MockRangeEnvironment(max_steps=4)

        result = run_episode(env, red, blue, max_steps=4)
        assert len(result.red_trajectory) >= 1
        assert len(result.blue_trajectory) >= 1
        assert "command" in result.red_trajectory[0]
        assert "stdout" in result.red_trajectory[0]
        assert result.blue_trajectory[0]["alerts"] == []

    def test_blue_receives_structured_observation(self):
        from open_range.agents.episode import run_episode

        class CaptureAgent(ScriptedAgent):
            def __init__(self, commands):
                super().__init__(commands=commands)
                self.observations = []

            def act(self, observation):
                self.observations.append(observation)
                return super().act(observation)

        red = ScriptedAgent(commands=["nmap -sV 10.0.1.0/24"])
        blue = CaptureAgent(commands=["grep logs"])
        env = MockRangeEnvironment(max_steps=2)

        run_episode(env, red, blue, max_steps=2)
        assert blue.observations
        assert hasattr(blue.observations[0], "stdout")
        assert blue.observations[0].alerts == ["scan detected"]

    def test_model_names_propagated(self):
        from open_range.agents.episode import run_episode

        red = ScriptedAgent(commands=["echo x"])
        blue = ScriptedAgent(commands=["echo y"])
        env = MockRangeEnvironment(max_steps=2)

        result = run_episode(
            env, red, blue, max_steps=2,
            red_model="test/red", blue_model="test/blue",
        )
        assert result.red_model == "test/red"
        assert result.blue_model == "test/blue"


# ===================================================================
# Evaluation harness
# ===================================================================


class TestEvaluate:
    """evaluate() runs multiple episodes and aggregates metrics."""

    def test_evaluate_returns_metrics(self):
        from open_range.agents.eval import evaluate

        red = ScriptedAgent(commands=["nmap scan", "echo done"])
        blue = ScriptedAgent(commands=["grep logs"])
        env = MockRangeEnvironment(max_steps=4)

        metrics = evaluate(env, red, blue, n_episodes=3, max_steps=4)
        assert metrics["n_episodes"] == 3
        assert "red_solve_rate" in metrics
        assert "blue_detect_rate" in metrics
        assert "avg_steps" in metrics
        assert "outcomes" in metrics
        assert len(metrics["results"]) == 3

    def test_evaluate_with_flag_capture(self):
        from open_range.agents.eval import evaluate

        red = ScriptedAgent(commands=["submit_flag FLAG{test}"])
        blue = ScriptedAgent(commands=["check_services"])
        env = MockRangeEnvironment()

        metrics = evaluate(env, red, blue, n_episodes=2, max_steps=50)
        assert metrics["red_solve_rate"] == 1.0
        assert metrics["outcomes"]["red_win"] == 2


# ===================================================================
# Prompts
# ===================================================================


class TestPrompts:
    """System prompts contain expected content."""

    def test_red_prompt_mentions_penetration(self):
        assert "penetration tester" in RED_SYSTEM_PROMPT

    def test_red_prompt_mentions_submit_flag(self):
        assert "submit_flag" in RED_SYSTEM_PROMPT

    def test_blue_prompt_mentions_soc(self):
        assert "SOC analyst" in BLUE_SYSTEM_PROMPT

    def test_blue_prompt_mentions_submit_finding(self):
        assert "submit_finding" in BLUE_SYSTEM_PROMPT

    def test_prompts_end_with_instruction(self):
        assert "single shell command" in RED_SYSTEM_PROMPT
        assert "single shell command" in BLUE_SYSTEM_PROMPT


# ===================================================================
# resolve_component integration
# ===================================================================


class TestResolveAgents:
    """Agent classes can be loaded via resolve_component."""

    def test_resolve_scripted_agent(self):
        from open_range.resolve import resolve_component

        agent = resolve_component(
            "open_range.agents.scripted_agent.ScriptedAgent",
            {"commands": ["echo test"]},
            RangeAgent,
        )
        assert isinstance(agent, RangeAgent)

    def test_resolve_llm_agent(self):
        from open_range.resolve import resolve_component

        agent = resolve_component(
            "open_range.agents.llm_agent.LLMRangeAgent",
            {"model": "openai/gpt-4o"},
            RangeAgent,
        )
        assert isinstance(agent, RangeAgent)
        assert agent.model == "openai/gpt-4o"

    def test_resolve_human_agent(self):
        from open_range.resolve import resolve_component

        agent = resolve_component(
            "open_range.agents.human_agent.HumanAgent",
            {},
            RangeAgent,
        )
        assert isinstance(agent, RangeAgent)
