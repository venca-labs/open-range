"""Tests for RangeEnvironment lifecycle — all run without Docker."""

import pytest

from open_range.protocols import FlagSpec, GoldenPathStep, SnapshotSpec, TaskSpec, TruthGraph
from open_range.server.environment import RangeEnvironment, _extract_command_name
from open_range.server.models import RangeAction, RangeObservation, RangeState


class TestCommandExtraction:
    """Helper: extracting base command name from full command strings."""

    def test_simple(self):
        assert _extract_command_name("nmap -sV web") == "nmap"

    def test_with_path(self):
        assert _extract_command_name("/usr/bin/nmap -sV web") == "nmap"

    def test_piped(self):
        assert _extract_command_name("curl http://web | grep flag") == "curl"

    def test_empty(self):
        assert _extract_command_name("") == ""


class TestReset:
    """reset() returns a RangeObservation with briefing."""

    def test_reset_returns_observation(self):
        env = RangeEnvironment(docker_available=False)
        obs = env.reset()
        assert isinstance(obs, RangeObservation)
        assert "Range ready" in obs.stdout

    def test_reset_sets_episode_id(self):
        env = RangeEnvironment(docker_available=False)
        env.reset(episode_id="ep_42")
        assert env.state.episode_id == "ep_42"

    def test_reset_clears_step_count(self):
        env = RangeEnvironment(docker_available=False)
        env.reset()
        env.step(RangeAction(command="nmap -sV web", mode="red"))
        assert env.state.step_count == 1
        env.reset()
        assert env.state.step_count == 0

    def test_reset_with_snapshot(self, sample_snapshot_spec):
        env = RangeEnvironment(docker_available=False)
        obs = env.reset(snapshot=sample_snapshot_spec)
        assert isinstance(obs, RangeObservation)
        assert env.snapshot is not None


class TestRedStep:
    """Red agent actions."""

    def test_red_step_returns_observation(self):
        env = RangeEnvironment(docker_available=False)
        env.reset()
        action = RangeAction(command="nmap -sV web", mode="red")
        obs = env.step(action)
        assert isinstance(obs, RangeObservation)

    def test_red_step_increments_counter(self):
        env = RangeEnvironment(docker_available=False)
        env.reset()
        env.step(RangeAction(command="nmap -sV web", mode="red"))
        assert env.state.step_count == 1
        env.step(RangeAction(command="curl http://web", mode="red"))
        assert env.state.step_count == 2

    def test_red_any_command_forwarded(self):
        """No artificial allowlist — commands route to the attacker container."""
        env = RangeEnvironment(docker_available=False)
        env.reset()
        obs = env.step(RangeAction(command="iptables -L", mode="red"))
        # In mock mode, this runs on attacker container (not rejected)
        assert obs.stderr == ""
        assert "attacker" in obs.stdout  # mock output includes container name

    def test_red_action_logged(self):
        env = RangeEnvironment(docker_available=False)
        env.reset()
        env.step(RangeAction(command="nmap -sV web", mode="red"))
        assert len(env.red_history) >= 1


class TestBlueStep:
    """Blue agent actions."""

    def test_blue_step_returns_observation(self):
        env = RangeEnvironment(docker_available=False)
        env.reset()
        obs = env.step(RangeAction(command="tail_log /var/log/syslog", mode="blue"))
        assert isinstance(obs, RangeObservation)

    def test_blue_submit_finding(self):
        env = RangeEnvironment(docker_available=False)
        env.reset()
        obs = env.step(RangeAction(command="submit_finding SQL injection detected", mode="blue"))
        assert "recorded" in obs.stdout.lower() or "submitted" in obs.stdout.lower()

    def test_blue_any_command_forwarded(self):
        """No artificial allowlist — commands route to the siem container."""
        env = RangeEnvironment(docker_available=False)
        env.reset()
        obs = env.step(RangeAction(command="nmap -sV web", mode="blue"))
        # In mock mode, this runs on siem container (not rejected)
        assert obs.stderr == ""
        assert "siem" in obs.stdout  # mock output includes container name

    def test_blue_empty_command_rejected(self):
        env = RangeEnvironment(docker_available=False)
        env.reset()
        obs = env.step(RangeAction(command="", mode="blue"))
        assert obs.stderr != ""


class TestFlagSubmission:
    """Flag submission triggers correct rewards."""

    def test_correct_flag_accepted(self):
        env = RangeEnvironment(docker_available=False)
        snapshot = SnapshotSpec(
            topology={"hosts": ["attacker", "web"]},
            flags=[FlagSpec(id="f1", value="FLAG{correct}", path="/f.txt", host="web")],
            golden_path=[],
            task=TaskSpec(red_briefing="Go.", blue_briefing="Watch."),
        )
        env.reset(snapshot=snapshot)
        obs = env.step(RangeAction(command="submit_flag FLAG{correct}", mode="red"))
        assert "FLAG{correct}" in env.state.flags_found
        assert "Correct" in obs.stdout or "correct" in obs.stdout.lower()

    def test_hallucinated_flag_rejected(self):
        env = RangeEnvironment(docker_available=False)
        snapshot = SnapshotSpec(
            topology={"hosts": ["attacker", "web"]},
            flags=[FlagSpec(id="f1", value="FLAG{real}", path="/f.txt", host="web")],
            golden_path=[],
            task=TaskSpec(red_briefing="Go.", blue_briefing="Watch."),
        )
        env.reset(snapshot=snapshot)
        obs = env.step(RangeAction(command="submit_flag FLAG{fake}", mode="red"))
        assert "FLAG{fake}" not in env.state.flags_found
        assert "invalid" in obs.stdout.lower() or "Invalid" in obs.stdout

    def test_all_flags_ends_episode(self):
        env = RangeEnvironment(docker_available=False)
        snapshot = SnapshotSpec(
            topology={"hosts": ["attacker", "web"]},
            flags=[FlagSpec(id="f1", value="FLAG{a}", path="/f.txt", host="web")],
            golden_path=[],
            task=TaskSpec(red_briefing="Go.", blue_briefing="Watch."),
        )
        env.reset(snapshot=snapshot)
        obs = env.step(RangeAction(command="submit_flag FLAG{a}", mode="red"))
        assert obs.done is True


class TestTermination:
    """Environment terminates at max_steps."""

    def test_max_steps_terminates(self):
        env = RangeEnvironment(docker_available=False, max_steps=3)
        env.reset()
        env.step(RangeAction(command="nmap -sV web", mode="red"))
        env.step(RangeAction(command="curl http://web", mode="red"))
        obs = env.step(RangeAction(command="curl http://web/login", mode="red"))
        assert obs.done is True


class TestStateProperty:
    """state property returns current RangeState."""

    def test_state_reflects_episode(self):
        env = RangeEnvironment(docker_available=False)
        env.reset(episode_id="test_ep")
        assert env.state.episode_id == "test_ep"
        assert env.state.step_count == 0
        env.step(RangeAction(command="nmap -sV web", mode="red"))
        assert env.state.step_count == 1
