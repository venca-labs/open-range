"""Tests for RangeEnvironment lifecycle — all run without Docker."""

import pytest

from open_range.protocols import (
    FlagSpec,
    GoldenPathStep,
    SnapshotSpec,
    TaskSpec,
    TruthGraph,
    Vulnerability,
)
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


# -------------------------------------------------------------------
# Task engine (#17)
# -------------------------------------------------------------------


def _make_multistep_snapshot():
    """Helper: snapshot with a multi_step task and milestones."""
    return SnapshotSpec(
        topology={
            "hosts": ["attacker", "web", "db"],
            "users": [
                {"username": "admin", "password": "admin123", "hosts": ["web", "db"]},
            ],
        },
        flags=[FlagSpec(id="f1", value="FLAG{ms}", path="/f.txt", host="db")],
        golden_path=[],
        task=TaskSpec(
            red_briefing="Multi-step challenge.",
            blue_briefing="Watch.",
            task_type="multi_step",
            milestones=["port scan complete", "credentials found", "database accessed"],
        ),
    )


class TestTaskEngine:
    """Milestone checking for multi_step tasks (#17)."""

    def test_milestone_detected_in_output(self):
        env = RangeEnvironment(docker_available=False)
        snapshot = _make_multistep_snapshot()
        env.reset(snapshot=snapshot)

        # Mock mode returns "[mock] executed on attacker: ..." which won't match.
        # We need to check that _check_milestone works with the right output.
        ms = env._check_milestone("Port scan complete -- found open ports")
        assert ms == "port scan complete"

    def test_milestone_not_duplicated(self):
        env = RangeEnvironment(docker_available=False)
        snapshot = _make_multistep_snapshot()
        env.reset(snapshot=snapshot)

        # Simulate first milestone completion
        env._state.milestones_completed.append("port scan complete")
        ms = env._check_milestone("Port scan complete again")
        assert ms is None  # Already completed

    def test_milestone_returns_none_for_exploit_task(self):
        env = RangeEnvironment(docker_available=False)
        snapshot = SnapshotSpec(
            topology={"hosts": ["attacker", "web"]},
            flags=[],
            golden_path=[],
            task=TaskSpec(red_briefing="Go.", blue_briefing="Watch.", task_type="exploit"),
        )
        env.reset(snapshot=snapshot)
        ms = env._check_milestone("anything here")
        assert ms is None

    def test_milestone_returns_none_for_no_match(self):
        env = RangeEnvironment(docker_available=False)
        snapshot = _make_multistep_snapshot()
        env.reset(snapshot=snapshot)
        ms = env._check_milestone("nothing relevant here")
        assert ms is None

    def test_milestones_tracked_in_state(self):
        env = RangeEnvironment(docker_available=False)
        snapshot = _make_multistep_snapshot()
        env.reset(snapshot=snapshot)
        assert env.state.milestones_completed == []

        # Manually add a milestone (simulating what step() does)
        env._state.milestones_completed.append("port scan complete")
        assert env.state.milestones_completed == ["port scan complete"]

    def test_task_type_field_on_task_spec(self):
        ts = TaskSpec(task_type="multi_step", milestones=["a", "b"])
        assert ts.task_type == "multi_step"
        assert ts.milestones == ["a", "b"]

    def test_success_conditions_on_task_spec(self):
        ts = TaskSpec(
            success_conditions=[
                {"type": "flag", "value": "FLAG{x}"},
                {"type": "endpoint", "url": "/api/data", "expect": "secret"},
            ],
        )
        assert len(ts.success_conditions) == 2
        assert ts.success_conditions[0]["type"] == "flag"


# -------------------------------------------------------------------
# Auth scenario (#25)
# -------------------------------------------------------------------


def _make_auth_snapshot():
    """Helper: snapshot with users for auth testing."""
    return SnapshotSpec(
        topology={
            "hosts": ["attacker", "web", "db"],
            "users": [
                {"username": "admin", "password": "admin123", "hosts": ["web", "db"]},
                {"username": "guest", "password": "guest", "hosts": ["web"]},
            ],
        },
        flags=[FlagSpec(id="f1", value="FLAG{auth}", path="/f.txt", host="db")],
        golden_path=[],
        task=TaskSpec(red_briefing="Auth challenge.", blue_briefing="Watch."),
    )


class TestAuthScenario:
    """Auth and logout commands update session tracking (#25)."""

    def test_auth_success(self):
        env = RangeEnvironment(docker_available=False)
        env.reset(snapshot=_make_auth_snapshot())
        obs = env.step(RangeAction(command="auth web admin admin123", mode="red"))
        assert "Authenticated" in obs.stdout
        assert env.state.active_sessions["web"] == "admin"

    def test_auth_failure(self):
        env = RangeEnvironment(docker_available=False)
        env.reset(snapshot=_make_auth_snapshot())
        obs = env.step(RangeAction(command="auth web admin wrongpass", mode="red"))
        assert "failed" in obs.stderr.lower()
        assert "web" not in env.state.active_sessions

    def test_auth_wrong_host(self):
        env = RangeEnvironment(docker_available=False)
        env.reset(snapshot=_make_auth_snapshot())
        obs = env.step(RangeAction(command="auth db guest guest", mode="red"))
        # guest only has access to web, not db
        assert "failed" in obs.stderr.lower()
        assert "db" not in env.state.active_sessions

    def test_auth_attempt_logged(self):
        env = RangeEnvironment(docker_available=False)
        env.reset(snapshot=_make_auth_snapshot())
        env.step(RangeAction(command="auth web admin admin123", mode="red"))
        assert len(env.state.auth_attempts) == 1
        assert env.state.auth_attempts[0]["success"] is True

    def test_auth_failure_logged(self):
        env = RangeEnvironment(docker_available=False)
        env.reset(snapshot=_make_auth_snapshot())
        env.step(RangeAction(command="auth web admin wrong", mode="red"))
        assert len(env.state.auth_attempts) == 1
        assert env.state.auth_attempts[0]["success"] is False

    def test_logout_success(self):
        env = RangeEnvironment(docker_available=False)
        env.reset(snapshot=_make_auth_snapshot())
        env.step(RangeAction(command="auth web admin admin123", mode="red"))
        assert "web" in env.state.active_sessions
        obs = env.step(RangeAction(command="logout web", mode="red"))
        assert "Logged out" in obs.stdout
        assert "web" not in env.state.active_sessions

    def test_logout_no_session(self):
        env = RangeEnvironment(docker_available=False)
        env.reset(snapshot=_make_auth_snapshot())
        obs = env.step(RangeAction(command="logout web", mode="red"))
        assert "No active session" in obs.stderr

    def test_auth_missing_args(self):
        env = RangeEnvironment(docker_available=False)
        env.reset(snapshot=_make_auth_snapshot())
        obs = env.step(RangeAction(command="auth web admin", mode="red"))
        assert "Usage" in obs.stderr

    def test_logout_missing_args(self):
        env = RangeEnvironment(docker_available=False)
        env.reset(snapshot=_make_auth_snapshot())
        obs = env.step(RangeAction(command="logout", mode="red"))
        assert "Usage" in obs.stderr

    def test_auth_creates_access_grant(self):
        env = RangeEnvironment(docker_available=False)
        env.reset(snapshot=_make_auth_snapshot())
        env.step(RangeAction(command="auth web admin admin123", mode="red"))
        assert "web:shell" in env.state.access_grants


# -------------------------------------------------------------------
# Pivot mechanics (#26)
# -------------------------------------------------------------------


class TestPivotMechanics:
    """Access grants and pivot tracking (#26)."""

    def test_pivot_detected_from_credential_leak(self):
        """When command output contains credentials matching the truth graph,
        access_grants and pivot_history are updated."""
        env = RangeEnvironment(docker_available=False)
        snapshot = SnapshotSpec(
            topology={
                "hosts": ["attacker", "web", "db"],
                "users": [
                    {"username": "dbadmin", "password": "s3cret!", "hosts": ["db"]},
                ],
            },
            flags=[],
            golden_path=[],
            task=TaskSpec(red_briefing="Go.", blue_briefing="Watch."),
        )
        env.reset(snapshot=snapshot)

        # Simulate checking pivot on command output that contains credentials
        env._check_pivot(
            RangeAction(command="cat /etc/app/config.ini", mode="red"),
            "db_user = dbadmin\ndb_pass = s3cret!\nhost = db",
        )
        assert "db:credential" in env.state.access_grants
        assert len(env.state.pivot_history) == 1
        assert env.state.pivot_history[0]["to"] == "db"
        assert env.state.pivot_history[0]["via"] == "credential_reuse"

    def test_no_pivot_without_matching_creds(self):
        env = RangeEnvironment(docker_available=False)
        snapshot = SnapshotSpec(
            topology={
                "hosts": ["attacker", "web"],
                "users": [
                    {"username": "admin", "password": "secret", "hosts": ["web"]},
                ],
            },
            flags=[],
            golden_path=[],
            task=TaskSpec(red_briefing="Go.", blue_briefing="Watch."),
        )
        env.reset(snapshot=snapshot)
        env._check_pivot(
            RangeAction(command="ls", mode="red"),
            "no credentials here",
        )
        assert env.state.access_grants == []
        assert env.state.pivot_history == []

    def test_pivot_not_duplicated(self):
        env = RangeEnvironment(docker_available=False)
        snapshot = SnapshotSpec(
            topology={
                "hosts": ["attacker", "web", "db"],
                "users": [
                    {"username": "admin", "password": "pass", "hosts": ["db"]},
                ],
            },
            flags=[],
            golden_path=[],
            task=TaskSpec(red_briefing="Go.", blue_briefing="Watch."),
        )
        env.reset(snapshot=snapshot)
        action = RangeAction(command="cat config", mode="red")
        env._check_pivot(action, "admin pass db")
        env._check_pivot(action, "admin pass db")
        # Should only appear once
        assert env.state.access_grants.count("db:credential") == 1

    def test_state_has_access_grants_field(self):
        state = RangeState()
        assert state.access_grants == []
        assert state.pivot_history == []

    def test_state_has_auth_fields(self):
        state = RangeState()
        assert state.active_sessions == {}
        assert state.auth_attempts == []
        assert state.milestones_completed == []
