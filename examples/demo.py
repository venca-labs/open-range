"""End-to-end scripted demo of OpenRange episode lifecycle.

Demonstrates:
    1. Environment reset with a snapshot
    2. Red agent: recon -> exploit -> flag capture
    3. Blue agent: log analysis -> detection -> patching
    4. Reward computation for both roles
    5. Trajectory logging for SFT export

Runs without Docker (uses mock mode) and without any LLM.

Usage::

    python -m examples.demo
    # or
    uv run python examples/demo.py
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

from open_range.protocols import (
    FlagSpec,
    GoldenPathStep,
    SnapshotSpec,
    TaskSpec,
    TruthGraph,
    Vulnerability,
)
from open_range.server.environment import RangeEnvironment
from open_range.server.models import RangeAction, RangeObservation
from open_range.training.trajectory import TrajectoryLogger


# ---------------------------------------------------------------------------
# Scripted agents
# ---------------------------------------------------------------------------


class ScriptedAgent:
    """Agent that follows a fixed command list. No LLM needed."""

    def __init__(self, script: list[str], role: str = "red") -> None:
        self.script = list(script)
        self.role = role
        self._step_idx = 0

    def reset(self, briefing: str, role: str) -> None:
        self.role = role
        self._step_idx = 0

    def act(self, observation: str) -> str:
        if self._step_idx < len(self.script):
            cmd = self.script[self._step_idx]
            self._step_idx += 1
            return cmd
        return "echo done"

    @property
    def exhausted(self) -> bool:
        return self._step_idx >= len(self.script)


# ---------------------------------------------------------------------------
# Demo snapshot (matches tier1_basic topology)
# ---------------------------------------------------------------------------


def make_demo_snapshot() -> SnapshotSpec:
    """Build a demo snapshot with a SQL injection vulnerability."""
    return SnapshotSpec(
        topology={
            "hosts": [
                "attacker", "firewall", "web", "mail",
                "db", "files", "ldap", "siem",
            ],
            "zones": {
                "external": ["attacker"],
                "dmz": ["web", "mail"],
                "internal": ["db", "files"],
                "management": ["ldap", "siem"],
            },
            "tier": 1,
        },
        truth_graph=TruthGraph(
            vulns=[
                Vulnerability(
                    id="vuln-sqli-1",
                    type="sqli",
                    host="web",
                    service="php",
                    injection_point="/search?q=",
                    vulnerable_code=(
                        "$conn->query(\"SELECT * FROM products "
                        "WHERE name LIKE '%$_GET[q]%'\");"
                    ),
                    root_cause="Unsanitized input in SQL query",
                    blast_radius="Full database read access",
                    remediation="Use parameterized queries",
                ),
            ],
        ),
        flags=[
            FlagSpec(
                id="flag-1",
                value="FLAG{test_sqli_123}",
                path="/var/flags/flag1.txt",
                host="db",
            ),
        ],
        golden_path=[
            GoldenPathStep(step=1, command="nmap -sV 10.0.1.0/24",
                           expect_in_stdout="80/tcp open http",
                           description="Port scan reveals web server"),
            GoldenPathStep(step=2, command="curl http://web/",
                           expect_in_stdout="Welcome",
                           description="Enumerate web application"),
            GoldenPathStep(step=3, command="curl 'http://web/search?q=test'",
                           expect_in_stdout="products",
                           description="Test search functionality"),
            GoldenPathStep(step=4,
                           command="curl 'http://web/search?q=test' UNION SELECT flag FROM flags--'",
                           expect_in_stdout="FLAG{test_sqli_123}",
                           description="Exploit SQL injection"),
            GoldenPathStep(step=5, command="submit_flag FLAG{test_sqli_123}",
                           expect_in_stdout="Correct",
                           description="Submit captured flag"),
        ],
        task=TaskSpec(
            red_briefing=(
                "Target network has a web application with database backend. "
                "Find vulnerabilities and capture the flag."
            ),
            blue_briefing=(
                "Monitor SIEM for suspicious activity. "
                "Investigate alerts, identify attacks, and apply patches."
            ),
        ),
    )


# ---------------------------------------------------------------------------
# Episode runner
# ---------------------------------------------------------------------------


def run_demo(
    env: RangeEnvironment | None = None,
    max_steps: int = 20,
    quiet: bool = False,
) -> dict[str, Any]:
    """Run a complete demo episode with scripted Red and Blue agents.

    Args:
        env: Optional pre-configured environment. If None, creates one
             in mock mode (no Docker required).
        max_steps: Maximum steps before forced termination.
        quiet: If True, suppress printed output.

    Returns:
        Dict with episode results and trajectory logger.
    """
    if env is None:
        env = RangeEnvironment(docker_available=False, max_steps=max_steps)

    snapshot = make_demo_snapshot()

    # Build scripted agents
    red = ScriptedAgent(
        script=[
            "nmap -sV 10.0.1.0/24",
            "curl http://web/",
            "curl 'http://web/search?q=test'",
            "curl 'http://web/search?q=test%27+UNION+SELECT+flag+FROM+flags--'",
            "submit_flag FLAG{test_sqli_123}",
        ],
        role="red",
    )

    blue = ScriptedAgent(
        script=[
            "tail -n 50 /var/log/siem/web_access.log",
            "grep -i 'union' /var/log/siem/web_access.log",
            "submit_finding SQLi attack detected from attacker targeting /search endpoint",
            "patch web /var/www/html/search.php",
        ],
        role="blue",
    )

    # Trajectory logger
    traj = TrajectoryLogger()

    def _print(msg: str) -> None:
        if not quiet:
            print(msg)

    # --- Episode start ---
    _print("=" * 60)
    _print("  OPENRANGE DEMO -- Scripted Red vs Blue Episode")
    _print("=" * 60)

    obs = env.reset(snapshot=snapshot, episode_id="demo-001")
    traj.start_episode(
        episode_id="demo-001",
        snapshot_id="tier1-sqli-demo",
        tier=1,
    )

    red.reset(briefing=obs.stdout, role="red")
    blue.reset(briefing=obs.stdout, role="blue")

    _print(f"\n{obs.stdout}\n")
    _print("-" * 60)

    step = 0
    last_obs = obs

    while not last_obs.done and step < max_steps:
        # Red's turn
        if red.exhausted:
            break

        red_cmd = red.act(last_obs.stdout)
        _print(f"\n[Step {step + 1}] RED >> {red_cmd}")
        red_obs = env.step(RangeAction(command=red_cmd, mode="red"))
        reward = red_obs.reward if red_obs.reward is not None else 0.0

        traj.log_turn(
            role="red",
            observation=last_obs.stdout,
            action=red_cmd,
            reward=float(reward),
        )

        _print(f"         stdout: {red_obs.stdout[:120]}{'...' if len(red_obs.stdout) > 120 else ''}")
        if red_obs.flags_captured:
            _print(f"         FLAGS CAPTURED: {red_obs.flags_captured}")
        _print(f"         reward: {reward:.4f}  done: {red_obs.done}")

        last_obs = red_obs
        step += 1

        if last_obs.done:
            break

        # Blue's turn
        if blue.exhausted:
            continue

        blue_cmd = blue.act(last_obs.stdout)
        _print(f"\n[Step {step + 1}] BLUE >> {blue_cmd}")
        blue_obs = env.step(RangeAction(command=blue_cmd, mode="blue"))
        reward = blue_obs.reward if blue_obs.reward is not None else 0.0

        traj.log_turn(
            role="blue",
            observation=last_obs.stdout,
            action=blue_cmd,
            reward=float(reward),
        )

        _print(f"          stdout: {blue_obs.stdout[:120]}{'...' if len(blue_obs.stdout) > 120 else ''}")
        if blue_obs.alerts:
            _print(f"          alerts: {blue_obs.alerts}")
        _print(f"          reward: {reward:.4f}  done: {blue_obs.done}")

        last_obs = blue_obs
        step += 1

    # Determine outcome
    if env.state.flags_found:
        outcome = "flag_captured"
    elif step >= max_steps:
        outcome = "timeout"
    else:
        outcome = "completed"

    episode = traj.end_episode(
        outcome=outcome,
        metrics={
            "steps": step,
            "flags_found": list(env.state.flags_found),
            "tier": env.state.tier,
        },
    )

    # --- Summary ---
    _print("\n" + "=" * 60)
    _print("  EPISODE SUMMARY")
    _print("=" * 60)
    _print(f"  Outcome:          {outcome}")
    _print(f"  Steps:            {step}")
    _print(f"  Flags found:      {env.state.flags_found}")
    _print(f"  Red total reward: {episode.total_red_reward:.4f}")
    _print(f"  Blue total reward:{episode.total_blue_reward:.4f}")
    _print(f"  Red turns:        {len(episode.red_turns)}")
    _print(f"  Blue turns:       {len(episode.blue_turns)}")
    _print("=" * 60)

    return {
        "outcome": outcome,
        "steps": step,
        "flags_found": list(env.state.flags_found),
        "episode": episode,
        "trajectory_logger": traj,
        "env": env,
    }


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> None:
    """Run the demo and optionally export trajectories."""
    result = run_demo()

    # Export trajectories to JSONL
    traj: TrajectoryLogger = result["trajectory_logger"]
    out_path = Path("demo_trajectories.jsonl")
    count = traj.export_jsonl(out_path, reward_threshold=0.0)
    print(f"\nExported {count} trajectory records to {out_path}")


if __name__ == "__main__":
    main()
