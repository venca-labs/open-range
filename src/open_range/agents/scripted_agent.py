"""Scripted agents for testing and demos.

No LLM required -- these agents replay a fixed list of commands.
Useful for integration tests, golden-path verification, and hackathon demos.
"""

from __future__ import annotations

from typing import Literal


class ScriptedAgent:
    """Replays a fixed list of commands in order.

    After the list is exhausted, repeats the last command (or a configurable
    fallback) so the episode can terminate normally.

    Satisfies the :class:`RangeAgent` protocol.
    """

    def __init__(
        self,
        commands: list[str] | None = None,
        fallback: str = "echo done",
    ) -> None:
        self.commands = list(commands) if commands else []
        self.fallback = fallback
        self._step_idx = 0
        self.role: str = "red"

    def reset(self, briefing: str, role: Literal["red", "blue"]) -> None:
        """Reset the step counter for a new episode."""
        self._step_idx = 0
        self.role = role

    def act(self, observation: str) -> str:
        """Return the next scripted command."""
        if self._step_idx < len(self.commands):
            cmd = self.commands[self._step_idx]
            self._step_idx += 1
            return cmd
        return self.fallback


# ---------------------------------------------------------------------------
# Pre-built demo agents
# ---------------------------------------------------------------------------

DEMO_RED_SCRIPT = [
    "nmap -sV 10.0.1.0/24",
    "curl http://web/",
    "curl http://web/api/users/1/profile",
    "curl http://web/api/users/2/profile",
    "curl http://web/api/users/3/profile",
    "mysql -h db -u svc_backup -pbackup123 -e 'SELECT * FROM flags.secrets'",
    "submit_flag FLAG{idor_chain_2_db}",
]

DEMO_BLUE_SCRIPT = [
    "grep -rn 'UNION' /var/log/siem/",
    "grep -rn '10.0.0.100' /var/log/siem/web_access.log",
    "submit_finding SQLi attempt from 10.0.0.100 targeting /search endpoint",
    "check_services",
]


class ScriptedRedAgent(ScriptedAgent):
    """Pre-built Red agent with a demo attack sequence."""

    def __init__(self) -> None:
        super().__init__(commands=DEMO_RED_SCRIPT, fallback="submit_flag done")


class ScriptedBlueAgent(ScriptedAgent):
    """Pre-built Blue agent with a demo defense sequence."""

    def __init__(self) -> None:
        super().__init__(commands=DEMO_BLUE_SCRIPT, fallback="check_services")
