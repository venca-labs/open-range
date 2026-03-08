"""Deterministic replay agents for testing, baselines, and demos.

No LLM is required. These agents replay a fixed list of commands and provide
lightweight reasoning text so synthetic trajectory export can still emit
tool-style transcripts.
"""

from __future__ import annotations

import shlex
from typing import Any, Literal


class ScriptedAgent:
    """Replays a fixed list of commands in order."""

    def __init__(
        self,
        commands: list[str] | None = None,
        fallback: str = "echo done",
    ) -> None:
        self.commands = list(commands) if commands else []
        self.fallback = fallback
        self._step_idx = 0
        self.role: str = "red"
        self.last_response_text: str = ""
        self.last_command: str = ""

    def reset(self, briefing: str, role: Literal["red", "blue"]) -> None:
        """Reset the step counter for a new episode."""
        del briefing
        self._step_idx = 0
        self.role = role
        self.last_response_text = ""
        self.last_command = ""

    def act(self, observation: Any) -> str:
        """Return the next scripted command."""
        del observation
        if self._step_idx < len(self.commands):
            cmd = self.commands[self._step_idx]
            self._step_idx += 1
        else:
            cmd = self.fallback

        self.last_command = cmd
        self.last_response_text = self._render_response(cmd)
        return cmd

    def _render_response(self, command: str) -> str:
        thought = _default_reasoning(command, role=self.role)
        return f"<think>\n{thought}\n</think>\nCommand: {command}"


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


def _default_reasoning(command: str, *, role: str) -> str:
    lowered = command.lower()
    try:
        parts = shlex.split(command)
    except ValueError:
        parts = command.split()

    first_path = next((part for part in parts[1:] if "/" in part and not part.startswith("http")), "")
    if "nmap" in lowered:
        return "I need a quick service inventory before probing any likely attack paths."
    if "curl" in lowered and ("union" in lowered or "select" in lowered):
        return "The search endpoint is a good candidate for SQL injection, so I will test a UNION-style payload."
    if "curl" in lowered:
        return "I should inspect the exposed web surface to identify routes, parameters, and authentication flows."
    if "mysql" in lowered:
        return "I appear to have database access, so I will enumerate data stores and look for the flag-bearing table."
    if lowered.startswith("cat ") and first_path:
        return f"I need to inspect {first_path} directly for credentials, source code, or other embedded clues."
    if lowered.startswith("grep "):
        if role == "blue":
            return "I need to filter the SIEM logs for indicators that confirm the suspected attack path."
        return "I should search the available files for indicators, credentials, or flag material."
    if lowered.startswith("find "):
        return "I need a broader file inventory before I decide which artifact to inspect next."
    if lowered.startswith("submit_flag "):
        return "The recovered token looks promising, so I will submit it for validation now."
    if lowered.startswith("submit_finding "):
        return "The observed activity is strong enough to report as a concrete finding."
    if lowered.startswith("patch "):
        return "I have enough evidence to apply a targeted remediation for the vulnerable path."
    if "check_services" in lowered:
        return "Before changing anything else, I should confirm the core services are still healthy."
    return "I will take the next concrete step that reduces uncertainty and moves the objective forward."
