"""Interactive human agent for manual play and debugging.

Prints observations to stdout and reads commands from stdin.
"""

from __future__ import annotations

import sys
from typing import Literal


class HumanAgent:
    """Interactive agent that prompts a human for commands.

    Satisfies the :class:`RangeAgent` protocol.
    """

    def __init__(self, prompt: str = "Enter command > ") -> None:
        self.prompt = prompt
        self.role: str = "red"

    def reset(self, briefing: str, role: Literal["red", "blue"]) -> None:
        """Display role and briefing to the human player."""
        self.role = role
        print(f"\n{'=' * 60}", file=sys.stderr)
        print(f"Role: {role.upper()}", file=sys.stderr)
        print(f"{'=' * 60}", file=sys.stderr)
        print(f"Briefing:\n{briefing}", file=sys.stderr)
        print(f"{'=' * 60}\n", file=sys.stderr)

    def act(self, observation: str) -> str:
        """Print the observation and read a command from stdin."""
        print(f"\n[{self.role.upper()}] Observation:\n{observation}\n", file=sys.stderr)
        try:
            return input(self.prompt).strip()
        except (EOFError, KeyboardInterrupt):
            return "echo quit"
