"""Trajectory logging for SFT warm-start data generation.

Records Red and Blue agent trajectories during episodes and exports
them as JSONL in OpenAI chat format for supervised fine-tuning.

Usage::

    logger = TrajectoryLogger()
    logger.start_episode("ep-001", snapshot_id="snap-001", tier=1)
    logger.log_turn(role="red", observation="Range ready...", action="nmap -sV web", reward=0.1)
    logger.log_turn(role="blue", observation="[IDS] scan detected", action="submit_finding nmap scan", reward=0.2)
    logger.end_episode(outcome="flag_captured", metrics={"steps": 5, "flags": 1})
    logger.export_jsonl("trajectories.jsonl", reward_threshold=0.5)
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# System prompts (mirrors docs/red-blue-agents.md)
# ---------------------------------------------------------------------------

RED_SYSTEM_PROMPT = (
    "You are a penetration tester conducting an authorized security assessment. "
    "You have access to a Kali Linux workstation on an external network. "
    "Your goal is to identify vulnerabilities, exploit them, and capture flags.\n\n"
    "Available actions:\n"
    "- Run any command on your attacker workstation (nmap, curl, sqlmap, ssh, etc.)\n"
    "- submit_flag <flag_string> -- submit a captured flag for verification\n"
    "- submit_evidence <json> -- document your findings\n\n"
    "Respond with a single shell command to execute."
)

BLUE_SYSTEM_PROMPT = (
    "You are a SOC analyst defending a corporate network. "
    "You have access to the SIEM console on the management network. "
    "Your goal is to detect attacks, investigate incidents, and remediate vulnerabilities.\n\n"
    "Available actions:\n"
    "- Query logs: grep, tail, awk on /var/log/siem/\n"
    "- submit_finding <description> -- report a detected attack\n"
    "- patch <host> <file> -- apply a security patch\n"
    "- iptables rules -- modify firewall\n"
    "- check_services -- verify all services are running\n\n"
    "Respond with a single shell command to execute."
)


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------


@dataclass
class Turn:
    """A single turn within an episode."""

    role: str  # "red" or "blue"
    observation: str  # what the agent saw
    action: str  # what the agent did
    reward: float  # per-step reward
    timestamp: float = 0.0

    def __post_init__(self) -> None:
        if self.timestamp == 0.0:
            self.timestamp = time.time()


@dataclass
class Episode:
    """A recorded episode with Red and Blue turns."""

    episode_id: str
    snapshot_id: str = ""
    tier: int = 1
    turns: list[Turn] = field(default_factory=list)
    outcome: str = ""  # "flag_captured", "blue_defended", "timeout"
    metrics: dict[str, Any] = field(default_factory=dict)
    started_at: float = 0.0
    ended_at: float = 0.0

    @property
    def red_turns(self) -> list[Turn]:
        """All turns by Red."""
        return [t for t in self.turns if t.role == "red"]

    @property
    def blue_turns(self) -> list[Turn]:
        """All turns by Blue."""
        return [t for t in self.turns if t.role == "blue"]

    @property
    def total_red_reward(self) -> float:
        """Sum of rewards for Red turns."""
        return sum(t.reward for t in self.red_turns)

    @property
    def total_blue_reward(self) -> float:
        """Sum of rewards for Blue turns."""
        return sum(t.reward for t in self.blue_turns)

    def to_chat_messages(self, role: str) -> list[dict[str, str]]:
        """Convert turns for a given role to OpenAI chat format.

        Each agent's trajectory is an independent training example:
        - system: role-specific system prompt
        - user: observation (environment output)
        - assistant: action (agent command)

        Interleaving is preserved: the agent's observations include
        the environment's responses to both its own and the opponent's
        actions (since they share infrastructure).
        """
        system_prompt = RED_SYSTEM_PROMPT if role == "red" else BLUE_SYSTEM_PROMPT
        messages: list[dict[str, str]] = [
            {"role": "system", "content": system_prompt},
        ]

        role_turns = [t for t in self.turns if t.role == role]
        for turn in role_turns:
            messages.append({"role": "user", "content": turn.observation})
            messages.append({"role": "assistant", "content": turn.action})

        return messages

    def to_jsonl_record(self, role: str) -> dict[str, Any]:
        """Build a single JSONL record for the given role."""
        reward = self.total_red_reward if role == "red" else self.total_blue_reward
        return {
            "episode_id": self.episode_id,
            "snapshot_id": self.snapshot_id,
            "tier": self.tier,
            "role": role,
            "messages": self.to_chat_messages(role),
            "reward": round(reward, 4),
            "outcome": self.outcome,
        }


# ---------------------------------------------------------------------------
# Logger
# ---------------------------------------------------------------------------


class TrajectoryLogger:
    """Records episode trajectories and exports them for SFT.

    Manages a collection of episodes. Each episode can contain turns
    from both Red and Blue agents. On export, Red and Blue trajectories
    are written as separate JSONL lines (independent training examples).
    """

    def __init__(self) -> None:
        self._episodes: list[Episode] = []
        self._current: Episode | None = None

    @property
    def episodes(self) -> list[Episode]:
        """All recorded episodes (completed only)."""
        return list(self._episodes)

    @property
    def current_episode(self) -> Episode | None:
        """The episode currently being recorded, if any."""
        return self._current

    def start_episode(
        self,
        episode_id: str,
        snapshot_id: str = "",
        tier: int = 1,
    ) -> Episode:
        """Begin recording a new episode.

        If a previous episode was not ended, it is finalized with
        outcome="abandoned" before starting the new one.

        Args:
            episode_id: Unique identifier for this episode.
            snapshot_id: Identifier of the snapshot being used.
            tier: Difficulty tier of the episode.

        Returns:
            The newly created Episode.
        """
        if self._current is not None:
            self.end_episode(outcome="abandoned")

        self._current = Episode(
            episode_id=episode_id,
            snapshot_id=snapshot_id,
            tier=tier,
            started_at=time.time(),
        )
        return self._current

    def log_turn(
        self,
        role: str,
        observation: str,
        action: str,
        reward: float = 0.0,
    ) -> Turn:
        """Record a single turn in the current episode.

        Args:
            role: "red" or "blue".
            observation: What the agent observed (stdout from env).
            action: The command the agent chose.
            reward: Per-step reward.

        Returns:
            The recorded Turn.

        Raises:
            RuntimeError: If no episode is active.
        """
        if self._current is None:
            raise RuntimeError(
                "No active episode. Call start_episode() first."
            )

        turn = Turn(
            role=role,
            observation=observation,
            action=action,
            reward=reward,
        )
        self._current.turns.append(turn)
        return turn

    def end_episode(
        self,
        outcome: str = "",
        metrics: dict[str, Any] | None = None,
    ) -> Episode:
        """Finalize the current episode.

        Args:
            outcome: Episode result (e.g. "flag_captured", "timeout").
            metrics: Optional metrics dict to attach.

        Returns:
            The finalized Episode.

        Raises:
            RuntimeError: If no episode is active.
        """
        if self._current is None:
            raise RuntimeError(
                "No active episode. Call start_episode() first."
            )

        self._current.outcome = outcome
        self._current.metrics = metrics or {}
        self._current.ended_at = time.time()

        episode = self._current
        self._episodes.append(episode)
        self._current = None
        return episode

    def export_jsonl(
        self,
        path: str | Path,
        reward_threshold: float = 0.0,
        roles: tuple[str, ...] = ("red", "blue"),
    ) -> int:
        """Write trajectories to a JSONL file for SFT training.

        Each episode produces one line per role (Red and Blue are
        independent training examples). Only episodes where the agent's
        total reward exceeds ``reward_threshold`` are included.

        Args:
            path: Output file path.
            reward_threshold: Minimum total reward for inclusion.
                Episodes below this threshold are filtered out.
            roles: Which roles to export. Default: both.

        Returns:
            Number of JSONL lines written.
        """
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)

        count = 0
        with open(path, "w") as f:
            for episode in self._episodes:
                for role in roles:
                    # Check if this role had any turns
                    role_turns = [t for t in episode.turns if t.role == role]
                    if not role_turns:
                        continue

                    # Filter by reward threshold
                    total_reward = sum(t.reward for t in role_turns)
                    if total_reward < reward_threshold:
                        continue

                    record = episode.to_jsonl_record(role)
                    f.write(json.dumps(record) + "\n")
                    count += 1

        return count

    def clear(self) -> None:
        """Remove all recorded episodes."""
        self._episodes.clear()
        self._current = None
