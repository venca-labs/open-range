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
from uuid import uuid4

# ---------------------------------------------------------------------------
# System prompts (mirrors docs/red-blue-agents.md)
# ---------------------------------------------------------------------------

RED_SYSTEM_PROMPT = (
    "You are an expert penetration tester conducting an authorized security assessment.\n"
    "Your objective is to recover the exercise flag by systematically exploring the target,\n"
    "validating hypotheses with tools, and only claiming success after you see evidence.\n\n"
    "Available tools:\n"
    "- shell_command: Run a shell command and capture stdout/stderr\n"
    "- read_file: Inspect source code, configs, or challenge artifacts directly\n"
    "- grep: Search files and logs for indicators, credentials, or flag material\n"
    "- file_search: Locate files by name or path fragment\n"
    "- flag_found: Submit a recovered flag immediately\n\n"
    "Work methodically: recon -> enumerate -> inspect -> exploit -> verify."
)

BLUE_SYSTEM_PROMPT = (
    "You are an experienced SOC analyst defending a corporate network.\n"
    "Your objective is to detect attacker activity, validate the evidence in the SIEM,\n"
    "and take measured remediation steps without breaking healthy services.\n\n"
    "Available tools:\n"
    "- shell_command: Run shell commands on the SIEM host and collect output\n"
    "- grep: Search logs for indicators, pivots, or suspicious patterns\n"
    "- read_file: Inspect configurations and aggregated log files directly\n"
    "- patch: Apply a remediation to a specific host or file\n"
    "- check_services: Verify availability after defensive actions\n\n"
    "Work methodically: monitor -> correlate -> confirm -> respond -> verify."
)


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------


@dataclass
class Turn:
    """A single turn within an episode."""

    role: str  # "red" or "blue"
    observation: str  # tool output or environment response after the action
    action: str  # what the agent did
    reward: float  # per-step reward
    assistant_content: str = ""
    tool_name: str = "shell_command"
    tool_arguments: dict[str, Any] = field(default_factory=dict)
    tool_output: str = ""
    tool_call_id: str = ""
    timestamp: float = 0.0

    def __post_init__(self) -> None:
        if self.timestamp == 0.0:
            self.timestamp = time.time()
        if not self.tool_output:
            self.tool_output = self.observation
        if not self.tool_call_id:
            self.tool_call_id = f"call_{uuid4().hex}"


@dataclass
class Episode:
    """A recorded episode with Red and Blue turns."""

    episode_id: str
    snapshot_id: str = ""
    tier: int = 1
    turns: list[Turn] = field(default_factory=list)
    outcome: str = ""  # "flag_captured", "blue_defended", "timeout"
    metrics: dict[str, Any] = field(default_factory=dict)
    briefings: dict[str, str] = field(default_factory=dict)
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

    def to_chat_messages(self, role: str) -> list[dict[str, Any]]:
        """Convert turns for a given role to tool-style chat format."""
        system_prompt = RED_SYSTEM_PROMPT if role == "red" else BLUE_SYSTEM_PROMPT
        messages: list[dict[str, Any]] = [
            {"role": "system", "content": system_prompt},
        ]
        initial_briefing = self.briefings.get(role)
        if not initial_briefing:
            role_turns = [t for t in self.turns if t.role == role]
            initial_briefing = role_turns[0].observation if role_turns else ""
        if initial_briefing:
            messages.append({"role": "user", "content": initial_briefing})

        role_turns = [t for t in self.turns if t.role == role]
        for turn in role_turns:
            messages.append(
                {
                    "role": "assistant",
                    "content": turn.assistant_content,
                    "tool_calls": [
                        {
                            "id": turn.tool_call_id,
                            "type": "function",
                            "function": {
                                "name": turn.tool_name,
                                "arguments": json.dumps(
                                    turn.tool_arguments,
                                    sort_keys=True,
                                ),
                            },
                        }
                    ],
                }
            )
            messages.append(
                {
                    "role": "tool",
                    "content": turn.tool_output,
                    "name": turn.tool_name,
                    "tool_call_id": turn.tool_call_id,
                }
            )

        return messages

    def to_jsonl_record(self, role: str) -> dict[str, Any]:
        """Build a single JSONL record for the given role."""
        reward = self.total_red_reward if role == "red" else self.total_blue_reward
        metadata = {
            "source": self.metrics.get("source", "open_range.synthetic"),
            "success": self.outcome == ("flag_captured" if role == "red" else "blue_defended"),
            "snapshot_id": self.snapshot_id,
            "tier": self.tier,
            "role": role,
        }
        extra_metadata = self.metrics.get("metadata")
        if isinstance(extra_metadata, dict):
            metadata.update(extra_metadata)

        record = {
            "episode_id": self.episode_id,
            "snapshot_id": self.snapshot_id,
            "tier": self.tier,
            "role": role,
            "messages": self.to_chat_messages(role),
            "reward": round(reward, 4),
            "outcome": self.outcome,
            "metadata": metadata,
        }
        ground_truth_flags = self.metrics.get("ground_truth_flags")
        if isinstance(ground_truth_flags, list):
            record["ground_truth_flag"] = ground_truth_flags[0] if ground_truth_flags else None
        else:
            record["ground_truth_flag"] = None
        record["optimal_steps"] = self.metrics.get("optimal_steps")
        return record


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
        briefings: dict[str, str] | None = None,
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
            briefings=dict(briefings or {}),
            started_at=time.time(),
        )
        return self._current

    def log_turn(
        self,
        role: str,
        observation: str,
        action: str,
        reward: float = 0.0,
        *,
        assistant_content: str = "",
        tool_name: str = "shell_command",
        tool_arguments: dict[str, Any] | None = None,
        tool_output: str | None = None,
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
            assistant_content=assistant_content,
            tool_name=tool_name,
            tool_arguments=dict(tool_arguments or {}),
            tool_output=tool_output or observation,
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
        records = self.to_records(reward_threshold=reward_threshold, roles=roles)
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)

        with open(path, "w") as f:
            for record in records:
                f.write(json.dumps(record) + "\n")

        return len(records)

    def to_records(
        self,
        reward_threshold: float = 0.0,
        roles: tuple[str, ...] = ("red", "blue"),
    ) -> list[dict[str, Any]]:
        """Return JSONL-ready records without writing them to disk."""
        records: list[dict[str, Any]] = []
        for episode in self._episodes:
            for role in roles:
                role_turns = [t for t in episode.turns if t.role == role]
                if not role_turns:
                    continue

                total_reward = sum(t.reward for t in role_turns)
                if total_reward < reward_threshold:
                    continue

                records.append(episode.to_jsonl_record(role))
        return records

    def clear(self) -> None:
        """Remove all recorded episodes."""
        self._episodes.clear()
        self._current = None
