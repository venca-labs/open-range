"""RangeAgent protocol and EpisodeResult dataclass.

Follows the same structural subtyping pattern as SnapshotBuilder,
NPCBehavior, and ValidatorCheck in ``open_range.protocols``.  Any object
with matching ``reset`` and ``act`` methods satisfies the protocol --
no base class required.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal, Protocol, runtime_checkable


@runtime_checkable
class RangeAgent(Protocol):
    """Agent that can play Red or Blue in OpenRange.

    This is a structural protocol -- any class with the right method
    signatures satisfies it.  No inheritance needed.
    """

    def reset(self, briefing: str, role: Literal["red", "blue"]) -> None:
        """Initialize agent for a new episode.

        Args:
            briefing: Task description from the snapshot
                      (Red: "Target network with web services..."
                       Blue: "You are SOC analyst for AcmeCorp...")
            role: Which side this agent plays.
        """
        ...

    def act(self, observation: str) -> str:
        """Given an observation, return the next command to execute.

        Args:
            observation: stdout from the previous step, or initial briefing.

        Returns:
            Shell command string (e.g., ``"nmap -sV 10.0.1.0/24"``).
        """
        ...


# ---------------------------------------------------------------------------
# Episode metrics & result
# ---------------------------------------------------------------------------


@dataclass
class EpisodeMetrics:
    """Computed metrics for a single episode."""

    flag_capture_rate: float = 0.0
    steps_to_first_flag: int | None = None
    stealth: float = 0.0
    detection_tp: float = 0.0
    false_positives: float = 0.0
    patch_success_rate: float = 0.0
    availability: float = 1.0


@dataclass
class EpisodeResult:
    """Full result of a single Red + Blue episode."""

    red_trajectory: list[dict] = field(default_factory=list)
    blue_trajectory: list[dict] = field(default_factory=list)
    flags_found: list[str] = field(default_factory=list)
    steps: int = 0
    tier: int = 1
    snapshot_id: str = ""
    red_model: str = ""
    blue_model: str = ""
    outcome: str = "timeout"  # "red_win" | "blue_win" | "timeout"
    metrics: EpisodeMetrics = field(default_factory=EpisodeMetrics)
