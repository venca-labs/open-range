"""Curriculum tracker for OpenRange training.

Tracks per-vuln-class and per-tier solve/detection rates across episodes.
Feeds runtime context to the Builder/Mutator so it can target agent
weaknesses and adjust difficulty.

Example::

    tracker = CurriculumTracker()
    tracker.record_episode(
        snapshot_id="snap-001",
        vuln_classes=["sqli", "weak_creds"],
        red_solved=True,
        blue_detected=False,
        tier=1,
    )
    ctx = tracker.get_build_context()
    # ctx = {
    #     "previous_vuln_classes": ["sqli", "weak_creds"],
    #     "red_solve_rate": 1.0,
    #     "blue_detect_rate": 0.0,
    #     "weak_areas": ["sqli", "weak_creds"],
    #     "recent_attack_surfaces": [...],
    #     "episode_count": 1,
    # }
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any


class CurriculumTracker:
    """Track episode outcomes for curriculum-driven snapshot generation.

    Maintains per-vuln-class and per-tier statistics so the Builder
    can target agent weaknesses and calibrate difficulty.
    """

    def __init__(self, history_window: int = 20) -> None:
        self.history_window = history_window
        self.vuln_stats: dict[str, dict[str, int]] = defaultdict(
            lambda: {"attempts": 0, "red_solves": 0, "blue_detects": 0}
        )
        self.tier_stats: dict[int, dict[str, Any]] = defaultdict(
            lambda: {"episodes": 0, "red_solves": 0, "blue_detects": 0}
        )
        self.episode_history: list[dict[str, Any]] = []

    def record_episode(
        self,
        snapshot_id: str,
        vuln_classes: list[str],
        red_solved: bool,
        blue_detected: bool,
        tier: int = 1,
        attack_surfaces: list[str] | None = None,
        extra: dict[str, Any] | None = None,
    ) -> None:
        """Record the outcome of a completed episode.

        Args:
            snapshot_id: Identifier of the snapshot used.
            vuln_classes: Vulnerability classes planted in the episode.
            red_solved: Whether Red captured a flag.
            blue_detected: Whether Blue detected the attack.
            tier: Difficulty tier of the episode.
            attack_surfaces: Injection points used (e.g. "/search?q=").
            extra: Additional metadata to store.
        """
        record = {
            "snapshot_id": snapshot_id,
            "vuln_classes": vuln_classes,
            "red_solved": red_solved,
            "blue_detected": blue_detected,
            "tier": tier,
            "attack_surfaces": attack_surfaces or [],
            **(extra or {}),
        }
        self.episode_history.append(record)

        # Trim to window
        if len(self.episode_history) > self.history_window * 2:
            self.episode_history = self.episode_history[-self.history_window:]

        # Update per-vuln stats
        for vc in vuln_classes:
            self.vuln_stats[vc]["attempts"] += 1
            if red_solved:
                self.vuln_stats[vc]["red_solves"] += 1
            if blue_detected:
                self.vuln_stats[vc]["blue_detects"] += 1

        # Update per-tier stats
        self.tier_stats[tier]["episodes"] += 1
        if red_solved:
            self.tier_stats[tier]["red_solves"] += 1
        if blue_detected:
            self.tier_stats[tier]["blue_detects"] += 1

    def get_build_context(self) -> dict[str, Any]:
        """Generate runtime context for the Builder/Mutator.

        Returns a dict suitable for passing as ``BuildContext`` fields:
        previous_vuln_classes, red_solve_rate, blue_detect_rate,
        weak_areas, recent_attack_surfaces, episode_count.
        """
        recent = self.episode_history[-self.history_window:]

        # Previous vuln classes (last 5 episodes for diversity enforcement)
        last_5 = self.episode_history[-5:]
        prev_vulns: list[str] = []
        for ep in last_5:
            prev_vulns.extend(ep.get("vuln_classes", []))

        # Overall solve/detect rates over window
        if recent:
            red_solve_rate = sum(1 for e in recent if e["red_solved"]) / len(recent)
            blue_detect_rate = sum(1 for e in recent if e["blue_detected"]) / len(recent)
        else:
            red_solve_rate = 0.0
            blue_detect_rate = 0.0

        # Weak areas: vuln classes where Red solves >80% or Blue detects <20%
        weak_areas: list[str] = []
        for vc, stats in self.vuln_stats.items():
            if stats["attempts"] >= 3:
                solve_rate = stats["red_solves"] / stats["attempts"]
                detect_rate = stats["blue_detects"] / stats["attempts"]
                # Red finds these too easy -- need harder variants
                if solve_rate > 0.8:
                    weak_areas.append(vc)
                # Blue can't detect these -- need more practice
                if detect_rate < 0.2:
                    weak_areas.append(vc)

        # Deduplicate
        weak_areas = list(dict.fromkeys(weak_areas))

        # Recent attack surfaces (last 5 episodes)
        recent_surfaces: list[str] = []
        for ep in last_5:
            recent_surfaces.extend(ep.get("attack_surfaces", []))

        return {
            "previous_vuln_classes": prev_vulns,
            "red_solve_rate": red_solve_rate,
            "blue_detect_rate": blue_detect_rate,
            "weak_areas": weak_areas,
            "recent_attack_surfaces": recent_surfaces,
            "episode_count": len(self.episode_history),
        }

    def should_escalate_tier(self, current_tier: int, threshold: float = 0.8) -> bool:
        """Check if the agent should move to a harder tier.

        Escalation happens when Red solve rate exceeds ``threshold``
        over the history window for the current tier.
        """
        stats = self.tier_stats.get(current_tier)
        if not stats or stats["episodes"] < 5:
            return False
        solve_rate = stats["red_solves"] / stats["episodes"]
        return solve_rate >= threshold

    def get_vuln_solve_rates(self) -> dict[str, float]:
        """Return per-vuln-class solve rates for analysis."""
        rates: dict[str, float] = {}
        for vc, stats in self.vuln_stats.items():
            if stats["attempts"] > 0:
                rates[vc] = stats["red_solves"] / stats["attempts"]
            else:
                rates[vc] = 0.0
        return rates

    def update_from_result(self, result: dict) -> None:
        """Update curriculum stats from an episode result.

        Accepts a dict with the following optional keys:

        - ``snapshot_id`` (str): episode/snapshot identifier
        - ``vuln_classes`` (list[str]): vulnerability classes in the episode
        - ``red_solved`` (bool): whether Red captured a flag
        - ``blue_detected`` (bool): whether Blue detected the attack
        - ``tier`` (int): difficulty tier
        - ``attack_surfaces`` (list[str]): injection points used
        - ``outcome`` (str): episode outcome (``red_win``, ``blue_win``, ``timeout``)
        - ``flags_found`` (list[str]): captured flags
        - ``steps`` (int): total steps taken

        If ``red_solved`` / ``blue_detected`` are not provided they are
        inferred from ``outcome`` and ``flags_found``.
        """
        snapshot_id = result.get("snapshot_id", "")
        vuln_classes = result.get("vuln_classes", [])
        tier = result.get("tier", 1)
        attack_surfaces = result.get("attack_surfaces", [])

        # Infer solve/detect status if not explicitly provided
        if "red_solved" in result:
            red_solved = bool(result["red_solved"])
        else:
            outcome = result.get("outcome", "")
            flags = result.get("flags_found", [])
            red_solved = outcome == "red_win" or bool(flags)

        if "blue_detected" in result:
            blue_detected = bool(result["blue_detected"])
        else:
            blue_detected = result.get("outcome", "") == "blue_win"

        # Collect extra metadata
        extra_keys = {
            "outcome", "flags_found", "steps",
            "red_model", "blue_model",
        }
        extra = {k: result[k] for k in extra_keys if k in result}

        self.record_episode(
            snapshot_id=snapshot_id,
            vuln_classes=vuln_classes,
            red_solved=red_solved,
            blue_detected=blue_detected,
            tier=tier,
            attack_surfaces=attack_surfaces,
            extra=extra if extra else None,
        )
