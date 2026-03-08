"""Reward components for OpenRange Red and Blue operators.

All rewards are grounded in verifiable container state -- flags via docker exec,
patches via re-running golden path steps, detection via logged actions.

Each individual reward class exposes a simple ``score()`` method with explicit
arguments (no hidden state). The composite classes aggregate components and
also expose a ``compute()`` method that accepts the environment's full context
tuple ``(action, observation, state, snapshot, ctx)`` so the Environment can
call rewards uniformly.

Tier multipliers: {1: 1.0, 2: 1.5, 3: 2.0, 4: 2.5, 5: 3.0}
"""

from __future__ import annotations

import logging
from typing import Any

from open_range.protocols import SnapshotSpec

from open_range.server.models import RangeAction, RangeObservation, RangeState

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Tier multipliers
# ---------------------------------------------------------------------------

TIER_MULTIPLIERS: dict[int, float] = {
    1: 1.0,
    2: 1.5,
    3: 2.0,
    4: 2.5,
    5: 3.0,
}


def _tier_multiplier(tier: int) -> float:
    """Return the complexity multiplier for the given tier."""
    return TIER_MULTIPLIERS.get(tier, 1.0)


# ===================================================================
# RED OPERATOR REWARDS
# ===================================================================


class FlagReward:
    """Binary reward: 1.0 if submitted flag matches a manifest flag, else 0.0."""

    def score(self, submitted: str, valid_flags: set[str]) -> float:
        return 1.0 if submitted in valid_flags else 0.0


class HallucinationPenalty:
    """Penalty of -0.3 for each flag submission not in the manifest."""

    PENALTY = -0.3

    def score(self, hallucinated_count: int) -> float:
        return self.PENALTY * hallucinated_count


class EfficiencyReward:
    """Exponential step-count discount: gamma^step_count."""

    def __init__(self, gamma: float = 0.95) -> None:
        self.gamma = gamma

    def score(self, step_count: int) -> float:
        return self.gamma ** step_count


class StealthReward:
    """Reward inversely proportional to Blue detections.

    ``1.0 - (detected_actions / total_actions)``

    0 detections -> 1.0, all actions detected -> 0.0.
    """

    def score(self, detected_actions: int, total_actions: int) -> float:
        if total_actions == 0:
            return 1.0
        return 1.0 - (detected_actions / total_actions)


class EvidenceReward:
    """Quality score for submitted evidence (0.0-1.0).

    Scores evidence based on structural quality:
    - Non-empty content (+0.25)
    - References a known vulnerability type (+0.25)
    - References a host from the snapshot topology (+0.25)
    - Sufficient detail (>50 chars) (+0.25)
    """

    VULN_KEYWORDS = {
        "sqli", "sql injection", "xss", "cross-site", "idor",
        "path traversal", "directory traversal", "command injection",
        "ssrf", "weak credentials", "broken auth", "jwt",
    }

    def score(self, content: str, host_names: set[str] | None = None) -> float:
        if not content:
            return 0.0
        lower = content.lower()
        score = 0.25  # non-empty
        if any(kw in lower for kw in self.VULN_KEYWORDS):
            score += 0.25
        if host_names and any(h in lower for h in host_names if h):
            score += 0.25
        if len(content) > 50:
            score += 0.25
        return min(score, 1.0)


class SocialEngineeringReward:
    """Binary: 1.0 if an NPC fell for a social engineering attack this episode."""

    def score(self, npc_compromised: bool) -> float:
        return 1.0 if npc_compromised else 0.0


class ComplexityBonus:
    """Tier-based multiplier for rewards.

    Tier 1=1.0x, Tier 2=1.5x, Tier 3=2.0x, Tier 4=2.5x, Tier 5=3.0x.
    """

    def multiplier(self, tier: int) -> float:
        return _tier_multiplier(tier)


# ---------------------------------------------------------------------------
# Composite Red
# ---------------------------------------------------------------------------


class CompositeRedReward:
    """Weighted sum of all Red reward components.

    Default weights::

        flag:        0.40  (primary objective)
        efficiency:  0.10  (speed bonus)
        stealth:     0.15  (avoid Blue detection)
        evidence:    0.10  (documentation quality)
        social:      0.05  (social engineering -- Level 1+ only)

    Complexity is applied as a multiplier on the weighted sum.
    Hallucination penalty is additive (not scaled by tier).
    """

    def __init__(
        self,
        gamma: float = 0.95,
        weights: dict[str, float] | None = None,
    ) -> None:
        self.weights = weights or {
            "flag": 0.40,
            "efficiency": 0.10,
            "stealth": 0.15,
            "evidence": 0.10,
            "social": 0.05,
        }
        self.flag = FlagReward()
        self.efficiency = EfficiencyReward(gamma)
        self.stealth = StealthReward()
        self.evidence = EvidenceReward()
        self.social = SocialEngineeringReward()
        self.complexity = ComplexityBonus()
        self.hallucination = HallucinationPenalty()

    # -- low-level score (explicit args, no env coupling) ---------------

    def score(
        self,
        submitted_flag: str | None = None,
        step_count: int = 0,
        detected_actions: int = 0,
        total_actions: int = 0,
        evidence_content: str = "",
        evidence_hosts: set[str] | None = None,
        npc_compromised: bool = False,
        hallucinated_count: int = 0,
        tier: int = 1,
    ) -> float:
        valid_flags: set[str] = set()  # caller should supply if known
        total = 0.0
        if submitted_flag is not None:
            total += self.weights["flag"] * self.flag.score(submitted_flag, valid_flags)
        total += self.weights["efficiency"] * self.efficiency.score(step_count)
        total += self.weights["stealth"] * self.stealth.score(detected_actions, total_actions)
        total += self.weights["evidence"] * self.evidence.score(evidence_content, evidence_hosts)
        total += self.weights["social"] * self.social.score(npc_compromised)
        scaled = total * self.complexity.multiplier(tier)
        scaled += self.hallucination.score(hallucinated_count)
        return scaled

    # -- high-level compute (called by RangeEnvironment.step) -----------

    def compute(
        self,
        action: RangeAction,
        observation: RangeObservation,
        state: RangeState,
        snapshot: SnapshotSpec,
        ctx: dict[str, Any] | None = None,
    ) -> float:
        """Compute composite Red reward from full environment context."""
        ctx = ctx or {}
        red_history = ctx.get("red_history", [])
        blue_history = ctx.get("blue_history", [])
        npc_log = ctx.get("npc_traffic_log", [])

        # Flag reward -- observation.flags_captured is set by environment
        valid_flags = {f.value for f in snapshot.flags}
        flag_score = 0.0
        if observation.flags_captured:
            for fc in observation.flags_captured:
                flag_score += self.flag.score(fc, valid_flags)

        # Efficiency
        eff_score = self.efficiency.score(state.step_count)

        # Stealth -- coupled to Blue
        red_actions = [
            r for r in red_history
            if r.get("type") not in ("hallucinated_flag", "evidence")
        ]
        blue_findings = [b for b in blue_history if b.get("type") == "finding"]
        detections = min(len(blue_findings), len(red_actions))
        stealth_score = self.stealth.score(detections, len(red_actions))

        # Evidence
        evidence_entries = [r for r in red_history if r.get("type") == "evidence"]
        evidence_content = evidence_entries[-1].get("content", "") if evidence_entries else ""
        topo_hosts = {
            h.get("name", "") if isinstance(h, dict) else ""
            for h in snapshot.topology.get("hosts", [])
        }
        evidence_score = self.evidence.score(evidence_content, topo_hosts)

        # Social engineering
        social_successes = [
            e for e in npc_log
            if e.get("type") == "social_engineering" and e.get("result") == "success"
        ]
        social_score = self.social.score(bool(social_successes))

        # Hallucination count
        hallucinated = [r for r in red_history if r.get("type") == "hallucinated_flag"]

        # Aggregate
        components = {
            "flag": flag_score,
            "efficiency": eff_score,
            "stealth": stealth_score,
            "evidence": evidence_score,
            "social": social_score,
        }
        base = sum(self.weights.get(k, 0.0) * v for k, v in components.items())
        scaled = base * self.complexity.multiplier(state.tier)
        halluc = self.hallucination.score(len(hallucinated))
        total = scaled + halluc

        logger.debug(
            "Red reward: components=%s base=%.3f scaled=%.3f halluc=%.3f total=%.3f",
            components, base, scaled, halluc, total,
        )
        return total


# ===================================================================
# BLUE OPERATOR REWARDS
# ===================================================================


class DetectionReward:
    """True-positive rate: correctly_identified / total_red_actions."""

    def score(self, true_positives: int, total_red_actions: int) -> float:
        if total_red_actions == 0:
            return 0.0
        return min(true_positives / total_red_actions, 1.0)


class PatchReward:
    """Binary: 1.0 if the patch blocks the exploit, else 0.0.

    In a full deployment, validation re-runs the golden path exploit step
    after patching. Here we track whether a patch command was issued.
    """

    def score(self, exploit_blocked: bool) -> float:
        return 1.0 if exploit_blocked else 0.0


class AvailabilityReward:
    """Fraction of services still healthy after Blue's defensive actions."""

    def score(self, healthy: int, total: int) -> float:
        if total == 0:
            return 1.0
        return healthy / total


class PhishingDetectionReward:
    """Reward for correctly identifying social engineering events.

    Level 1+ only. Returns fraction of SE events Blue flagged.
    """

    def score(self, phishing_detected: int, total_se_events: int) -> float:
        if total_se_events == 0:
            return 0.0
        return min(phishing_detected / total_se_events, 1.0)


class FalsePositiveReward:
    """Penalty of -0.2 per NPC event incorrectly flagged as attack."""

    PENALTY = -0.2

    def score(self, false_positives: int) -> float:
        return self.PENALTY * false_positives


# ---------------------------------------------------------------------------
# Composite Blue
# ---------------------------------------------------------------------------


class CompositeBlueReward:
    """Weighted sum of all Blue reward components.

    Default weights::

        detection:     0.35
        patch:         0.25
        availability:  0.15
        phishing:      0.05

    Complexity is applied as a multiplier on the weighted sum.
    False positive penalty is additive (not scaled by tier).
    """

    def __init__(
        self,
        weights: dict[str, float] | None = None,
    ) -> None:
        self.weights = weights or {
            "detection": 0.35,
            "patch": 0.25,
            "availability": 0.15,
            "phishing": 0.05,
        }
        self.detection = DetectionReward()
        self.patch = PatchReward()
        self.availability = AvailabilityReward()
        self.phishing = PhishingDetectionReward()
        self.complexity = ComplexityBonus()
        self.false_positive = FalsePositiveReward()

    # -- low-level score ------------------------------------------------

    def score(
        self,
        true_positives: int = 0,
        total_red_actions: int = 0,
        exploit_blocked: bool = False,
        healthy_services: int = 0,
        total_services: int = 0,
        phishing_detected: int = 0,
        total_se_events: int = 0,
        false_positives: int = 0,
        tier: int = 1,
    ) -> float:
        total = 0.0
        total += self.weights["detection"] * self.detection.score(true_positives, total_red_actions)
        total += self.weights["patch"] * self.patch.score(exploit_blocked)
        total += self.weights["availability"] * self.availability.score(healthy_services, total_services)
        total += self.weights["phishing"] * self.phishing.score(phishing_detected, total_se_events)
        scaled = total * self.complexity.multiplier(tier)
        scaled += self.false_positive.score(false_positives)
        return scaled

    # -- high-level compute (called by RangeEnvironment.step) -----------

    def compute(
        self,
        action: RangeAction,
        observation: RangeObservation,
        state: RangeState,
        snapshot: SnapshotSpec,
        ctx: dict[str, Any] | None = None,
    ) -> float:
        """Compute composite Blue reward from full environment context."""
        ctx = ctx or {}
        red_history = ctx.get("red_history", [])
        blue_history = ctx.get("blue_history", [])
        npc_log = ctx.get("npc_traffic_log", [])

        # Detection -- coupled to Red
        red_actions = [
            r for r in red_history
            if r.get("type") not in ("hallucinated_flag", "evidence")
        ]
        blue_findings = [b for b in blue_history if b.get("type") == "finding"]
        tp = min(len(blue_findings), len(red_actions))
        detect_score = self.detection.score(tp, len(red_actions))

        # Patch -- did Blue issue any patch commands?
        patches = [b for b in blue_history if b.get("cmd_name") == "patch"]
        patch_score = self.patch.score(bool(patches))

        # Availability
        svc = state.services_status or {}
        total_svc = len(svc)
        healthy = sum(
            1 for v in svc.values()
            if v in ("running", "healthy", True, "up")
        )
        avail_score = self.availability.score(healthy, total_svc)

        # Phishing detection
        se_events = [e for e in npc_log if e.get("type") == "social_engineering"]
        phishing_kw = ("phish", "social", "spear", "pretext", "suspicious email")
        phishing_found = [
            b for b in blue_findings
            if any(kw in b.get("content", "").lower() for kw in phishing_kw)
        ]
        phish_score = self.phishing.score(len(phishing_found), len(se_events))

        # False positives -- findings that reference benign NPC traffic
        npc_sources = {
            e.get("source", "") for e in npc_log if e.get("label") == "benign"
        }
        fp_count = 0
        for f in blue_findings:
            content = f.get("content", "").lower()
            if any(src.lower() in content for src in npc_sources if src):
                fp_count += 1

        # Aggregate
        components = {
            "detection": detect_score,
            "patch": patch_score,
            "availability": avail_score,
            "phishing": phish_score,
        }
        base = sum(self.weights.get(k, 0.0) * v for k, v in components.items())
        scaled = base * self.complexity.multiplier(state.tier)
        fp_penalty = self.false_positive.score(fp_count)
        total = scaled + fp_penalty

        logger.debug(
            "Blue reward: components=%s base=%.3f scaled=%.3f fp=%.3f total=%.3f",
            components, base, scaled, fp_penalty, total,
        )
        return total
