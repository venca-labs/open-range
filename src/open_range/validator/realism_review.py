"""Check 10: Realism review — LLM advisory on scenario plausibility.

Uses LiteLLM to review task briefings for leakage and overall realism.
Always ``advisory=True``: can trigger a retry but never overrides a
mechanical pass.

The LLM never sees flag values or golden-path commands — only summaries
and briefings.
"""

from __future__ import annotations

import json
import logging
import os

from open_range.builder.prompts import REALISM_REVIEW_PROMPT
from open_range.protocols import CheckResult, ContainerSet, SnapshotSpec

logger = logging.getLogger(__name__)


class RealismReviewCheck:
    """LLM-based realism review.  Always advisory."""

    def __init__(self, model: str | None = None) -> None:
        self.model = model or os.environ.get(
            "OPENRANGE_VALIDATOR_MODEL",
            "anthropic/claude-haiku-4-5-20251001",
        )

    async def check(self, snapshot: SnapshotSpec, containers: ContainerSet) -> CheckResult:
        try:
            import litellm  # noqa: F811
        except ImportError:
            return CheckResult(
                name="realism_review",
                passed=True,
                advisory=True,
                details={"note": "litellm not installed — skipping advisory review"},
            )

        # Build a redacted summary — never expose flag values or golden-path
        # commands to the reviewer LLM.
        tier = snapshot.topology.get("tier", 1)
        summary = {
            "task_briefings": {
                "red_briefing": snapshot.task.red_briefing,
                "blue_briefing": snapshot.task.blue_briefing,
            },
            "vuln_types": [v.type for v in snapshot.truth_graph.vulns],
            "vuln_hosts": [v.host for v in snapshot.truth_graph.vulns],
            "topology_hosts": snapshot.topology.get("hosts", []),
            "golden_path_length": len(snapshot.golden_path),
            "tier": tier,
        }

        try:
            response = await litellm.acompletion(
                model=self.model,
                messages=[
                    {"role": "system", "content": REALISM_REVIEW_PROMPT},
                    {"role": "user", "content": json.dumps(summary)},
                ],
                response_format={"type": "json_object"},
                temperature=0.0,
            )
            review = json.loads(response.choices[0].message.content)
            passed = bool(review.get("pass", False))
            issues = review.get("issues", [])
        except Exception as exc:  # noqa: BLE001
            # LLM failure should not block validation — degrade gracefully.
            logger.warning("Realism review LLM call failed: %s", exc)
            return CheckResult(
                name="realism_review",
                passed=True,
                advisory=True,
                details={"note": f"LLM review failed ({exc}) — skipping"},
            )

        return CheckResult(
            name="realism_review",
            passed=passed,
            advisory=True,
            details={"issues": issues, "model": self.model},
            error="" if passed else "; ".join(str(i) for i in issues),
        )
