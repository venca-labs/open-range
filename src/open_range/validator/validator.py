"""Validator pipeline orchestrator — runs checks in sequence, fail-fast on mechanical."""

from __future__ import annotations

import logging
import time

from pydantic import BaseModel, Field

from open_range.protocols import CheckResult, ContainerSet, SnapshotSpec, ValidatorCheck

logger = logging.getLogger(__name__)

# Check classes whose failures are advisory (logged, may trigger retry,
# but never block admission on their own).
_ADVISORY_CHECK_CLASSES = {"NPCConsistencyCheck", "RealismReviewCheck"}


class ValidationResult(BaseModel):
    """Aggregate result of all validator checks."""

    passed: bool = False
    checks: list[CheckResult] = Field(default_factory=list)
    total_time_s: float = 0.0


class ValidatorGate:
    """Run a list of :class:`ValidatorCheck` instances in order.

    Mechanical checks (``advisory=False``) fail-fast: the first failure stops
    the pipeline.  Advisory checks (``advisory=True``) are always recorded but
    never prevent an overall pass.
    """

    def __init__(self, checks: list[ValidatorCheck]) -> None:
        self.checks = list(checks)

    async def validate(
        self,
        snapshot: SnapshotSpec,
        containers: ContainerSet,
    ) -> ValidationResult:
        results: list[CheckResult] = []
        for check in self.checks:
            check_name = type(check).__name__
            is_advisory = check_name in _ADVISORY_CHECK_CLASSES
            t0 = time.monotonic()
            try:
                result = await check.check(snapshot, containers)
            except Exception as exc:  # noqa: BLE001
                result = CheckResult(
                    name=check_name,
                    passed=False,
                    advisory=is_advisory,
                    error=f"unhandled: {exc}",
                )
            result.time_s = time.monotonic() - t0
            results.append(result)

            if not result.passed:
                if result.advisory:
                    logger.info(
                        "Advisory check %s failed: %s (non-blocking)",
                        result.name,
                        result.error,
                    )
                else:
                    # Fail-fast on mechanical (non-advisory) failures.
                    logger.warning(
                        "Mechanical check %s failed: %s — stopping pipeline",
                        result.name,
                        result.error,
                    )
                    break

        passed = all(r.passed for r in results if not r.advisory)
        return ValidationResult(
            passed=passed,
            checks=results,
            total_time_s=sum(r.time_s for r in results),
        )
