"""Vuln mutation logic -- swap vulnerabilities between resets.

The Mutator wraps a SnapshotBuilder and adds mutation-specific context:
ensuring vuln diversity, targeting weak areas, and feeding back error
context from failed validations.
"""

from __future__ import annotations

import logging
from typing import Any

from open_range.protocols import BuildContext, SnapshotBuilder, SnapshotSpec

logger = logging.getLogger(__name__)


class Mutator:
    """Orchestrate vuln mutation across resets.

    Tracks episode history and feeds it into the Builder's context so that
    each reset produces a genuinely different challenge.
    """

    def __init__(
        self,
        builder: SnapshotBuilder,
        max_retries: int = 3,
    ) -> None:
        self.builder = builder
        self.max_retries = max_retries
        self._history: list[str] = []  # recent vuln classes
        self._attack_surfaces: list[str] = []  # recent injection points
        self._episode_count: int = 0

    async def mutate(
        self,
        manifest: dict,
        context: BuildContext | None = None,
        error: dict[str, Any] | None = None,
    ) -> SnapshotSpec:
        """Generate a mutated snapshot, avoiding recent vuln classes.

        Args:
            manifest: Parsed manifest dict.
            context: Optional base context (curriculum stats, etc.).
            error: Error feedback from a failed validation attempt.

        Returns:
            A new SnapshotSpec with different vulns from the previous episode.
        """
        if context is None:
            context = BuildContext()

        # Inject episode history into context
        context.previous_vuln_classes = list(self._history[-3:])
        context.recent_attack_surfaces = list(self._attack_surfaces[-5:])
        context.episode_count = self._episode_count

        if error is not None:
            # error field may or may not exist on BuildContext
            try:
                context.error = error  # type: ignore[attr-defined]
            except (AttributeError, ValueError):
                pass  # protocol version without error field

        snapshot = await self.builder.build(manifest, context)

        # Update history
        new_classes = [v.type for v in snapshot.truth_graph.vulns]
        self._history.extend(new_classes)
        new_surfaces = [v.injection_point for v in snapshot.truth_graph.vulns]
        self._attack_surfaces.extend(new_surfaces)
        self._episode_count += 1

        logger.info(
            "Mutator: episode %d, vuln classes: %s",
            self._episode_count,
            new_classes,
        )

        return snapshot

    @property
    def episode_count(self) -> int:
        """Number of episodes (mutations) so far."""
        return self._episode_count

    @property
    def history(self) -> list[str]:
        """All vuln classes used so far, in order."""
        return list(self._history)
