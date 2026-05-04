"""Auto-evolve: pack enumerates mutations, core picks one based on signal.

The pack lists every evolution move available from a given snapshot,
tagging each with direction (harden / soften / diversify) and a
relevance score (0..1) reflecting how well the move responds to recent
agent behavior. Core applies a policy to derive a direction from the
report set, picks the highest-relevance candidate in that direction,
and forwards to ``evolve()``.

Pack owns enumeration and tagging. Core owns the loop, the policy, the
tie-break, and the empty-proposal short-circuit.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal

if TYPE_CHECKING:
    from openrange.core.builder import BuildEventSink
    from openrange.core.episode import EpisodeReport
    from openrange.core.pack import PackRegistry
    from openrange.core.snapshot import Snapshot
    from openrange.llm import LLMBackend


Direction = Literal["harden", "soften", "diversify"]


@dataclass(frozen=True, slots=True)
class Mutation:
    """One evolution move the pack offers.

    ``directive`` is the dict ``evolve()`` consumes (e.g.
    ``{"patch": ["sql_injection"]}``). ``direction`` is the pack's claim
    that applying this move makes the next world harder, easier, or
    differently shaped. ``relevance`` is the pack's confidence (0..1)
    that this move responds to what the agent actually did. ``note`` is
    human-readable; surfaces in lineage and dashboard.
    """

    directive: Mapping[str, object]
    direction: Direction
    relevance: float = 0.0
    note: str = ""


CurriculumPolicy = Callable[[Sequence["EpisodeReport"]], "Direction | None"]


def direction_from_reports(
    reports: Sequence[EpisodeReport],
    *,
    harden_threshold: float = 0.66,
    soften_threshold: float = 0.33,
) -> Direction | None:
    """Default policy: pass-rate across reports decides direction.

    Returns ``None`` when there are no reports — no signal to act on.
    """
    if not reports:
        return None
    passed = sum(1 for r in reports if _report_passed(r))
    pass_rate = passed / len(reports)
    if pass_rate >= harden_threshold:
        return "harden"
    if pass_rate <= soften_threshold:
        return "soften"
    return "diversify"


def _report_passed(report: EpisodeReport) -> bool:
    result = report.verifier_result
    if result is None:
        return False
    return result.get("passed") is True


def auto_evolve(
    snapshot: Snapshot,
    *reports: EpisodeReport,
    policy: CurriculumPolicy = direction_from_reports,
    llm: LLMBackend | None = None,
    event_sink: BuildEventSink | None = None,
    registry: PackRegistry | None = None,
) -> Snapshot | None:
    """Pick a mutation based on agent performance and apply it.

    Asks the snapshot's pack to enumerate available mutations given the
    reports (LLM enrichment if ``llm`` is supplied), applies ``policy``
    to choose a direction, picks the highest-relevance mutation in that
    direction, and forwards to ``evolve()``.

    Returns ``None`` when there's no signal to act on (no reports, no
    mutations, no direction, no candidate matching direction, or zero-
    relevance best candidate). Callers loop until ``None`` to walk the
    curriculum naturally.
    """
    from openrange.core.builder import _resolve_registry, evolve, resolve_pack

    if not reports:
        return None
    registry = _resolve_registry(registry)
    pack = resolve_pack(snapshot.manifest, registry)
    options = pack.available_mutations(snapshot, reports, llm=llm)
    if not options:
        return None
    direction = policy(reports)
    if direction is None:
        return None
    candidates = [o for o in options if o.direction == direction]
    if not candidates:
        return None
    chosen = max(candidates, key=lambda o: o.relevance)
    if chosen.relevance <= 0.0:
        return None
    # Surface the chosen mutation so the dashboard lineage view gets
    # the full story — direction + note + parent snapshot — rather
    # than two snapshots back-to-back with no narrative connection.
    # Fires before ``evolve()`` so it lands even if the subsequent
    # build raises.
    if event_sink is not None:
        event_sink(
            "auto_evolve_chosen",
            {
                "parent_snapshot_id": snapshot.id,
                "direction": chosen.direction,
                "relevance": chosen.relevance,
                "note": chosen.note,
                "directive": dict(chosen.directive),
                "candidates_considered": len(candidates),
            },
        )
    return evolve(
        snapshot,
        chosen.directive,
        llm=llm,
        event_sink=event_sink,
        registry=registry,
    )


__all__ = [
    "CurriculumPolicy",
    "Direction",
    "Mutation",
    "auto_evolve",
    "direction_from_reports",
]
