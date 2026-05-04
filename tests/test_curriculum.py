"""Core auto-evolve tests.

Cover the policy + the orchestration in ``openrange.core.curriculum``,
without touching any pack-specific code. The pack-side enumerator is
tested in test_cyber_auto_curriculum.py.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from types import MappingProxyType
from typing import cast

from openrange.core.curriculum import (
    Mutation,
    auto_evolve,
    direction_from_reports,
)
from openrange.core.episode import EpisodeReport

# ---------------------------------------------------------------------------
# direction_from_reports
# ---------------------------------------------------------------------------


def _report(passed: bool) -> EpisodeReport:
    score = 1.0 if passed else 0.0
    return EpisodeReport(
        snapshot_id="snap",
        task_id="task",
        final_state=MappingProxyType({"requests": ()}),
        verifier_result=MappingProxyType({"passed": passed, "score": score}),
    )


def test_direction_none_when_no_reports() -> None:
    assert direction_from_reports(()) is None


def test_direction_harden_when_pass_rate_high() -> None:
    reports = [_report(True), _report(True), _report(True)]
    assert direction_from_reports(reports) == "harden"


def test_direction_soften_when_pass_rate_low() -> None:
    reports = [_report(False), _report(False), _report(False)]
    assert direction_from_reports(reports) == "soften"


def test_direction_diversify_when_mid_band() -> None:
    reports = [_report(True), _report(False)]
    assert direction_from_reports(reports) == "diversify"


def test_direction_threshold_boundaries() -> None:
    # 2/3 = 0.66... ≥ 0.66 → harden
    high = [_report(True), _report(True), _report(False)]
    assert direction_from_reports(high) == "harden"
    # 1/3 = 0.33... ≤ 0.33 is False; default soften threshold strict
    low = [_report(False), _report(False), _report(True)]
    assert direction_from_reports(low) == "diversify"


def test_direction_treats_missing_passed_as_failure() -> None:
    bad = EpisodeReport(
        snapshot_id="s",
        task_id="t",
        final_state=MappingProxyType({}),
        verifier_result=None,
    )
    assert direction_from_reports([bad]) == "soften"


# ---------------------------------------------------------------------------
# auto_evolve — orchestration
# ---------------------------------------------------------------------------


class _FakeSnapshot:
    """Minimal Snapshot stand-in. ``auto_evolve`` only calls
    ``resolve_pack(snapshot.manifest, registry)``; for the no-op short-
    circuits below the manifest is never read.
    """

    id = "fake-snap"
    manifest = cast(object, MappingProxyType({}))
    world_graph = None


def test_auto_evolve_no_reports_returns_none() -> None:
    snap = _FakeSnapshot()
    result = auto_evolve(cast(object, snap))  # type: ignore[arg-type]
    assert result is None


def test_auto_evolve_no_options_returns_none(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """When the pack returns no mutations, None signals no-op."""
    snap = _FakeSnapshot()
    captured: dict[str, object] = {}

    class _StubPack:
        def available_mutations(
            self,
            snapshot: object,
            reports: Sequence[EpisodeReport],
            *,
            llm: object | None = None,
        ) -> tuple[Mutation, ...]:
            captured["called"] = True
            return ()

    def _resolve_pack(_manifest: object, _registry: object) -> object:
        return _StubPack()

    monkeypatch.setattr("openrange.core.builder.resolve_pack", _resolve_pack)
    result = auto_evolve(
        cast(object, snap),  # type: ignore[arg-type]
        _report(True),
    )
    assert result is None
    assert captured.get("called") is True


def test_auto_evolve_no_matching_direction_returns_none(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """Pack offers only soften options but agent passed (harden direction)."""
    snap = _FakeSnapshot()
    options = (
        Mutation(
            directive=MappingProxyType({"add": ["x"]}),
            direction="soften",
            relevance=0.9,
        ),
    )

    class _StubPack:
        def available_mutations(
            self,
            *_args: object,
            **_kw: object,
        ) -> tuple[Mutation, ...]:
            return options

    monkeypatch.setattr(
        "openrange.core.builder.resolve_pack",
        lambda *_args, **_kw: _StubPack(),
    )
    result = auto_evolve(cast(object, snap), _report(True))  # type: ignore[arg-type]
    assert result is None


def test_auto_evolve_zero_relevance_returns_none(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    snap = _FakeSnapshot()
    options = (
        Mutation(
            directive=MappingProxyType({"patch": ["sql_injection"]}),
            direction="harden",
            relevance=0.0,
        ),
    )

    class _StubPack:
        def available_mutations(self, *a: object, **kw: object) -> tuple[Mutation, ...]:
            return options

    monkeypatch.setattr(
        "openrange.core.builder.resolve_pack",
        lambda *a, **kw: _StubPack(),
    )
    result = auto_evolve(cast(object, snap), _report(True))  # type: ignore[arg-type]
    assert result is None


def test_auto_evolve_picks_highest_relevance_in_direction(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """Agent passed → harden; pick highest-relevance harden option."""
    snap = _FakeSnapshot()
    chosen_directive: dict[str, object] = {}

    options = (
        Mutation(
            directive=MappingProxyType({"patch": ["ssrf"]}),
            direction="harden",
            relevance=0.2,
        ),
        Mutation(
            directive=MappingProxyType({"patch": ["sql_injection"]}),
            direction="harden",
            relevance=0.9,
        ),
        Mutation(
            directive=MappingProxyType({"add": ["broken_authz"]}),
            direction="soften",
            relevance=0.95,
        ),
    )

    class _StubPack:
        def available_mutations(self, *a: object, **kw: object) -> tuple[Mutation, ...]:
            return options

    def _stub_evolve(
        snapshot: object,
        curriculum: Mapping[str, object],
        **_kw: object,
    ) -> object:
        chosen_directive.update(dict(curriculum))
        return "evolved"

    monkeypatch.setattr(
        "openrange.core.builder.resolve_pack",
        lambda *a, **kw: _StubPack(),
    )
    monkeypatch.setattr("openrange.core.builder.evolve", _stub_evolve)

    result = auto_evolve(cast(object, snap), _report(True))  # type: ignore[arg-type]
    assert result == "evolved"
    assert chosen_directive == {"patch": ["sql_injection"]}


def test_auto_evolve_custom_policy(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """Trainer can override the direction policy."""
    snap = _FakeSnapshot()
    options = (
        Mutation(
            directive=MappingProxyType({"add": ["x"]}),
            direction="diversify",
            relevance=0.5,
        ),
    )

    class _StubPack:
        def available_mutations(self, *a: object, **kw: object) -> tuple[Mutation, ...]:
            return options

    captured: dict[str, object] = {}

    def _stub_evolve(
        snapshot: object,
        curriculum: Mapping[str, object],
        **_kw: object,
    ) -> object:
        captured["directive"] = dict(curriculum)
        return "evolved"

    monkeypatch.setattr(
        "openrange.core.builder.resolve_pack",
        lambda *a, **kw: _StubPack(),
    )
    monkeypatch.setattr("openrange.core.builder.evolve", _stub_evolve)

    result = auto_evolve(
        cast(object, snap),  # type: ignore[arg-type]
        _report(True),
        policy=lambda _reports: "diversify",
    )
    assert result == "evolved"
    assert captured["directive"] == {"add": ["x"]}
