"""Tests for cyber.webapp's procedural mutation enumerator.

Builds a real v1 snapshot and runs ``available_mutations`` against
synthetic ``EpisodeReport`` payloads to verify direction tagging and
relevance scoring. The LLM enrichment path is exercised separately
with a stub backend.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from types import MappingProxyType

from cyber_webapp import CyberWebappPack
from cyber_webapp.mutation import available_mutations
from cyber_webapp.vulnerabilities import CATALOG as VULN_CATALOG

from openrange.core.builder import build
from openrange.core.episode import EpisodeReport

V1_MANIFEST = {
    "pack": {"id": "cyber.webapp", "source": {"kind": "builtin"}},
    "mode": "simulation",
    "world": {},
}


def _build_snapshot(seed: int = 0):  # type: ignore[no-untyped-def]
    return build(V1_MANIFEST, prompt=f"seed={seed}")


def _vuln_paths(snapshot, kind: str) -> set[str]:  # type: ignore[no-untyped-def]
    """Find HTTP paths of endpoints affected by vulnerabilities of ``kind``."""
    graph = snapshot.world_graph
    assert graph is not None
    vuln_ids = {
        n.id
        for n in graph.nodes
        if n.type == "vulnerability" and n.attrs.get("kind") == kind
    }
    target_ids: set[str] = set()
    for edge in graph.edges:
        if edge.relation == "affects" and edge.source in vuln_ids:
            target_ids.add(edge.target)
    return {
        str(n.attrs.get("path", ""))
        for n in graph.nodes
        if n.id in target_ids and n.type == "endpoint"
    }


def _report_with_requests(
    snapshot_id: str,
    requests: Sequence[Mapping[str, object]],
    *,
    passed: bool = True,
) -> EpisodeReport:
    return EpisodeReport(
        snapshot_id=snapshot_id,
        task_id="task",
        final_state=MappingProxyType({"requests": list(requests)}),
        verifier_result=MappingProxyType(
            {"passed": passed, "score": 1.0 if passed else 0.0},
        ),
    )


# ---------------------------------------------------------------------------
# Procedural enumeration
# ---------------------------------------------------------------------------


def test_available_mutations_returns_options_for_v1_world() -> None:
    snap = _build_snapshot()
    options = available_mutations(snap, ())
    assert options, "expected at least one mutation for a v1-built world"
    # Every catalog kind is represented somewhere in the option list
    kinds_in_directives: set[str] = set()
    for opt in options:
        directive = opt.directive
        for verb in ("patch", "add"):
            for kind in directive.get(verb, ()):
                kinds_in_directives.add(str(kind))
    assert set(VULN_CATALOG).issubset(kinds_in_directives)


def test_patch_options_tagged_harden_with_floor_relevance() -> None:
    snap = _build_snapshot()
    options = available_mutations(snap, ())
    patch_options = [o for o in options if "patch" in o.directive]
    assert patch_options
    for opt in patch_options:
        assert opt.direction == "harden"
        # No reports → floor relevance only
        assert opt.relevance == 0.05


def test_add_options_tagged_by_world_presence() -> None:
    snap = _build_snapshot()
    options = available_mutations(snap, ())
    graph = snap.world_graph
    assert graph is not None
    kinds_in_world = {
        str(n.attrs.get("kind")) for n in graph.nodes if n.type == "vulnerability"
    }
    for opt in options:
        if "add" not in opt.directive:
            continue
        kinds = list(opt.directive["add"])  # type: ignore[arg-type]
        assert len(kinds) == 1
        kind = str(kinds[0])
        if kind in kinds_in_world:
            assert opt.direction == "diversify"
        else:
            assert opt.direction == "soften"


def test_relevance_climbs_when_agent_hits_vuln_endpoints() -> None:
    """Synthetic request log targeting vuln-bearing endpoints should
    push that kind's patch relevance well above the floor."""
    snap = _build_snapshot()
    graph = snap.world_graph
    assert graph is not None
    # Pick a vuln kind that's actually present and find one of its paths.
    kinds_in_world = sorted(
        {str(n.attrs.get("kind")) for n in graph.nodes if n.type == "vulnerability"},
    )
    assert kinds_in_world
    target_kind = kinds_in_world[0]
    target_paths = _vuln_paths(snap, target_kind)
    assert target_paths, f"no endpoint path found for {target_kind}"
    target_path = next(iter(target_paths))

    requests = [
        {"method": "GET", "path": target_path, "status": 200} for _ in range(10)
    ]
    report = _report_with_requests(snap.id, requests)
    options = available_mutations(snap, [report])
    patch_for_target = next(
        o
        for o in options
        if "patch" in o.directive and target_kind in o.directive["patch"]  # type: ignore[operator]
    )
    # Hits land on a target_kind endpoint → that patch's relevance climbs
    # above the floor. (Other patches may *also* climb if multiple vulns
    # share an endpoint, which is allowed by the ontology — we don't
    # assert on the rest here.)
    assert patch_for_target.relevance > 0.5


def test_failed_requests_dont_inflate_relevance() -> None:
    snap = _build_snapshot()
    graph = snap.world_graph
    assert graph is not None
    kinds_in_world = sorted(
        {str(n.attrs.get("kind")) for n in graph.nodes if n.type == "vulnerability"},
    )
    target_kind = kinds_in_world[0]
    target_paths = _vuln_paths(snap, target_kind)
    target_path = next(iter(target_paths))

    # 10 requests but all 4xx — should be ignored
    requests = [
        {"method": "GET", "path": target_path, "status": 404} for _ in range(10)
    ]
    report = _report_with_requests(snap.id, requests, passed=False)
    options = available_mutations(snap, [report])
    patch_for_target = next(
        o
        for o in options
        if "patch" in o.directive and target_kind in o.directive["patch"]  # type: ignore[operator]
    )
    # No successful hits → floor only
    assert patch_for_target.relevance == 0.05


def test_directives_are_evolve_consumable() -> None:
    """Each Mutation.directive must be the shape ``evolve()`` accepts."""
    snap = _build_snapshot()
    options = available_mutations(snap, ())
    for opt in options:
        assert isinstance(opt.directive, Mapping)
        # v1 directives are single-verb with a list of kinds
        keys = set(opt.directive.keys())
        assert keys <= {"patch", "add"}
        for verb in keys:
            value = opt.directive[verb]
            assert isinstance(value, list | tuple)
            assert all(isinstance(k, str) for k in value)


# ---------------------------------------------------------------------------
# CyberWebappPack.available_mutations integration (procedural path)
# ---------------------------------------------------------------------------


def test_pack_available_mutations_no_llm_matches_procedural() -> None:
    snap = _build_snapshot()
    pack = CyberWebappPack()
    pack_options = pack.available_mutations(snap, [])
    proc_options = available_mutations(snap, [])
    assert len(pack_options) == len(proc_options)
    for a, b in zip(pack_options, proc_options, strict=False):
        assert a.directive == b.directive
        assert a.direction == b.direction
        assert a.relevance == b.relevance


# ---------------------------------------------------------------------------
# LLM enrichment (stub backend)
# ---------------------------------------------------------------------------


class _StubLLMBackend:
    """Minimal LLMBackend that returns a fixed JSON payload."""

    def __init__(self, response: Mapping[str, object]) -> None:
        self._response = response
        self.calls = 0

    def complete(self, request) -> object:  # type: ignore[no-untyped-def]
        from openrange.llm import LLMResult

        self.calls += 1
        return LLMResult(text="", parsed_json=self._response)


def test_llm_enrichment_overrides_relevance_and_note() -> None:
    snap = _build_snapshot()
    procedural = available_mutations(snap, [])
    # Bump every option's relevance to 0.99 and rewrite the note
    enriched_response = {
        "mutations": [
            {"index": i, "relevance": 0.99, "note": f"llm-note-{i}"}
            for i in range(len(procedural))
        ],
    }
    llm = _StubLLMBackend(enriched_response)
    pack = CyberWebappPack()
    options = pack.available_mutations(snap, [], llm=llm)  # type: ignore[arg-type]
    assert llm.calls == 1
    assert len(options) == len(procedural)
    for i, opt in enumerate(options):
        assert opt.relevance == 0.99
        assert opt.note == f"llm-note-{i}"
        # Direction & directive must NOT be touched by the LLM pass
        assert opt.direction == procedural[i].direction
        assert opt.directive == procedural[i].directive


def test_llm_enrichment_falls_back_on_bad_response() -> None:
    """LLM returning garbage → procedural list passes through unchanged."""
    snap = _build_snapshot()
    procedural = available_mutations(snap, [])
    llm = _StubLLMBackend({"mutations": "not a list"})
    pack = CyberWebappPack()
    options = pack.available_mutations(snap, [], llm=llm)  # type: ignore[arg-type]
    assert len(options) == len(procedural)
    for a, b in zip(options, procedural, strict=False):
        assert a.relevance == b.relevance
        assert a.note == b.note


def test_pack_available_mutations_default_returns_empty() -> None:
    """Packs that don't override get the empty-tuple default and skip
    auto-evolve cleanly."""
    from openrange.core.pack import Pack

    class _BarePack(Pack):
        id = "bare"
        version = "v0"

        @property
        def ontology(self):  # type: ignore[no-untyped-def]
            raise NotImplementedError

        def realize(self, graph, manifest):  # type: ignore[no-untyped-def]
            raise NotImplementedError

    assert _BarePack().available_mutations(None, []) == ()  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Verify Mutation directive can be fed back into evolve()
# ---------------------------------------------------------------------------


def test_chosen_mutation_is_acceptable_to_evolve() -> None:
    """End-to-end: pick a patch mutation and evolve() consumes it."""
    from openrange.core.builder import evolve

    snap = _build_snapshot()
    options = available_mutations(snap, [])
    patch_option = next(o for o in options if "patch" in o.directive)
    # evolve() is the public API — must accept the directive shape
    child = evolve(snap, patch_option.directive)
    assert isinstance(child, type(snap))
    assert child.id != snap.id
    # Lineage carries the directive
    assert child.lineage[-1].curriculum
    assert "patch" in dict(child.lineage[-1].curriculum)
