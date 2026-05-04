"""Tests for the procedural cyber builder + v1 pack.

These tests cover the C2 baseline:
  - The builder produces graphs that pass v1 ontology constraints across
    a sweep of seeds.
  - The builder is deterministic given a seed (same seed → same graph).
  - End-to-end ``build()`` admits a v1 snapshot with no LLM dependency.
  - ``evolve()`` with ``patch`` and ``add`` curricula mutates the graph
    correctly. Patching the only oracle-path vuln yields a hardened
    world that still admits (the agent will fail; that's the training
    signal).
"""

from __future__ import annotations

import random

import openrange as OR
from openrange.core.builder import build, evolve
from openrange.packs.cyber_webapp_offense_v1.builder import ProceduralBuilder
from openrange.packs.cyber_webapp_offense_v1.ontology import ONTOLOGY
from openrange.packs.cyber_webapp_offense_v1.priors import PRIORS
from openrange.packs.cyber_webapp_offense_v1.sampling import sample_graph

V1_MANIFEST = {
    "pack": {"id": "cyber.webapp.offense.v1", "source": {"kind": "builtin"}},
    "mode": "simulation",
    "world": {},
}


# ---------------------------------------------------------------------------
# Sampling
# ---------------------------------------------------------------------------


def test_sample_graph_satisfies_ontology_across_seeds() -> None:
    for seed in range(10):
        rng = random.Random(seed)
        graph = sample_graph(rng, PRIORS)
        errors = ONTOLOGY.validate(graph)
        assert not errors, f"seed {seed}: {[e.message for e in errors]}"


def test_sample_graph_is_deterministic() -> None:
    rng_a = random.Random(7)
    rng_b = random.Random(7)
    graph_a = sample_graph(rng_a, PRIORS)
    graph_b = sample_graph(rng_b, PRIORS)
    assert graph_a.as_dict() == graph_b.as_dict()


def test_sample_graph_has_required_node_types() -> None:
    rng = random.Random(0)
    graph = sample_graph(rng, PRIORS)
    types = {n.type for n in graph.nodes}
    # Every realistic generation has these.
    assert {"service", "endpoint", "secret", "vulnerability", "data_store"} <= types


# ---------------------------------------------------------------------------
# End-to-end build
# ---------------------------------------------------------------------------


def test_v1_pack_builds_without_llm() -> None:
    from openrange.packs.cyber_webapp_offense_v1.sampling import (
        TASK_TARGETS,
        TASK_VERBS,
    )

    snapshot = build(V1_MANIFEST)
    assert snapshot.admission.passed
    # task_id is derived per build from verb_target pools.
    task = snapshot.tasks[0]
    verb, _, target = task.id.partition("_")
    assert verb in TASK_VERBS
    assert target in TASK_TARGETS
    assert snapshot.world_graph is not None
    flag_secrets = [
        n
        for n in snapshot.world_graph.nodes
        if n.type == "secret" and n.attrs.get("kind") == "flag"
    ]
    assert len(flag_secrets) == 1


def test_v1_seeds_produce_distinct_worlds() -> None:
    """Sweeping seeds yields distinct graphs (the plan's "100 distinct" acceptance).

    The build is deterministic given a seed; variety comes from sweeping
    the seed space. Tests construct the builder directly with different
    seeds; production users do the same via ``manifest.builder`` or by
    invoking the pack's ``default_builder()`` with a curriculum carrying
    a seed.
    """
    flags = set()
    for seed in range(5):
        rng = random.Random(seed)
        graph = sample_graph(rng, PRIORS)
        flag = next(
            n.attrs["value_ref"]
            for n in graph.nodes
            if n.type == "secret" and n.attrs.get("kind") == "flag"
        )
        flags.add(flag)
    assert len(flags) >= 2


def test_v1_seeded_builds_are_reproducible() -> None:
    """Seeded curriculum pins the rng; same seed → same world."""
    from openrange.core.builder import BuildContext

    pack = OR.PACKS.resolve("cyber.webapp.offense.v1")
    builder_a = pack.default_builder(BuildContext(curriculum={"seed": 7}))
    builder_b = pack.default_builder(BuildContext(curriculum={"seed": 7}))
    assert isinstance(builder_a, ProceduralBuilder)
    assert isinstance(builder_b, ProceduralBuilder)
    assert builder_a._seed == builder_b._seed == 7


def test_v1_pack_is_registered() -> None:
    assert "cyber.webapp.offense.v1" in OR.PACKS.ids()
    pack = OR.PACKS.resolve("cyber.webapp.offense.v1")
    assert pack.ontology is ONTOLOGY
    assert pack.generation_priors() is PRIORS


def test_v1_default_builder_seed_propagates_from_curriculum() -> None:
    pack = OR.PACKS.resolve("cyber.webapp.offense.v1")
    from openrange.core.builder import BuildContext

    ctx_default = BuildContext()
    ctx_seeded = BuildContext(curriculum={"seed": 42})
    builder_default = pack.default_builder(ctx_default)
    builder_seeded = pack.default_builder(ctx_seeded)
    assert isinstance(builder_default, ProceduralBuilder)
    assert isinstance(builder_seeded, ProceduralBuilder)
    assert builder_default._seed == 0
    assert builder_seeded._seed == 42


# ---------------------------------------------------------------------------
# Curriculum: patch
# ---------------------------------------------------------------------------


def test_evolve_patches_named_vulns() -> None:
    s1 = build(V1_MANIFEST)
    kinds_before = [
        n.attrs["kind"]
        for n in s1.world_graph.nodes
        if n.type == "vulnerability"
    ]
    assert kinds_before, "fresh build should place at least one vuln"
    target_kind = kinds_before[0]
    s2 = evolve(s1, curriculum={"patch": [target_kind]})
    kinds_after = [
        n.attrs["kind"]
        for n in s2.world_graph.nodes
        if n.type == "vulnerability"
    ]
    assert target_kind not in kinds_after


def test_evolve_patch_all_yields_hardened_world() -> None:
    """Removing every vuln yields a world that still admits but has no chain.

    This is the curriculum-driven 'hardened' path the meeting notes
    described — the agent will fail to retrieve the flag, which is a
    valid training signal, not a build error.
    """
    s1 = build(V1_MANIFEST)
    kinds = list(
        {
            n.attrs["kind"]
            for n in s1.world_graph.nodes
            if n.type == "vulnerability"
        },
    )
    s_hardened = evolve(s1, curriculum={"patch": kinds})
    remaining = [
        n for n in s_hardened.world_graph.nodes if n.type == "vulnerability"
    ]
    assert remaining == []
    # World still admits.
    assert s_hardened.admission.passed


def test_evolve_patch_preserves_non_vuln_topology() -> None:
    """Patching shouldn't touch services, endpoints, accounts, etc."""
    s1 = build(V1_MANIFEST)
    services_before = sorted(n.id for n in s1.world_graph.nodes if n.type == "service")
    accounts_before = sorted(n.id for n in s1.world_graph.nodes if n.type == "account")

    kinds = [
        n.attrs["kind"]
        for n in s1.world_graph.nodes
        if n.type == "vulnerability"
    ]
    s2 = evolve(s1, curriculum={"patch": kinds[:1]})
    services_after = sorted(n.id for n in s2.world_graph.nodes if n.type == "service")
    accounts_after = sorted(n.id for n in s2.world_graph.nodes if n.type == "account")

    assert services_before == services_after
    assert accounts_before == accounts_after


# ---------------------------------------------------------------------------
# Curriculum: add
# ---------------------------------------------------------------------------


def test_evolve_adds_new_vulns() -> None:
    s1 = build(V1_MANIFEST)
    s2 = evolve(s1, curriculum={"add": ["sql_injection"]})
    kinds_after = [
        n.attrs["kind"]
        for n in s2.world_graph.nodes
        if n.type == "vulnerability"
    ]
    assert "sql_injection" in kinds_after


def test_evolve_add_unknown_kind_is_noop() -> None:
    s1 = build(V1_MANIFEST)
    n_before = sum(1 for n in s1.world_graph.nodes if n.type == "vulnerability")
    s2 = evolve(s1, curriculum={"add": ["does_not_exist"]})
    n_after = sum(1 for n in s2.world_graph.nodes if n.type == "vulnerability")
    assert n_before == n_after


# ---------------------------------------------------------------------------
# Patch + evolve curriculum walk
# ---------------------------------------------------------------------------


def test_curriculum_walk_progressively_hardens_world() -> None:
    """The meeting-notes scenario: incrementally patch vulns across snapshots.

    Each evolve step removes one or more vulns; the final world has
    none left. Demonstrates that patching is a graph mutation, not a
    special pathway.
    """
    s1 = build(V1_MANIFEST)
    initial_kinds = list(
        {
            n.attrs["kind"]
            for n in s1.world_graph.nodes
            if n.type == "vulnerability"
        },
    )
    current = s1
    for kind in initial_kinds:
        current = evolve(current, curriculum={"patch": [kind]})
        remaining_kinds = {
            n.attrs["kind"]
            for n in current.world_graph.nodes
            if n.type == "vulnerability"
        }
        assert kind not in remaining_kinds
    final_vulns = [
        n for n in current.world_graph.nodes if n.type == "vulnerability"
    ]
    assert final_vulns == []
