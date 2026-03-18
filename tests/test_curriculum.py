from __future__ import annotations

from pathlib import Path

from open_range._runtime_store import load_world_ir
from open_range.compiler import EnterpriseSaaSManifestCompiler
from open_range.curriculum import (
    FrontierMutationPolicy,
    PopulationStats,
    propose_mutations,
)
from open_range.pipeline import BuildPipeline
from open_range.store import FileSnapshotStore
from open_range.weaknesses import CatalogWeaknessSeeder
from tests.support import OFFLINE_BUILD_CONFIG, manifest_payload


def _manifest_payload() -> dict:
    payload = manifest_payload()
    payload["objectives"]["red"] = [
        {"predicate": "asset_read(finance_docs)"},
        {"predicate": "credential_obtained(idp_admin_cred)"},
    ]
    return payload


def _seeded_world():
    world = EnterpriseSaaSManifestCompiler().compile(_manifest_payload())
    return CatalogWeaknessSeeder().apply(world)


def test_policy_choose_parent_prefers_frontier_train_world():
    policy = FrontierMutationPolicy()
    population = [
        PopulationStats(
            snapshot_id="snap-hard",
            world_id="world-hard",
            split="train",
            episodes=12,
            red_win_rate=0.05,
            blue_win_rate=0.9,
            flake_rate=0.02,
            novelty=0.8,
            blue_signal_points=5,
        ),
        PopulationStats(
            snapshot_id="snap-frontier",
            world_id="world-frontier",
            split="train",
            episodes=8,
            red_win_rate=0.52,
            blue_win_rate=0.48,
            flake_rate=0.01,
            novelty=0.6,
            blue_signal_points=4,
        ),
        PopulationStats(
            snapshot_id="snap-eval",
            world_id="world-eval",
            split="eval",
            episodes=50,
            red_win_rate=0.5,
            blue_win_rate=0.5,
            flake_rate=0.0,
            novelty=1.0,
            blue_signal_points=6,
        ),
    ]

    assert policy.choose_parent(population) == "snap-frontier"


def test_policy_mutate_is_deterministic_and_tracks_lineage():
    world = _seeded_world()
    policy = FrontierMutationPolicy()
    stats = PopulationStats(
        snapshot_id="snap-parent",
        world_id=world.world_id,
        split="train",
        episodes=10,
        red_win_rate=0.7,
        blue_win_rate=0.3,
        flake_rate=0.02,
        novelty=0.4,
        blue_signal_points=4,
    )

    child_a = policy.mutate(world, parent_stats=stats, child_seed=2026)
    child_b = policy.mutate(world, parent_stats=stats, child_seed=2026)

    assert child_a == child_b
    assert child_a.lineage.generation == world.lineage.generation + 1
    assert child_a.lineage.parent_world_id == world.world_id
    assert child_a.seed == 2026
    assert len(child_a.hosts) <= len(world.hosts) + world.mutation_bounds.max_new_hosts
    assert (
        len(child_a.services)
        <= len(world.services) + world.mutation_bounds.max_new_services
    )
    assert len(child_a.users) <= len(world.users) + world.mutation_bounds.max_new_users
    assert (
        len(child_a.weaknesses)
        <= len(world.weaknesses) + world.mutation_bounds.max_new_weaknesses
    )
    assert child_a.lineage.mutation_ops != world.lineage.mutation_ops
    assert all(weak.realization for weak in child_a.weaknesses)
    assert all(weak.remediation_kind == "shell" for weak in child_a.weaknesses)
    assert all(weak.remediation_command for weak in child_a.weaknesses)


def test_mutated_child_is_admitted_and_can_live_in_eval_pool(tmp_path: Path):
    store = FileSnapshotStore(tmp_path / "snapshots")
    pipeline = BuildPipeline(store=store)
    parent_candidate = pipeline.build(
        _manifest_payload(), tmp_path / "parent-render", OFFLINE_BUILD_CONFIG
    )
    parent_snapshot = pipeline.admit(parent_candidate, split="train")
    parent_world = load_world_ir(store, parent_snapshot.snapshot_id)

    policy = FrontierMutationPolicy()
    child_world = policy.mutate(
        parent_world,
        parent_stats=PopulationStats(
            snapshot_id=parent_snapshot.snapshot_id,
            world_id=parent_world.world_id,
            split="train",
            episodes=6,
            red_win_rate=0.55,
            blue_win_rate=0.45,
            flake_rate=0.01,
            novelty=0.7,
            blue_signal_points=4,
        ),
        child_seed=3030,
    )
    child_snapshot = pipeline.admit_child(
        child_world,
        tmp_path / "child-render",
        split="eval",
        build_config=OFFLINE_BUILD_CONFIG,
    )

    assert child_snapshot.parent_world_id == parent_world.world_id
    assert child_snapshot.validator_report.admitted is True
    assert len(store.list(split="train")) == 1
    assert len(store.list(split="eval")) == 1
    assert (
        store.sample(split="eval", strategy="latest").snapshot_id
        == child_snapshot.snapshot_id
    )


def test_propose_mutations_loads_best_parent_from_store(tmp_path: Path):
    store = FileSnapshotStore(tmp_path / "snapshots")
    pipeline = BuildPipeline(store=store)
    parent_snapshot = pipeline.admit(
        pipeline.build(_manifest_payload(), tmp_path / "render", OFFLINE_BUILD_CONFIG),
        split="train",
    )
    parent_world = load_world_ir(store, parent_snapshot.snapshot_id)

    children = propose_mutations(
        [
            PopulationStats(
                snapshot_id=parent_snapshot.snapshot_id,
                world_id=parent_world.world_id,
                split="train",
                episodes=5,
                red_win_rate=0.5,
                blue_win_rate=0.5,
                flake_rate=0.0,
                novelty=0.5,
                blue_signal_points=4,
            )
        ],
        store=store,
    )

    assert len(children) == 1
    assert children[0].lineage.parent_world_id == parent_world.world_id


def test_mutation_added_weakness_carries_target_metadata():
    world = _seeded_world()
    policy = FrontierMutationPolicy()
    child = policy.mutate(
        world,
        parent_stats=PopulationStats(
            snapshot_id="snap-parent",
            world_id=world.world_id,
            split="train",
            episodes=12,
            red_win_rate=0.2,
            blue_win_rate=0.8,
            flake_rate=0.01,
            novelty=0.5,
            blue_signal_points=4,
        ),
        child_seed=4040,
    )

    assert any(
        weak.target_kind in {"service", "workflow", "asset", "telemetry"}
        for weak in child.weaknesses
    )
    assert all(weak.target_ref for weak in child.weaknesses)


def test_mutation_can_persistently_patch_parent_weakness_and_replace_it():
    world = _seeded_world()
    parent_ids = {weak.id for weak in world.weaknesses}
    policy = FrontierMutationPolicy()
    child = policy.mutate(
        world,
        parent_stats=PopulationStats(
            snapshot_id="snap-parent",
            world_id=world.world_id,
            split="train",
            episodes=10,
            red_win_rate=0.2,
            blue_win_rate=0.8,
            flake_rate=0.01,
            novelty=0.6,
            blue_signal_points=4,
        ),
        child_seed=5050,
    )

    assert any(
        token.startswith("patch_weakness") for token in child.lineage.mutation_ops
    )
    assert parent_ids - {weak.id for weak in child.weaknesses}
    assert child.weaknesses


def test_mutation_can_harden_direct_route_and_expose_alternate_one():
    world = _seeded_world()
    policy = FrontierMutationPolicy()
    child = policy.mutate(
        world,
        parent_stats=PopulationStats(
            snapshot_id="snap-parent",
            world_id=world.world_id,
            split="train",
            episodes=10,
            red_win_rate=0.5,
            blue_win_rate=0.5,
            flake_rate=0.01,
            novelty=0.6,
            blue_signal_points=4,
        ),
        child_seed=6060,
    )

    assert any(
        token.startswith("harden_route_expose_alternate")
        for token in child.lineage.mutation_ops
    )
    assert not any(
        edge.source == "svc-web" and edge.target == "svc-fileshare"
        for edge in child.network_edges
    )
    assert any(
        edge.source == "svc-email" and edge.target.startswith("svc-fileshare")
        for edge in child.network_edges
    )
