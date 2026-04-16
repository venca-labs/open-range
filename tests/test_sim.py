from __future__ import annotations

from pathlib import Path

from open_range._reference_sim import ReferenceSimPlane
from open_range._runtime_store import hydrate_runtime_snapshot
from open_range.admit import LocalAdmissionController
from open_range.compiler import EnterpriseSaaSManifestCompiler
from open_range.render import EnterpriseSaaSKindRenderer
from open_range.store import FileSnapshotStore
from open_range.synth import EnterpriseSaaSWorldSynthesizer
from open_range.weaknesses import CatalogWeaknessSeeder
from tests.support import OFFLINE_BUILD_CONFIG, manifest_payload


def _manifest_payload() -> dict:
    return manifest_payload()


def _snapshot(tmp_path: Path):
    world = CatalogWeaknessSeeder().apply(
        EnterpriseSaaSManifestCompiler().compile(_manifest_payload())
    )
    synth = EnterpriseSaaSWorldSynthesizer().synthesize(world, tmp_path / "synth")
    artifacts = EnterpriseSaaSKindRenderer().render(world, synth, tmp_path / "rendered")
    reference_bundle, report = LocalAdmissionController(mode="fail_fast").admit(
        world, artifacts, OFFLINE_BUILD_CONFIG
    )
    store = FileSnapshotStore(tmp_path / "snapshots")
    return hydrate_runtime_snapshot(
        store, store.create(world, artifacts, reference_bundle, report, synth=synth)
    )


def test_reference_sim_plane_generates_deterministic_bootstrap_trace(tmp_path: Path):
    snapshot = _snapshot(tmp_path)
    plane = ReferenceSimPlane()

    trace_a = plane.generate_bootstrap_trace(snapshot, episode_seed=7)
    trace_b = plane.generate_bootstrap_trace(snapshot, episode_seed=7)

    assert trace_a == trace_b
    assert trace_a.turns
    assert {turn.role for turn in trace_a.turns} == {"red", "blue"}
