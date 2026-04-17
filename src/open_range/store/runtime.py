"""Internal runtime hydration helpers for private world and reference material."""

from __future__ import annotations

from open_range.admission import ReferenceBundle
from open_range.contracts.snapshot import RuntimeSnapshot, Snapshot
from open_range.contracts.world import WorldIR
from open_range.store.core import FileSnapshotStore, PoolSplit
from open_range.store.paths import reference_bundle_path, world_path


def load_world_ir(store: FileSnapshotStore, snapshot_id: str) -> WorldIR:
    path = world_path(store.store_dir, snapshot_id)
    return WorldIR.model_validate_json(path.read_text(encoding="utf-8"))


def hydrate_runtime_snapshot(
    store: FileSnapshotStore, snapshot: Snapshot
) -> RuntimeSnapshot:
    world = load_world_ir(store, snapshot.snapshot_id)
    reference_bundle = ReferenceBundle.model_validate_json(
        reference_bundle_path(store.store_dir, snapshot.snapshot_id).read_text(
            encoding="utf-8"
        )
    )
    return RuntimeSnapshot.model_validate(
        {
            **snapshot.model_dump(mode="json"),
            "world": world.model_dump(mode="json"),
            "reference_bundle": reference_bundle.model_dump(mode="json"),
        }
    )


def load_runtime_snapshot(
    store: FileSnapshotStore, snapshot_id: str
) -> RuntimeSnapshot:
    return hydrate_runtime_snapshot(store, store.load(snapshot_id))


def sample_runtime_snapshot(
    store: FileSnapshotStore,
    *,
    split: PoolSplit = "train",
    seed: int | None = None,
    strategy: str = "random",
) -> RuntimeSnapshot:
    return hydrate_runtime_snapshot(
        store, store.sample(split=split, seed=seed, strategy=strategy)
    )
