"""Immutable snapshot persistence with explicit runtime hydration."""

from __future__ import annotations

import json
import time
from pathlib import Path
from random import Random
from typing import Literal, Protocol

from open_range.admission import ReferenceBundle, ValidatorReport
from open_range.contracts.snapshot import (
    KindArtifacts,
    RuntimeSnapshot,
    Snapshot,
    world_hash,
)
from open_range.contracts.world import WorldIR
from open_range.synth import SynthArtifacts

from .seed_state import build_seed_state

PoolSplit = Literal["train", "eval"]


def _snapshot_dir(store_dir: str | Path, snapshot_id: str) -> Path:
    return Path(store_dir) / snapshot_id


def _snapshot_path(store_dir: str | Path, snapshot_id: str) -> Path:
    return _snapshot_dir(store_dir, snapshot_id) / "snapshot.json"


def _metadata_path(store_dir: str | Path, snapshot_id: str) -> Path:
    return _snapshot_dir(store_dir, snapshot_id) / "metadata.json"


def _world_path(store_dir: str | Path, snapshot_id: str) -> Path:
    return _snapshot_dir(store_dir, snapshot_id) / "world.json"


def _reference_bundle_path(store_dir: str | Path, snapshot_id: str) -> Path:
    return _snapshot_dir(store_dir, snapshot_id) / "reference_bundle.json"


def _validator_report_path(store_dir: str | Path, snapshot_id: str) -> Path:
    return _snapshot_dir(store_dir, snapshot_id) / "validator_report.json"


class SnapshotStore(Protocol):
    def create(
        self,
        world: WorldIR,
        artifacts: KindArtifacts,
        wb: ReferenceBundle,
        vr: ValidatorReport,
        synth: SynthArtifacts | None = None,
        *,
        split: PoolSplit = "train",
    ) -> Snapshot: ...
    def load(self, snapshot_id: str) -> Snapshot: ...
    def list(self, *, split: PoolSplit | None = None) -> tuple[Snapshot, ...]: ...
    def sample(
        self,
        *,
        split: PoolSplit = "train",
        seed: int | None = None,
        strategy: Literal["random", "latest"] = "random",
    ) -> Snapshot: ...


class FileSnapshotStore:
    """Persist immutable snapshots as JSON on disk."""

    def __init__(self, store_dir: str | Path = "snapshots") -> None:
        self.store_dir = Path(store_dir)
        self.store_dir.mkdir(parents=True, exist_ok=True)

    def create(
        self,
        world: WorldIR,
        artifacts: KindArtifacts,
        wb: ReferenceBundle,
        vr: ValidatorReport,
        synth: SynthArtifacts | None = None,
        *,
        split: PoolSplit = "train",
    ) -> Snapshot:
        seed_state = build_seed_state(world, artifacts, synth)
        snapshot_id = f"{world.world_id}-{world_hash(world)[:8]}"
        snap_dir = _snapshot_dir(self.store_dir, snapshot_id)
        snap_dir.mkdir(parents=True, exist_ok=True)
        world_json_path = _world_path(self.store_dir, snapshot_id)
        reference_json_path = _reference_bundle_path(self.store_dir, snapshot_id)
        report_json_path = _validator_report_path(self.store_dir, snapshot_id)
        world_json_path.write_text(world.model_dump_json(indent=2), encoding="utf-8")
        reference_json_path.write_text(wb.model_dump_json(indent=2), encoding="utf-8")
        report_json_path.write_text(vr.model_dump_json(indent=2), encoding="utf-8")
        snapshot = Snapshot(
            snapshot_id=snapshot_id,
            world_id=world.world_id,
            seed=world.seed,
            artifacts_dir=artifacts.render_dir,
            image_digests=artifacts.pinned_image_digests,
            state_seed_dir=seed_state.state_seed_dir,
            validator_report_path=str(report_json_path),
            artifacts=artifacts,
            db_seed_state=seed_state.db_seed_state,
            mail_state=seed_state.mail_state,
            file_assets=seed_state.file_assets,
            identity_seed=seed_state.identity_seed,
            validator_report=vr,
            world_hash=world_hash(world),
            parent_snapshot_id=None,
            parent_world_id=world.lineage.parent_world_id,
        )
        _snapshot_path(self.store_dir, snapshot_id).write_text(
            snapshot.model_dump_json(indent=2), encoding="utf-8"
        )
        _metadata_path(self.store_dir, snapshot_id).write_text(
            json.dumps(
                {
                    "snapshot_id": snapshot_id,
                    "world_id": world.world_id,
                    "world_hash": snapshot.world_hash,
                    "stored_at": time.time(),
                    "weakness_count": len(world.weaknesses),
                    "service_count": len(world.services),
                    "split": split,
                },
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        return snapshot

    def load(self, snapshot_id: str) -> Snapshot:
        path = _snapshot_path(self.store_dir, snapshot_id)
        if not path.exists():
            raise FileNotFoundError(snapshot_id)
        return Snapshot.model_validate_json(path.read_text(encoding="utf-8"))

    def list(self, *, split: PoolSplit | None = None) -> tuple[Snapshot, ...]:
        snapshots: list[Snapshot] = []
        for entry in sorted(self.store_dir.iterdir(), key=lambda path: path.name):
            if not entry.is_dir():
                continue
            meta_path = _metadata_path(self.store_dir, entry.name)
            metadata = (
                {"split": "train"}
                if not meta_path.exists()
                else json.loads(meta_path.read_text(encoding="utf-8"))
            )
            if split is not None and metadata.get("split", "train") != split:
                continue
            path = _snapshot_path(self.store_dir, entry.name)
            if not path.exists():
                continue
            snapshots.append(
                Snapshot.model_validate_json(path.read_text(encoding="utf-8"))
            )
        return tuple(snapshots)

    def sample(
        self,
        *,
        split: PoolSplit = "train",
        seed: int | None = None,
        strategy: Literal["random", "latest"] = "random",
    ) -> Snapshot:
        snapshots = list(self.list(split=split))
        if not snapshots:
            raise FileNotFoundError(f"no snapshots available in split {split!r}")
        if strategy == "latest":
            return snapshots[-1]
        if strategy != "random":
            raise ValueError("strategy must be 'random' or 'latest'")
        rng = Random(seed)
        return snapshots[rng.randrange(len(snapshots))]


def load_world_ir(store: FileSnapshotStore, snapshot_id: str) -> WorldIR:
    path = _world_path(store.store_dir, snapshot_id)
    return WorldIR.model_validate_json(path.read_text(encoding="utf-8"))


def hydrate_runtime_snapshot(
    store: FileSnapshotStore, snapshot: Snapshot
) -> RuntimeSnapshot:
    world = load_world_ir(store, snapshot.snapshot_id)
    reference_bundle = ReferenceBundle.model_validate_json(
        _reference_bundle_path(store.store_dir, snapshot.snapshot_id).read_text(
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
