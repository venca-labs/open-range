"""Immutable snapshot persistence with explicit runtime hydration."""

from __future__ import annotations

import json
import shutil
import time
from pathlib import Path
from random import Random
from typing import Literal

from open_range.contracts.snapshot import (
    KindArtifacts,
    RuntimeSnapshot,
    Snapshot,
    world_hash,
)
from open_range.contracts.validation import ReferenceBundle, ValidatorReport
from open_range.contracts.world import WorldIR
from open_range.synth.models import SynthArtifacts

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
        snapshot_id = f"{world.world_id}-{split}-{world_hash(world)[:8]}"
        existing = _snapshot_path(self.store_dir, snapshot_id)
        if existing.exists():
            return self.load(snapshot_id)
        seed_state = build_seed_state(world, artifacts, synth)
        snap_dir = _snapshot_dir(self.store_dir, snapshot_id)
        snap_dir.mkdir(parents=True)
        stored_artifacts = _persist_artifacts_bundle(snap_dir, artifacts)
        stored_state_seed_dir = _persist_state_seed_dir(
            snap_dir,
            seed_state.state_seed_dir,
            source_render_dir=Path(artifacts.render_dir),
            stored_render_dir=Path(stored_artifacts.render_dir),
        )
        public_report = _public_validator_report(
            vr,
            artifacts=stored_artifacts,
        )
        world_json_path = _world_path(self.store_dir, snapshot_id)
        reference_json_path = _reference_bundle_path(self.store_dir, snapshot_id)
        report_json_path = _validator_report_path(self.store_dir, snapshot_id)
        world_json_path.write_text(world.model_dump_json(indent=2), encoding="utf-8")
        reference_json_path.write_text(wb.model_dump_json(indent=2), encoding="utf-8")
        report_json_path.write_text(
            public_report.model_dump_json(indent=2), encoding="utf-8"
        )
        snapshot = Snapshot(
            snapshot_id=snapshot_id,
            world_id=world.world_id,
            seed=world.seed,
            artifacts_dir=stored_artifacts.render_dir,
            image_digests=stored_artifacts.pinned_image_digests,
            state_seed_dir=stored_state_seed_dir,
            validator_report_path=str(report_json_path),
            artifacts=stored_artifacts,
            db_seed_state=seed_state.db_seed_state,
            file_assets=seed_state.file_assets,
            validator_report=public_report,
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
        snapshots: list[tuple[float, str, Snapshot]] = []
        for entry in self.store_dir.iterdir():
            if not entry.is_dir():
                continue
            meta_path = _metadata_path(self.store_dir, entry.name)
            metadata = (
                {"split": "train", "stored_at": 0.0}
                if not meta_path.exists()
                else json.loads(meta_path.read_text(encoding="utf-8"))
            )
            if split is not None and metadata.get("split", "train") != split:
                continue
            path = _snapshot_path(self.store_dir, entry.name)
            if not path.exists():
                continue
            snapshots.append(
                (
                    float(metadata.get("stored_at", 0.0)),
                    entry.name,
                    Snapshot.model_validate_json(path.read_text(encoding="utf-8")),
                )
            )
        snapshots.sort(key=lambda item: (item[0], item[1]))
        return tuple(snapshot for _stored_at, _name, snapshot in snapshots)

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


def _persist_artifacts_bundle(
    snapshot_dir: Path,
    artifacts: KindArtifacts,
) -> KindArtifacts:
    source_render_dir = Path(artifacts.render_dir)
    stored_render_dir = snapshot_dir / "rendered"
    if stored_render_dir.exists():
        shutil.rmtree(stored_render_dir)
    shutil.copytree(source_render_dir, stored_render_dir)
    return KindArtifacts(
        render_dir=str(stored_render_dir),
        chart_dir=_rebase_path(
            artifacts.chart_dir, source_render_dir, stored_render_dir
        ),
        values_path=_rebase_path(
            artifacts.values_path, source_render_dir, stored_render_dir
        ),
        kind_config_path=_rebase_path(
            artifacts.kind_config_path, source_render_dir, stored_render_dir
        ),
        manifest_summary_path=_rebase_path(
            artifacts.manifest_summary_path, source_render_dir, stored_render_dir
        ),
        rendered_files=tuple(
            _rebase_path(path, source_render_dir, stored_render_dir)
            for path in artifacts.rendered_files
            if Path(_rebase_path(path, source_render_dir, stored_render_dir)).exists()
        ),
        chart_values=artifacts.chart_values,
        pinned_image_digests=artifacts.pinned_image_digests,
    )


def _persist_state_seed_dir(
    snapshot_dir: Path,
    source_state_seed_dir: str,
    *,
    source_render_dir: Path,
    stored_render_dir: Path,
) -> str:
    rebased = _rebase_path(source_state_seed_dir, source_render_dir, stored_render_dir)
    rebased_path = Path(rebased)
    if rebased_path.exists():
        return str(rebased_path)
    source_path = Path(source_state_seed_dir)
    stored_state_dir = snapshot_dir / "state-seed"
    if stored_state_dir.exists():
        shutil.rmtree(stored_state_dir)
    shutil.copytree(source_path, stored_state_dir)
    return str(stored_state_dir)


def _rebase_path(path: str, source_root: Path, stored_root: Path) -> str:
    source_path = Path(path)
    try:
        relative = source_path.relative_to(source_root)
    except ValueError:
        return str(source_path)
    return str(stored_root / relative)


def _public_validator_report(
    report: ValidatorReport,
    *,
    artifacts: KindArtifacts,
) -> ValidatorReport:
    public_health_info = dict(report.health_info)
    if "render_dir" in public_health_info:
        public_health_info["render_dir"] = artifacts.render_dir
    return report.model_copy(
        update={
            "build_logs": artifacts.rendered_files,
            "health_info": public_health_info,
            "stages": tuple(
                stage.model_copy(
                    update={
                        "checks": tuple(
                            check.model_copy(update={"details": {}})
                            for check in stage.checks
                        )
                    }
                )
                for stage in report.stages
            ),
        }
    )


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
