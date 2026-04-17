"""Immutable snapshot persistence with explicit runtime hydration."""

from __future__ import annotations

import hashlib
import json
import shutil
import time
from pathlib import Path
from random import Random
from typing import Literal

import yaml

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


def _runtime_bundle_path(store_dir: str | Path, snapshot_id: str) -> Path:
    return _snapshot_dir(store_dir, snapshot_id) / "runtime_bundle.json"


def _snapshot_fingerprint(
    wb: ReferenceBundle,
    vr: ValidatorReport,
    artifacts: KindArtifacts,
) -> str:
    payload = {
        "references": wb.model_dump(mode="json"),
        "mode": vr.mode,
        "artifacts": _artifacts_fingerprint(artifacts),
        "stages": [
            {
                "name": stage.name,
                "checks": [check.name for check in stage.checks],
            }
            for stage in vr.stages
        ],
    }
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()[:8]


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
        snapshot_id = (
            f"{world.world_id}-{split}-{world_hash(world)[:8]}-"
            f"{_snapshot_fingerprint(wb, vr, artifacts)}"
        )
        existing = _snapshot_path(self.store_dir, snapshot_id)
        if existing.exists():
            return self.load(snapshot_id)
        seed_state = build_seed_state(world, artifacts, synth)
        snap_dir = _snapshot_dir(self.store_dir, snapshot_id)
        snap_dir.mkdir(parents=True)
        public_artifacts, runtime_artifacts = _persist_artifacts_bundle(
            snap_dir, artifacts
        )
        public_state_seed_dir, runtime_state_seed_dir = _persist_state_seed_dirs(
            snap_dir,
            seed_state.state_seed_dir,
            source_render_dir=Path(artifacts.render_dir),
            runtime_render_dir=Path(runtime_artifacts.render_dir),
        )
        public_report = _public_validator_report(
            vr,
            artifacts=public_artifacts,
        )
        world_json_path = _world_path(self.store_dir, snapshot_id)
        reference_json_path = _reference_bundle_path(self.store_dir, snapshot_id)
        report_json_path = _validator_report_path(self.store_dir, snapshot_id)
        runtime_bundle_json_path = _runtime_bundle_path(self.store_dir, snapshot_id)
        world_json_path.write_text(world.model_dump_json(indent=2), encoding="utf-8")
        reference_json_path.write_text(wb.model_dump_json(indent=2), encoding="utf-8")
        report_json_path.write_text(
            public_report.model_dump_json(indent=2), encoding="utf-8"
        )
        runtime_bundle_json_path.write_text(
            json.dumps(
                {
                    "artifacts": runtime_artifacts.model_dump(mode="json"),
                    "state_seed_dir": runtime_state_seed_dir,
                    "db_seed_state": seed_state.db_seed_state,
                    "file_assets": seed_state.file_assets,
                },
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        snapshot = Snapshot(
            snapshot_id=snapshot_id,
            world_id=world.world_id,
            seed=world.seed,
            artifacts_dir=public_artifacts.render_dir,
            image_digests=public_artifacts.pinned_image_digests,
            state_seed_dir=public_state_seed_dir,
            validator_report_path=str(report_json_path),
            artifacts=public_artifacts,
            db_seed_state={},
            file_assets={},
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
) -> tuple[KindArtifacts, KindArtifacts]:
    source_render_dir = Path(artifacts.render_dir)
    public_render_dir = snapshot_dir / "rendered"
    runtime_render_dir = snapshot_dir / "runtime-rendered"
    for stored_render_dir in (public_render_dir, runtime_render_dir):
        if stored_render_dir.exists():
            shutil.rmtree(stored_render_dir)
        shutil.copytree(source_render_dir, stored_render_dir)

    public_chart_values = _public_chart_values(artifacts.chart_values)
    _sanitize_public_render_tree(
        source_render_dir=source_render_dir,
        stored_render_dir=public_render_dir,
        artifacts=artifacts,
        chart_values=public_chart_values,
    )
    return (
        _rebased_artifacts(
            artifacts,
            source_render_dir=source_render_dir,
            stored_render_dir=public_render_dir,
            chart_values=public_chart_values,
        ),
        _rebased_artifacts(
            artifacts,
            source_render_dir=source_render_dir,
            stored_render_dir=runtime_render_dir,
            chart_values=artifacts.chart_values,
        ),
    )


def _persist_state_seed_dirs(
    snapshot_dir: Path,
    source_state_seed_dir: str,
    *,
    source_render_dir: Path,
    runtime_render_dir: Path,
) -> tuple[str, str]:
    public_state_dir = snapshot_dir / "state-seed"
    if public_state_dir.exists():
        shutil.rmtree(public_state_dir)
    public_state_dir.mkdir(parents=True)

    rebased = _rebase_path(source_state_seed_dir, source_render_dir, runtime_render_dir)
    rebased_path = Path(rebased)
    if rebased_path.exists():
        return str(public_state_dir), str(rebased_path)
    source_path = Path(source_state_seed_dir)
    runtime_state_dir = snapshot_dir / "runtime-state-seed"
    if runtime_state_dir.exists():
        shutil.rmtree(runtime_state_dir)
    shutil.copytree(source_path, runtime_state_dir)
    return str(public_state_dir), str(runtime_state_dir)


def _rebase_path(path: str, source_root: Path, stored_root: Path) -> str:
    source_path = Path(path)
    try:
        relative = source_path.relative_to(source_root)
    except ValueError:
        return str(source_path)
    return str(stored_root / relative)


def _persist_rendered_file(path: str, source_root: Path, stored_root: Path) -> str:
    rebased = _rebase_path(path, source_root, stored_root)
    rebased_path = Path(rebased)
    if rebased_path.exists():
        return str(rebased_path)
    source_path = Path(path)
    if not source_path.exists():
        return ""
    external_dir = stored_root / "_external"
    external_dir.mkdir(parents=True, exist_ok=True)
    digest = hashlib.sha256(str(source_path).encode("utf-8")).hexdigest()[:8]
    target_path = external_dir / f"{source_path.stem}-{digest}{source_path.suffix}"
    shutil.copy2(source_path, target_path)
    return str(target_path)


def _rebased_artifacts(
    artifacts: KindArtifacts,
    *,
    source_render_dir: Path,
    stored_render_dir: Path,
    chart_values: dict[str, object],
) -> KindArtifacts:
    stored_rendered_files = tuple(
        stored_path
        for path in artifacts.rendered_files
        if (
            stored_path := _persist_rendered_file(
                path, source_render_dir, stored_render_dir
            )
        )
    )
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
        rendered_files=stored_rendered_files,
        chart_values=chart_values,
        pinned_image_digests=artifacts.pinned_image_digests,
    )


def _public_chart_values(chart_values: dict[str, object]) -> dict[str, object]:
    public_values = json.loads(json.dumps(chart_values))
    public_values.pop("security", None)
    services = public_values.get("services", {})
    if not isinstance(services, dict):
        return public_values
    for service in services.values():
        if not isinstance(service, dict):
            continue
        for payload in service.get("payloads", ()):
            if isinstance(payload, dict):
                payload.pop("content", None)
        for sidecar in service.get("sidecars", ()):
            if not isinstance(sidecar, dict):
                continue
            for payload in sidecar.get("payloads", ()):
                if isinstance(payload, dict):
                    payload.pop("content", None)
    return public_values


def _sanitize_public_render_tree(
    *,
    source_render_dir: Path,
    stored_render_dir: Path,
    artifacts: KindArtifacts,
    chart_values: dict[str, object],
) -> None:
    for relative in ("security", "synth"):
        path = stored_render_dir / relative
        if path.exists():
            shutil.rmtree(path)
    values_path = Path(
        _rebase_path(artifacts.values_path, source_render_dir, stored_render_dir)
    )
    values_path.write_text(
        yaml.safe_dump(chart_values, sort_keys=False),
        encoding="utf-8",
    )
    summary_path = Path(
        _rebase_path(
            artifacts.manifest_summary_path, source_render_dir, stored_render_dir
        )
    )
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    summary["values_hash"] = hashlib.sha256(
        json.dumps(chart_values, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    summary_path.write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _artifacts_fingerprint(artifacts: KindArtifacts) -> str:
    render_dir = Path(artifacts.render_dir)
    digest = hashlib.sha256()
    for path in sorted(path for path in render_dir.rglob("*") if path.is_file()):
        digest.update(str(path.relative_to(render_dir)).encode("utf-8"))
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()[:8]


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
    runtime_bundle = json.loads(
        _runtime_bundle_path(store.store_dir, snapshot.snapshot_id).read_text(
            encoding="utf-8"
        )
    )
    runtime_artifacts = KindArtifacts.model_validate(runtime_bundle["artifacts"])
    return RuntimeSnapshot.model_validate(
        {
            **snapshot.model_dump(mode="json"),
            "artifacts_dir": runtime_artifacts.render_dir,
            "state_seed_dir": runtime_bundle["state_seed_dir"],
            "artifacts": runtime_artifacts.model_dump(mode="json"),
            "db_seed_state": runtime_bundle["db_seed_state"],
            "file_assets": runtime_bundle["file_assets"],
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
