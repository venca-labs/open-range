"""Seed-state derivation for stored snapshots."""

from __future__ import annotations

from dataclasses import dataclass

from open_range.contracts.snapshot import KindArtifacts
from open_range.contracts.world import WorldIR
from open_range.synth.models import SynthArtifacts


@dataclass(frozen=True, slots=True)
class SnapshotSeedState:
    db_seed_state: dict[str, object]
    file_assets: dict[str, str]
    state_seed_dir: str


def build_seed_state(
    world: WorldIR,
    artifacts: KindArtifacts,
    synth: SynthArtifacts | None,
) -> SnapshotSeedState:
    db_seed_state: dict[str, object] = {
        "services": [svc.id for svc in world.services if svc.kind == "db"]
    }
    file_assets = {asset.id: asset.location for asset in world.assets}
    state_seed_dir = artifacts.render_dir

    if synth is None:
        return SnapshotSeedState(
            db_seed_state=db_seed_state,
            file_assets=file_assets,
            state_seed_dir=state_seed_dir,
        )

    return SnapshotSeedState(
        db_seed_state={
            "services": [svc.id for svc in world.services if svc.kind == "db"],
            "payload_files": [
                item.key for item in synth.service_payloads.get("svc-db", ())
            ],
        },
        file_assets={
            synth_file.key: synth_file.mount_path
            for synth_file in synth.service_payloads.get("svc-fileshare", ())
        },
        state_seed_dir=synth.outdir,
    )
