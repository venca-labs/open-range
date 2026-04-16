"""Seed-state derivation for stored snapshots."""

from __future__ import annotations

from dataclasses import dataclass

from open_range.snapshot import KindArtifacts
from open_range.synth import SynthArtifacts
from open_range.world_ir import WorldIR


@dataclass(frozen=True, slots=True)
class SnapshotSeedState:
    db_seed_state: dict[str, object]
    mail_state: dict[str, object]
    file_assets: dict[str, str]
    identity_seed: dict[str, object]
    state_seed_dir: str


def build_seed_state(
    world: WorldIR,
    artifacts: KindArtifacts,
    synth: SynthArtifacts | None,
) -> SnapshotSeedState:
    db_seed_state: dict[str, object] = {
        "services": [svc.id for svc in world.services if svc.kind == "db"]
    }
    mail_state: dict[str, object] = {
        "mailboxes": [
            persona.mailbox for persona in world.green_personas if persona.mailbox
        ]
    }
    file_assets = {asset.id: asset.location for asset in world.assets}
    identity_seed: dict[str, object] = {"users": [user.id for user in world.users]}
    state_seed_dir = artifacts.render_dir

    if synth is None:
        return SnapshotSeedState(
            db_seed_state=db_seed_state,
            mail_state=mail_state,
            file_assets=file_assets,
            identity_seed=identity_seed,
            state_seed_dir=state_seed_dir,
        )

    return SnapshotSeedState(
        db_seed_state={
            "services": [svc.id for svc in world.services if svc.kind == "db"],
            "payload_files": [
                item.key for item in synth.service_payloads.get("svc-db", ())
            ],
        },
        mail_state={
            mailbox: list(messages) for mailbox, messages in synth.mailboxes.items()
        },
        file_assets={
            synth_file.key: synth_file.mount_path
            for synth_file in synth.service_payloads.get("svc-fileshare", ())
        },
        identity_seed={
            "users": [user.id for user in world.users],
            "mailboxes": sorted(synth.mailboxes),
        },
        state_seed_dir=synth.outdir,
    )
