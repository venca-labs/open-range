"""Deterministic bounded synthesis for enterprise SaaS worlds."""

from __future__ import annotations

import json
from pathlib import Path

from open_range.contracts.world import WorldIR

from .models import SynthArtifacts, SynthFile
from .payloads import (
    asset_content,
    db_init_sql,
    mailbox_weakness_messages,
    weakness_realization_content,
    web_index_html,
)


class EnterpriseSaaSWorldSynthesizer:
    """Generate bounded deterministic business artifacts from `WorldIR`."""

    def synthesize(self, world: WorldIR, outdir: Path) -> SynthArtifacts:
        outdir = Path(outdir)
        outdir.mkdir(parents=True, exist_ok=True)

        payloads = {
            service.id: tuple(self._service_payloads(world, service.id))
            for service in world.services
        }
        generated: list[str] = []
        for service_id, files in payloads.items():
            service_dir = outdir / service_id
            service_dir.mkdir(parents=True, exist_ok=True)
            for synth_file in files:
                path = service_dir / synth_file.key
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(synth_file.content, encoding="utf-8")
                generated.append(str(path))

        mailboxes = {
            persona.mailbox: tuple(self._mailbox_seed(world, persona.mailbox))
            for persona in world.green_personas
            if persona.mailbox
        }
        summary = {
            "world_id": world.world_id,
            "service_payload_counts": {
                service_id: len(files) for service_id, files in payloads.items()
            },
            "mailbox_message_counts": {
                mailbox: len(messages) for mailbox, messages in mailboxes.items()
            },
        }
        summary_path = outdir / "synth-summary.json"
        summary_path.write_text(
            json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        generated.append(str(summary_path))

        return SynthArtifacts(
            outdir=str(outdir),
            summary_path=str(summary_path),
            service_payloads=payloads,
            mailboxes=mailboxes,
            generated_files=tuple(generated),
        )

    def _service_payloads(self, world: WorldIR, service_id: str) -> list[SynthFile]:
        if service_id == "svc-web":
            payloads = [
                SynthFile(
                    key="index.html",
                    mount_path="/var/www/html/index.html",
                    content=web_index_html(world),
                )
            ]
            payloads.extend(
                SynthFile(
                    key=f"{asset.id}.txt",
                    mount_path=f"/var/www/html/content/{asset.id}.txt",
                    content=asset_content(asset),
                )
                for asset in world.assets
                if asset.owner_service == service_id
            )
            payloads.extend(self._weakness_payloads(world, service_id))
            return payloads
        if service_id == "svc-db":
            payloads = [
                SynthFile(
                    key="01-init.sql",
                    mount_path="/docker-entrypoint-initdb.d/01-init.sql",
                    content=db_init_sql(world),
                )
            ]
            payloads.extend(self._weakness_payloads(world, service_id))
            return payloads
        if service_id == "svc-fileshare":
            payloads = [
                SynthFile(
                    key=f"{asset.id}.txt",
                    mount_path=f"/srv/shared/{asset.id}.txt",
                    content=asset_content(asset),
                )
                for asset in world.assets
                if asset.owner_service == service_id
            ]
            payloads.extend(self._weakness_payloads(world, service_id))
            return payloads
        if service_id == "svc-siem":
            payloads = [
                SynthFile(
                    key="index.html",
                    mount_path="/srv/http/siem/index.html",
                    content="OpenRange SIEM log sink\n",
                ),
            ]
            payloads.extend(self._weakness_payloads(world, service_id))
            return payloads
        return self._weakness_payloads(world, service_id)

    def _mailbox_seed(self, world: WorldIR, mailbox: str) -> list[str]:
        business = world.business_archetype.replace("_", " ")
        seeded = [
            f"Subject: Welcome to {business}\n\nMailbox {mailbox} initialized for {world.world_id}.",
            f"Subject: Workflow digest\n\nTrack {len(world.workflows)} workflows in {world.world_id}.",
        ]
        if world.phishing_surface_enabled:
            seeded.append(
                f"Subject: Password reset review\n\nA routine password reset request is queued for {mailbox} in {world.world_id}."
            )
        seeded.extend(mailbox_weakness_messages(world, mailbox))
        return seeded

    def _weakness_payloads(self, world: WorldIR, service_id: str) -> list[SynthFile]:
        payloads: list[SynthFile] = []
        for weakness in world.weaknesses:
            for realization in weakness.realization:
                if realization.service != service_id:
                    continue
                key = realization.path.lstrip("/").replace("/", "__")
                payloads.append(
                    SynthFile(
                        key=key,
                        mount_path=realization.path,
                        content=weakness_realization_content(
                            world, weakness, realization
                        ),
                    )
                )
        return payloads
