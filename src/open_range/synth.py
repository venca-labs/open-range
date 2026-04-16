"""Deterministic bounded synthesis for enterprise SaaS worlds."""

from __future__ import annotations

import json
import textwrap
from pathlib import Path
from typing import Protocol

from pydantic import BaseModel, ConfigDict, Field

from open_range.code_web import code_web_realization_content
from open_range.weakness_families import (
    has_realization_renderer_for_family,
    render_realization_content_for_family,
)
from open_range.world_ir import (
    AssetSpec,
    WeaknessRealizationSpec,
    WeaknessSpec,
    WorldIR,
)


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class SynthFile(_StrictModel):
    key: str = Field(min_length=1)
    mount_path: str = Field(min_length=1)
    content: str


class SynthArtifacts(_StrictModel):
    outdir: str
    summary_path: str
    service_payloads: dict[str, tuple[SynthFile, ...]] = Field(default_factory=dict)
    mailboxes: dict[str, tuple[str, ...]] = Field(default_factory=dict)
    generated_files: tuple[str, ...] = Field(default_factory=tuple)


class WorldSynthesizer(Protocol):
    def synthesize(self, world: WorldIR, outdir: Path) -> SynthArtifacts: ...


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
            "mailboxes": {
                mailbox: list(messages) for mailbox, messages in mailboxes.items()
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
                    content=_web_index_html(world),
                )
            ]
            payloads.extend(
                SynthFile(
                    key=f"{asset.id}.txt",
                    mount_path=f"/var/www/html/content/{asset.id}.txt",
                    content=_asset_content(asset),
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
                    content=_db_init_sql(world),
                )
            ]
            payloads.extend(self._weakness_payloads(world, service_id))
            return payloads
        if service_id == "svc-fileshare":
            payloads = [
                SynthFile(
                    key=f"{asset.id}.txt",
                    mount_path=f"/srv/shared/{asset.id}.txt",
                    content=_asset_content(asset),
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
        seeded.extend(_mailbox_weakness_messages(world, mailbox))
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
                        content=_weakness_realization_content(
                            world, weakness, realization
                        ),
                    )
                )
        return payloads


def _web_index_html(world: WorldIR) -> str:
    asset_links = (
        "\n".join(
            f'<li><a href="/content/{asset.id}.txt">{asset.id}</a></li>'
            for asset in world.assets
            if asset.owner_service == "svc-web"
        )
        or "<li>No web-hosted assets</li>"
    )
    return textwrap.dedent(
        f"""\
        <html>
          <head><title>{world.business_archetype}</title></head>
          <body>
            <h1>{world.business_archetype}</h1>
            <p>OpenRange seeded portal for {world.world_id}</p>
            <ul>
              {asset_links}
            </ul>
          </body>
        </html>
        """
    )


def _db_init_sql(world: WorldIR) -> str:
    user_rows = "\n".join(
        f"INSERT INTO users (username, password, role, department, email) VALUES ('{user.id}', '{_default_password(user.id)}', '{user.role}', '{user.department}', '{user.email}');"
        for user in world.users
    )
    asset_rows = "\n".join(
        f"INSERT INTO assets (asset_id, asset_class, contents) VALUES ('{asset.id}', '{asset.asset_class}', '{_asset_content(asset)}');"
        for asset in world.assets
        if asset.owner_service == "svc-db"
    )
    return textwrap.dedent(
        f"""\
        CREATE DATABASE IF NOT EXISTS app;
        USE app;
        CREATE TABLE IF NOT EXISTS users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(64) NOT NULL,
            password VARCHAR(128) NOT NULL,
            role VARCHAR(64) NOT NULL,
            department VARCHAR(64) NOT NULL,
            email VARCHAR(128) NOT NULL
        );
        CREATE TABLE IF NOT EXISTS assets (
            id INT AUTO_INCREMENT PRIMARY KEY,
            asset_id VARCHAR(64) NOT NULL,
            asset_class VARCHAR(64) NOT NULL,
            contents TEXT NOT NULL
        );
        {user_rows}
        {asset_rows}
        """
    )


def _asset_content(asset: AssetSpec) -> str:
    return f"seeded-{asset.asset_class}-{asset.id}"


def _default_password(user_id: str) -> str:
    return f"{user_id}-pass"


def _weakness_realization_content(
    world: WorldIR,
    weakness: WeaknessSpec,
    realization: WeaknessRealizationSpec,
) -> str:
    if has_realization_renderer_for_family(weakness.family):
        return render_realization_content_for_family(world, weakness, realization)
    if weakness.family == "code_web":
        return code_web_realization_content(world, weakness, realization)
    raise ValueError(
        f"unsupported realization renderer for weakness family {weakness.family!r}"
    )


def _mailbox_weakness_messages(world: WorldIR, mailbox: str) -> list[str]:
    slug = _mailbox_slug(mailbox)
    messages: list[str] = []
    for weakness in world.weaknesses:
        for realization in weakness.realization:
            if realization.kind != "mailbox":
                continue
            if f"/{slug}/" not in realization.path:
                continue
            messages.append(_weakness_realization_content(world, weakness, realization))
    return messages


def _mailbox_slug(mailbox: str) -> str:
    return mailbox.replace("@", "_at_").replace(".", "_")
