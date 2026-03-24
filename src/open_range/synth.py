"""Deterministic bounded synthesis for enterprise SaaS worlds."""

from __future__ import annotations

import json
import textwrap
from pathlib import Path
from typing import Protocol

from pydantic import BaseModel, ConfigDict, Field

from open_range.code_web import code_web_realization_content
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
    if weakness.family == "config_identity":
        return _config_identity_content(world, weakness)
    if weakness.family == "workflow_abuse":
        if realization.kind == "mailbox":
            return _workflow_mailbox_content(world, weakness, realization)
        return _workflow_content(world, weakness)
    if weakness.family == "code_web":
        return code_web_realization_content(world, weakness, realization)
    if weakness.family == "telemetry_blindspot":
        return _telemetry_content(world, weakness)
    if realization.kind == "mailbox":
        return _secret_mailbox_content(world, weakness, realization)
    if weakness.kind == "env_file_leak":
        return _env_file_content(world, weakness)
    if weakness.kind == "backup_leak":
        return _backup_leak_content(world, weakness)
    if weakness.kind == "hardcoded_app_secret":
        return _hardcoded_app_secret_content(world, weakness)
    exposed = weakness.target_ref or weakness.target
    secret_material = _secret_material(world, exposed)
    return textwrap.dedent(
        f"""\
        OpenRange exposed material
        world_id={world.world_id}
        weakness_id={weakness.id}
        kind={weakness.kind}
        exposed_ref={exposed}
        secret_material={secret_material}
        remediation={weakness.remediation}
        """
    )


def _secret_material(world: WorldIR, exposed_ref: str) -> str:
    asset = next((asset for asset in world.assets if asset.id == exposed_ref), None)
    if asset is not None:
        return _asset_content(asset)
    user = next((user for user in world.users if user.id == exposed_ref), None)
    if user is not None:
        return _default_password(user.id)
    credential = next(
        (
            credential
            for credential in world.credentials
            if credential.id == exposed_ref
        ),
        None,
    )
    if credential is not None:
        return f"seeded-secret-{credential.id}"
    if exposed_ref.endswith("_cred") or exposed_ref.endswith("_token"):
        return f"seeded-secret-{exposed_ref}"
    return exposed_ref


def _config_identity_content(world: WorldIR, weakness: WeaknessSpec) -> str:
    payload = {
        "world_id": world.world_id,
        "weakness_id": weakness.id,
        "kind": weakness.kind,
        "target": weakness.target,
        "target_ref": weakness.target_ref,
        "mfa_required": False,
        "privileged_scope_validation": False,
    }
    if weakness.kind == "weak_password":
        payload.update({"min_password_length": 6, "password_reuse_allowed": True})
    elif weakness.kind == "default_credential":
        payload.update({"default_username": "admin", "default_password": "admin"})
    elif weakness.kind == "overbroad_service_account":
        payload.update(
            {"service_account_scope": ["svc-db", "svc-fileshare", "svc-idp"]}
        )
    elif weakness.kind == "admin_surface_exposed":
        payload.update({"admin_surface_public": True, "debug_toggle": True})
    elif weakness.kind == "trust_edge_misconfig":
        payload.update({"trust_scope": "corp-wide", "peer_validation": False})
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


def _workflow_content(world: WorldIR, weakness: WeaknessSpec) -> str:
    payload = {
        "world_id": world.world_id,
        "weakness_id": weakness.id,
        "kind": weakness.kind,
        "target_ref": weakness.target_ref,
        "approval_guard": "disabled",
    }
    if weakness.kind == "helpdesk_reset_bypass":
        payload.update(
            {"identity_verification": "none", "reset_without_ticket_owner": True}
        )
    elif weakness.kind == "approval_chain_bypass":
        payload.update({"required_approvals": 1, "secondary_approval_skipped": True})
    elif weakness.kind == "document_share_abuse":
        payload.update(
            {"share_visibility": "public_link", "expiration_required": False}
        )
    elif weakness.kind == "phishing_credential_capture":
        payload.update(
            {"mail_filtering": "allow", "credential_capture_landing": "/login"}
        )
    elif weakness.kind == "internal_request_impersonation":
        payload.update(
            {"sender_verification": "disabled", "internal_alias_trust": True}
        )
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


def _workflow_mailbox_content(
    world: WorldIR, weakness: WeaknessSpec, realization: WeaknessRealizationSpec
) -> str:
    subject = "Password reset verification"
    body = "Confirm your account details to complete the request."
    if weakness.kind == "internal_request_impersonation":
        subject = "Urgent internal request"
        body = "Please share the requested file and credentials for the finance review."
    return textwrap.dedent(
        f"""\
        Subject: {subject}

        OpenRange workflow message for {world.world_id}
        weakness_id={weakness.id}
        kind={weakness.kind}
        mailbox_path={realization.path}
        action={body}
        """
    )


def _telemetry_content(world: WorldIR, weakness: WeaknessSpec) -> str:
    payload = {
        "world_id": world.world_id,
        "weakness_id": weakness.id,
        "kind": weakness.kind,
        "target": weakness.target,
        "ship_to_siem": False,
    }
    if weakness.kind == "missing_web_logs":
        payload.update({"access_logs_enabled": False, "error_logs_enabled": False})
    elif weakness.kind == "missing_idp_logs":
        payload.update({"auth_logs_enabled": False, "audit_logs_enabled": False})
    elif weakness.kind == "delayed_siem_ingest":
        payload.update({"delay_seconds": 180})
    elif weakness.kind == "unmonitored_admin_action":
        payload.update({"admin_actions_logged": False})
    elif weakness.kind == "silent_mail_rule":
        payload.update(
            {"mail_rule_logging": False, "mailbox_auto_forward_alerting": False}
        )
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


def _secret_mailbox_content(
    world: WorldIR, weakness: WeaknessSpec, realization: WeaknessRealizationSpec
) -> str:
    secret_material = _secret_material(world, weakness.target_ref or weakness.target)
    return textwrap.dedent(
        f"""\
        Subject: Security review follow-up

        OpenRange mailbox message for {world.world_id}
        weakness_id={weakness.id}
        kind={weakness.kind}
        mailbox_path={realization.path}
        secret_material={secret_material}
        """
    )


def _env_file_content(world: WorldIR, weakness: WeaknessSpec) -> str:
    secret_material = _secret_material(world, weakness.target_ref or weakness.target)
    return textwrap.dedent(
        f"""\
        APP_ENV=production
        APP_DEBUG=false
        OPENRANGE_WORLD_ID={world.world_id}
        OPENRANGE_APP_SECRET={secret_material}
        """
    )


def _backup_leak_content(world: WorldIR, weakness: WeaknessSpec) -> str:
    secret_material = _secret_material(world, weakness.target_ref or weakness.target)
    return textwrap.dedent(
        f"""\
        -- OpenRange backup export
        -- world_id={world.world_id}
        INSERT INTO leaked_credentials(secret_ref, secret_value) VALUES ('{weakness.target_ref}', '{secret_material}');
        """
    )


def _hardcoded_app_secret_content(world: WorldIR, weakness: WeaknessSpec) -> str:
    secret_material = _secret_material(world, weakness.target_ref or weakness.target)
    return textwrap.dedent(
        f"""\
        <?php
        define('OPENRANGE_WORLD_ID', '{world.world_id}');
        define('OPENRANGE_APP_SECRET', '{secret_material}');
        ?>
        """
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
