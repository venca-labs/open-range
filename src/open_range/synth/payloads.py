"""Low-level synth payload rendering helpers."""

from __future__ import annotations

import textwrap

from open_range.contracts.world import (
    AssetSpec,
    WeaknessRealizationSpec,
    WeaknessSpec,
    WorldIR,
)
from open_range.weaknesses import render_realization_content


def web_index_html(world: WorldIR) -> str:
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


def db_init_sql(world: WorldIR) -> str:
    user_rows = "\n".join(
        f"INSERT INTO users (username, password, role, department, email) VALUES ('{user.id}', '{default_password(user.id)}', '{user.role}', '{user.department}', '{user.email}');"
        for user in world.users
    )
    asset_rows = "\n".join(
        f"INSERT INTO assets (asset_id, asset_class, contents) VALUES ('{asset.id}', '{asset.asset_class}', '{asset_content(asset)}');"
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


def asset_content(asset: AssetSpec) -> str:
    return f"seeded-{asset.asset_class}-{asset.id}"


def default_password(user_id: str) -> str:
    return f"{user_id}-pass"


def weakness_realization_content(
    world: WorldIR,
    weakness: WeaknessSpec,
    realization: WeaknessRealizationSpec,
) -> str:
    return render_realization_content(world, weakness, realization)


def mailbox_weakness_messages(world: WorldIR, mailbox: str) -> list[str]:
    slug = mailbox_slug(mailbox)
    messages: list[str] = []
    for weakness in world.weaknesses:
        for realization in weakness.realization:
            if realization.kind != "mailbox":
                continue
            if f"/{slug}/" not in realization.path:
                continue
            messages.append(weakness_realization_content(world, weakness, realization))
    return messages


def mailbox_slug(mailbox: str) -> str:
    return mailbox.replace("@", "_at_").replace(".", "_")
