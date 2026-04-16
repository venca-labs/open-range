"""Shared exact-code web flaw helpers."""

from __future__ import annotations

import json
from dataclasses import dataclass
from urllib.parse import quote

from open_range.objectives.effects import effect_marker_token
from open_range.world_ir import WeaknessSpec, WorldIR


@dataclass(frozen=True, slots=True)
class CodeWebTemplate:
    route_path: str
    summary: str
    witness_query: tuple[tuple[str, str], ...]
    expected_contains: str


def preferred_asset(world: WorldIR) -> str:
    for asset in world.assets:
        if asset.confidentiality == "critical":
            return asset.id
    return world.assets[0].id if world.assets else "finance_docs"


def foothold_token(world: WorldIR, weakness: WeaknessSpec) -> str:
    return f"OPENRANGE-FOOTHOLD:{world.world_id}:{weakness.id}"


def foothold_path(weakness: WeaknessSpec) -> str:
    return f"/opt/openrange/footholds/{weakness.id}.txt"


def protected_record_path(weakness: WeaknessSpec) -> str:
    return f"/opt/openrange/records/{weakness.id}.txt"


def guard_path(weakness: WeaknessSpec) -> str:
    return f"/var/www/html/.openrange/guards/{weakness.id}.patched"


def egress_canary_url(weakness: WeaknessSpec) -> str:
    token = quote(effect_marker_token(weakness), safe="")
    return f"http://svc-siem:9201/openrange-egress/{weakness.id}?token={token}"


def php_string_literal(text: str) -> str:
    return json.dumps(text)
