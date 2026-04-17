"""Exact-code web flaw templates, witness payloads, and realizations."""

from __future__ import annotations

from open_range.contracts.world import WeaknessRealizationSpec, WeaknessSpec, WorldIR
from open_range.objectives.effects import (
    effect_marker_path,
    effect_marker_service,
    effect_marker_token,
)

from .common import (
    CodeWebTemplate,
    egress_canary_url,
    foothold_path,
    foothold_token,
    preferred_asset,
    protected_record_path,
)


def code_web_realizations(
    world: WorldIR, weakness: WeaknessSpec
) -> tuple[WeaknessRealizationSpec, ...]:
    template = code_web_template(world, weakness)
    realizations = [
        WeaknessRealizationSpec(
            kind="code",
            service=weakness.target,
            path=f"/var/www/html{template.route_path}",
            summary=template.summary,
        ),
        WeaknessRealizationSpec(
            kind="seed_data",
            service=weakness.target,
            path=foothold_path(weakness),
            summary="marker file returned when the vulnerable handler is exploited",
        ),
    ]
    if weakness.kind == "broken_authorization":
        realizations.append(
            WeaknessRealizationSpec(
                kind="seed_data",
                service=weakness.target,
                path=protected_record_path(weakness),
                summary="admin record returned without an authorization check",
            )
        )
    if weakness.kind == "ssrf":
        realizations.append(
            WeaknessRealizationSpec(
                kind="seed_data",
                service=effect_marker_service(weakness),
                path=effect_marker_path(weakness),
                summary="sink-side egress canary log written when the vulnerable SSRF handler reaches the telemetry sink",
            )
        )
    return tuple(realizations)


def code_web_template(world: WorldIR, weakness: WeaknessSpec) -> CodeWebTemplate:
    asset_id = preferred_asset(world)
    if weakness.kind == "sql_injection":
        return CodeWebTemplate(
            route_path="/search.php",
            summary="search handler concatenates user input into a SQL-like query string",
            witness_query=(
                ("q", f"' UNION SELECT '{foothold_token(world, weakness)}' -- "),
                ("asset", asset_id),
            ),
            expected_contains=foothold_token(world, weakness),
        )
    if weakness.kind == "broken_authorization":
        return CodeWebTemplate(
            route_path="/records.php",
            summary="records handler exposes privileged objects without object-level authorization",
            witness_query=(("record", "admin-console"), ("viewer", "sales-01")),
            expected_contains=foothold_token(world, weakness),
        )
    if weakness.kind == "auth_bypass":
        return CodeWebTemplate(
            route_path="/admin.php",
            summary="admin handler trusts a debug switch instead of enforcing authentication state",
            witness_query=(("debug", "1"), ("as", "admin")),
            expected_contains=effect_marker_token(weakness),
        )
    if weakness.kind == "path_traversal":
        return CodeWebTemplate(
            route_path="/download.php",
            summary="download handler reads arbitrary paths supplied by the requester",
            witness_query=(("path", foothold_path(weakness)),),
            expected_contains=foothold_token(world, weakness),
        )
    if weakness.kind == "ssrf":
        return CodeWebTemplate(
            route_path="/fetch.php",
            summary="URL fetcher can retrieve internal-only HTTP resources without egress controls",
            witness_query=(("url", egress_canary_url(weakness)),),
            expected_contains=effect_marker_token(weakness),
        )
    return CodeWebTemplate(
        route_path="/ops.php",
        summary="operations handler shells out with untrusted input",
        witness_query=(("host", f"127.0.0.1;cat {foothold_path(weakness)}"),),
        expected_contains=effect_marker_token(weakness),
    )


def code_web_payload(world: WorldIR, weakness: WeaknessSpec) -> dict[str, object]:
    template = code_web_template(world, weakness)
    return {
        "path": template.route_path,
        "query": {key: value for key, value in template.witness_query},
        "exploit_kind": weakness.kind,
        "expect_contains": template.expected_contains,
    }
