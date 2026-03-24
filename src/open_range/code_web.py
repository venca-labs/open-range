"""Parameterized exact-code web flaw templates for `enterprise_saas_v1`."""

from __future__ import annotations

import json
import shlex
import textwrap
from dataclasses import dataclass
from urllib.parse import quote

from open_range.effect_markers import (
    effect_marker_content,
    effect_marker_path,
    effect_marker_service,
    effect_marker_token,
)
from open_range.world_ir import WeaknessRealizationSpec, WeaknessSpec, WorldIR


@dataclass(frozen=True, slots=True)
class CodeWebTemplate:
    route_path: str
    summary: str
    witness_query: tuple[tuple[str, str], ...]
    expected_contains: str


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
            path=_foothold_path(weakness),
            summary="marker file returned when the vulnerable handler is exploited",
        ),
    ]
    if weakness.kind == "broken_authorization":
        realizations.append(
            WeaknessRealizationSpec(
                kind="seed_data",
                service=weakness.target,
                path=_protected_record_path(weakness),
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
    asset_id = _preferred_asset(world)
    if weakness.kind == "sql_injection":
        return CodeWebTemplate(
            route_path="/search.php",
            summary="search handler concatenates user input into a SQL-like query string",
            witness_query=(
                ("q", f"' UNION SELECT '{_foothold_token(world, weakness)}' -- "),
                ("asset", asset_id),
            ),
            expected_contains=_foothold_token(world, weakness),
        )
    if weakness.kind == "broken_authorization":
        return CodeWebTemplate(
            route_path="/records.php",
            summary="records handler exposes privileged objects without object-level authorization",
            witness_query=(("record", "admin-console"), ("viewer", "sales-01")),
            expected_contains=_foothold_token(world, weakness),
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
            witness_query=(("path", _foothold_path(weakness)),),
            expected_contains=_foothold_token(world, weakness),
        )
    if weakness.kind == "ssrf":
        return CodeWebTemplate(
            route_path="/fetch.php",
            summary="URL fetcher can retrieve internal-only HTTP resources without egress controls",
            witness_query=(("url", _egress_canary_url(weakness)),),
            expected_contains=effect_marker_token(weakness),
        )
    return CodeWebTemplate(
        route_path="/ops.php",
        summary="operations handler shells out with untrusted input",
        witness_query=(("host", f"127.0.0.1;cat {_foothold_path(weakness)}"),),
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


def code_web_realization_content(
    world: WorldIR, weakness: WeaknessSpec, realization: WeaknessRealizationSpec
) -> str:
    if realization.path == _foothold_path(weakness):
        return _foothold_token(world, weakness) + "\n"
    if realization.path == _protected_record_path(weakness):
        return textwrap.dedent(
            f"""\
            admin_console=enabled
            world_id={world.world_id}
            token={_foothold_token(world, weakness)}
            """
        )
    if realization.path == effect_marker_path(weakness):
        return ""
    return _route_template(world, weakness)


def code_web_remediation_command(weakness: WeaknessSpec) -> str:
    guard_path = _guard_path(weakness)
    guard_dir = guard_path.rsplit("/", 1)[0]
    return f"mkdir -p {shlex.quote(guard_dir)} && touch {shlex.quote(guard_path)}"


def code_web_cleanup_commands(weakness: WeaknessSpec) -> tuple[str, ...]:
    return (f"rm -f {shlex.quote(_guard_path(weakness))}",)


def code_web_guard_path(weakness: WeaknessSpec) -> str:
    return _guard_path(weakness)


def _route_template(world: WorldIR, weakness: WeaknessSpec) -> str:
    foothold_path = _foothold_path(weakness)
    guard_path = _guard_path(weakness)
    effect_path = effect_marker_path(weakness)
    effect_content = _php_string_literal(effect_marker_content(weakness))
    if weakness.kind == "sql_injection":
        return textwrap.dedent(
            f"""\
            <?php
            if (file_exists('{guard_path}')) {{
                http_response_code(403);
                echo 'remediated';
                return;
            }}
            $q = $_GET['q'] ?? '';
            $sql = "SELECT asset_id FROM assets WHERE asset_id = '" . $q . "'";
            if (stripos($q, 'union select') !== false || strpos($q, "' OR '1'='1") !== false) {{
                echo file_get_contents('{foothold_path}');
                return;
            }}
            header('Content-Type: text/plain');
            echo "sql=" . $sql;
            ?>
            """
        )
    if weakness.kind == "broken_authorization":
        return textwrap.dedent(
            f"""\
            <?php
            if (file_exists('{guard_path}')) {{
                http_response_code(403);
                echo 'remediated';
                return;
            }}
            $records = [
                'public' => 'announcement=OpenRange',
                'admin-console' => file_get_contents('{_protected_record_path(weakness)}'),
            ];
            $record = $_GET['record'] ?? 'public';
            header('Content-Type: text/plain');
            echo $records[$record] ?? 'missing';
            ?>
            """
        )
    if weakness.kind == "auth_bypass":
        return textwrap.dedent(
            f"""\
            <?php
            if (file_exists('{guard_path}')) {{
                http_response_code(403);
                echo 'remediated';
                return;
            }}
            $debug = $_GET['debug'] ?? '0';
            $as = $_GET['as'] ?? 'user';
            if (($debug === '1' || ($_GET['impersonate'] ?? '') === 'it_admin') && $as === 'admin') {{
                @mkdir(dirname('{effect_path}'), 0777, true);
                file_put_contents('{effect_path}', {effect_content});
                echo file_get_contents('{effect_path}');
                return;
            }}
            http_response_code(403);
            header('Content-Type: text/plain');
            echo 'denied';
            ?>
            """
        )
    if weakness.kind == "path_traversal":
        return textwrap.dedent(
            f"""\
            <?php
            if (file_exists('{guard_path}')) {{
                http_response_code(403);
                echo 'remediated';
                return;
            }}
            $path = $_GET['path'] ?? '';
            if ($path === '') {{
                http_response_code(400);
                echo 'missing path';
                return;
            }}
            if (is_file($path)) {{
                header('Content-Type: text/plain');
                echo file_get_contents($path);
                return;
            }}
            http_response_code(404);
            echo 'missing';
            ?>
            """
        )
    if weakness.kind == "ssrf":
        return textwrap.dedent(
            f"""\
            <?php
            if (file_exists('{guard_path}')) {{
                http_response_code(403);
                echo 'remediated';
                return;
            }}
            $url = $_GET['url'] ?? '';
            if ($url === '') {{
                http_response_code(400);
                echo 'missing url';
                return;
            }}
            $ctx = stream_context_create(['http' => ['timeout' => 2]]);
            $response = @file_get_contents($url, false, $ctx);
            if ($response === false) {{
                http_response_code(502);
                echo 'fetch failed';
                return;
            }}
            header('Content-Type: text/plain');
            echo $response;
            ?>
            """
        )
    return textwrap.dedent(
        f"""\
        <?php
        if (file_exists('{guard_path}')) {{
            http_response_code(403);
            echo 'remediated';
            return;
        }}
        $host = $_GET['host'] ?? '127.0.0.1';
        $cmd = "printf 'scan=%s\\n' " . $host;
        $output = shell_exec($cmd . " 2>&1");
        if (strpos((string)$output, 'OPENRANGE-FOOTHOLD:') !== false) {{
            @mkdir(dirname('{effect_path}'), 0777, true);
            file_put_contents('{effect_path}', {effect_content});
            header('Content-Type: text/plain');
            echo file_get_contents('{effect_path}');
            return;
        }}
        header('Content-Type: text/plain');
        echo $output;
        ?>
        """
    )


def _preferred_asset(world: WorldIR) -> str:
    for asset in world.assets:
        if asset.confidentiality == "critical":
            return asset.id
    return world.assets[0].id if world.assets else "finance_docs"


def _foothold_token(world: WorldIR, weakness: WeaknessSpec) -> str:
    return f"OPENRANGE-FOOTHOLD:{world.world_id}:{weakness.id}"


def _foothold_path(weakness: WeaknessSpec) -> str:
    return f"/opt/openrange/footholds/{weakness.id}.txt"


def _protected_record_path(weakness: WeaknessSpec) -> str:
    return f"/opt/openrange/records/{weakness.id}.txt"


def _guard_path(weakness: WeaknessSpec) -> str:
    return f"/var/www/html/.openrange/guards/{weakness.id}.patched"


def _egress_canary_url(weakness: WeaknessSpec) -> str:
    token = quote(effect_marker_token(weakness), safe="")
    return f"http://svc-siem:9201/openrange-egress/{weakness.id}?token={token}"


def _php_string_literal(text: str) -> str:
    return json.dumps(text)
