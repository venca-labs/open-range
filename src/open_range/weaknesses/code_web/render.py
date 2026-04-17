"""Exact-code web flaw route rendering and offline witness content."""

from __future__ import annotations

import textwrap

from open_range.contracts.world import WeaknessRealizationSpec, WeaknessSpec, WorldIR
from open_range.objectives.effects import (
    effect_marker_content,
    effect_marker_path,
)

from .common import (
    foothold_path,
    foothold_token,
    guard_path,
    php_string_literal,
    protected_record_path,
)


def code_web_realization_content(
    world: WorldIR, weakness: WeaknessSpec, realization: WeaknessRealizationSpec
) -> str:
    if realization.path == foothold_path(weakness):
        return foothold_token(world, weakness) + "\n"
    if realization.path == protected_record_path(weakness):
        return textwrap.dedent(
            f"""\
            admin_console=enabled
            world_id={world.world_id}
            token={foothold_token(world, weakness)}
            """
        )
    if realization.path == effect_marker_path(weakness):
        return ""
    return _route_template(world, weakness).lstrip()


def _route_template(world: WorldIR, weakness: WeaknessSpec) -> str:
    target_foothold_path = foothold_path(weakness)
    target_guard_path = guard_path(weakness)
    effect_path = effect_marker_path(weakness)
    effect_content = php_string_literal(effect_marker_content(weakness))
    if weakness.kind == "sql_injection":
        return textwrap.dedent(
            f"""\
            <?php
            if (file_exists('{target_guard_path}')) {{
                http_response_code(403);
                echo 'remediated';
                return;
            }}
            $q = $_GET['q'] ?? '';
            $sql = "SELECT asset_id FROM assets WHERE asset_id = '" . $q . "' AND tenant_scope = 'catalog'";
            if (stripos($q, 'union select') !== false || preg_match("/\\bor\\s+'?1'?\\s*=\\s*'?1'?\\b/i", $q)) {{
                echo file_get_contents('{target_foothold_path}');
                return;
            }}
            header('Content-Type: text/plain');
            if ((strpos($q, "'--") !== false || strpos($q, "'#") !== false) && stripos($q, 'admin') !== false) {{
                echo "search field: q\nbackend query: " . $sql . "\nrows: 1\nasset id: admin-console";
                return;
            }}
            if (substr_count($q, "'") % 2 === 1 && strpos($q, "--") === false) {{
                echo "search field: q\nbackend query: " . $sql . "\nsql error: syntax error near '" . $q . "'";
                return;
            }}
            echo "search field: q\nbackend query: " . $sql . "\nrows: 0";
            ?>
            """
        )
    if weakness.kind == "broken_authorization":
        return textwrap.dedent(
            f"""\
            <?php
            if (file_exists('{target_guard_path}')) {{
                http_response_code(403);
                echo 'remediated';
                return;
            }}
            $records = [
                'public' => 'announcement=OpenRange',
                'admin-console' => file_get_contents('{protected_record_path(weakness)}'),
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
            if (file_exists('{target_guard_path}')) {{
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
            if (file_exists('{target_guard_path}')) {{
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
            if (file_exists('{target_guard_path}')) {{
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
        if (file_exists('{target_guard_path}')) {{
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
