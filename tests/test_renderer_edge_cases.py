"""Edge case tests for KindRenderer.

Tests unusual/boundary specs: no flags, no users, no firewall rules,
db-only flags, file-only flags, multiple vulns, empty golden path,
single host, custom zones.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest
import yaml

from open_range.builder.renderer import KindRenderer, _sanitize_key
from open_range.protocols import (
    FlagSpec,
    SnapshotSpec,
    TruthGraph,
    Vulnerability,
)


@pytest.fixture
def renderer():
    return KindRenderer()


def _minimal_topology(**overrides):
    topo = {
        "hosts": ["web", "db"],
        "zones": {"dmz": ["web"], "internal": ["db"]},
        "users": [],
        "firewall_rules": [],
    }
    topo.update(overrides)
    return topo


def _render_values(renderer, spec):
    """Render and return parsed values.yaml."""
    with tempfile.TemporaryDirectory() as tmpdir:
        out = Path(tmpdir) / "out"
        renderer.render(spec, out)
        return yaml.safe_load((out / "openrange" / "values.yaml").read_text())


# ---------------------------------------------------------------------------
# No flags
# ---------------------------------------------------------------------------


class TestNoFlags:
    def test_renders_without_error(self, renderer):
        spec = SnapshotSpec(topology=_minimal_topology(), flags=[])
        values = _render_values(renderer, spec)
        assert values["flags"] == []

    def test_no_flag_payloads(self, renderer):
        spec = SnapshotSpec(topology=_minimal_topology(), flags=[])
        values = _render_values(renderer, spec)
        for svc in values["services"].values():
            for p in svc.get("payloads", []):
                assert "FLAG{" not in p.get("content", "")


# ---------------------------------------------------------------------------
# No users
# ---------------------------------------------------------------------------


class TestNoUsers:
    def test_renders_without_error(self, renderer):
        spec = SnapshotSpec(topology=_minimal_topology(users=[]))
        values = _render_values(renderer, spec)
        assert values["users"] == []

    def test_db_user_defaults(self, renderer):
        spec = SnapshotSpec(topology=_minimal_topology(users=[]))
        values = _render_values(renderer, spec)
        db_env = values["services"]["db"]["env"]
        assert db_env["MYSQL_USER"] == "app_user"
        assert db_env["MYSQL_PASSWORD"] == "AppUs3r!2024"


# ---------------------------------------------------------------------------
# No firewall rules
# ---------------------------------------------------------------------------


class TestNoFirewallRules:
    def test_empty_firewall_rules(self, renderer):
        spec = SnapshotSpec(topology=_minimal_topology(firewall_rules=[]))
        values = _render_values(renderer, spec)
        assert values["firewallRules"] == []


# ---------------------------------------------------------------------------
# DB-only flags
# ---------------------------------------------------------------------------


class TestDBOnlyFlags:
    def test_db_flag_not_in_web_payloads(self, renderer):
        spec = SnapshotSpec(
            topology=_minimal_topology(),
            flags=[
                FlagSpec(id="f1", value="FLAG{db_only}", path="db:flags.secrets.flag", host="db"),
            ],
        )
        values = _render_values(renderer, spec)
        web = values["services"].get("web", {})
        for p in web.get("payloads", []):
            assert "FLAG{db_only}" not in p.get("content", "")


# ---------------------------------------------------------------------------
# File-only flags
# ---------------------------------------------------------------------------


class TestFileOnlyFlags:
    def test_flag_in_host_payloads(self, renderer):
        spec = SnapshotSpec(
            topology=_minimal_topology(),
            flags=[
                FlagSpec(id="f1", value="FLAG{file_flag}", path="/var/flags/f1.txt", host="web"),
            ],
        )
        values = _render_values(renderer, spec)
        web_payloads = values["services"]["web"].get("payloads", [])
        flag_mounts = [p for p in web_payloads if p["mountPath"] == "/var/flags/f1.txt"]
        assert len(flag_mounts) == 1
        assert "FLAG{file_flag}" in flag_mounts[0]["content"]

    def test_multiple_file_flags(self, renderer):
        spec = SnapshotSpec(
            topology=_minimal_topology(),
            flags=[
                FlagSpec(id="f1", value="FLAG{first}", path="/var/flags/f1.txt", host="web"),
                FlagSpec(id="f2", value="FLAG{second}", path="/var/flags/f2.txt", host="web"),
            ],
        )
        values = _render_values(renderer, spec)
        web_payloads = values["services"]["web"].get("payloads", [])
        flag_contents = [p["content"] for p in web_payloads if "FLAG{" in p["content"]]
        assert len(flag_contents) == 2


# ---------------------------------------------------------------------------
# Multiple vuln types
# ---------------------------------------------------------------------------


class TestMultipleVulnTypes:
    def test_values_valid_with_multiple_vulns(self, renderer):
        spec = SnapshotSpec(
            topology=_minimal_topology(),
            truth_graph=TruthGraph(
                vulns=[
                    Vulnerability(id="v1", type="sqli", host="web"),
                    Vulnerability(id="v2", type="path_traversal", host="web"),
                    Vulnerability(id="v3", type="weak_creds", host="db"),
                ]
            ),
        )
        values = _render_values(renderer, spec)
        assert "web" in values["services"]
        assert "db" in values["services"]


# ---------------------------------------------------------------------------
# Single host
# ---------------------------------------------------------------------------


class TestSingleHost:
    def test_renders_single_host(self, renderer):
        spec = SnapshotSpec(
            topology={
                "hosts": ["web"],
                "zones": {"dmz": ["web"]},
                "users": [],
                "firewall_rules": [],
            },
        )
        values = _render_values(renderer, spec)
        assert len(values["services"]) == 1
        assert "web" in values["services"]

    def test_single_zone(self, renderer):
        spec = SnapshotSpec(
            topology={
                "hosts": ["web"],
                "zones": {"dmz": ["web"]},
                "users": [],
                "firewall_rules": [],
            },
        )
        values = _render_values(renderer, spec)
        assert len(values["zones"]) == 1
        assert "dmz" in values["zones"]


# ---------------------------------------------------------------------------
# Dict-format hosts
# ---------------------------------------------------------------------------


class TestDictFormatHosts:
    def test_dict_hosts_resolved(self, renderer):
        spec = SnapshotSpec(
            topology={
                "hosts": [
                    {"name": "web", "zone": "dmz"},
                    {"name": "db", "zone": "internal"},
                ],
                "zones": {"dmz": ["web"], "internal": ["db"]},
                "users": [],
                "firewall_rules": [],
            },
        )
        values = _render_values(renderer, spec)
        assert "web" in values["services"]
        assert "db" in values["services"]
        assert values["services"]["web"]["zone"] == "dmz"


# ---------------------------------------------------------------------------
# Custom / unknown zones
# ---------------------------------------------------------------------------


class TestCustomZones:
    def test_unknown_zone_gets_default_cidr(self, renderer):
        spec = SnapshotSpec(
            topology={
                "hosts": ["web"],
                "zones": {"custom_zone": ["web"]},
                "users": [],
                "firewall_rules": [],
            },
        )
        values = _render_values(renderer, spec)
        assert values["zones"]["custom_zone"]["cidr"] == "10.0.0.0/24"


# ---------------------------------------------------------------------------
# DB user resolution
# ---------------------------------------------------------------------------


class TestDBUserResolution:
    def test_admin_not_picked_as_db_user(self, renderer):
        spec = SnapshotSpec(
            topology=_minimal_topology(users=[
                {"username": "root_admin", "password": "X", "groups": ["admins"], "hosts": ["db"]},
            ]),
        )
        values = _render_values(renderer, spec)
        assert values["services"]["db"]["env"]["MYSQL_USER"] == "app_user"

    def test_non_admin_db_user_picked(self, renderer):
        spec = SnapshotSpec(
            topology=_minimal_topology(users=[
                {"username": "dbworker", "password": "Work3r!", "groups": ["users"], "hosts": ["db", "web"]},
            ]),
        )
        values = _render_values(renderer, spec)
        assert values["services"]["db"]["env"]["MYSQL_USER"] == "dbworker"
        assert values["services"]["db"]["env"]["MYSQL_PASSWORD"] == "Work3r!"

    def test_mysql_root_pass_from_topology(self, renderer):
        spec = SnapshotSpec(
            topology=_minimal_topology(mysql_root_password="CustomRoot!"),
        )
        values = _render_values(renderer, spec)
        assert values["services"]["db"]["env"]["MYSQL_ROOT_PASSWORD"] == "CustomRoot!"


# ---------------------------------------------------------------------------
# _sanitize_key
# ---------------------------------------------------------------------------


class TestSanitizeKey:
    def test_simple_path(self):
        assert _sanitize_key("var/www/index.php") == "var-www-index.php"

    def test_strips_leading_slash(self):
        assert _sanitize_key("/var/flags/flag1.txt") == "var-flags-flag1.txt"

    def test_preserves_dots_and_dashes(self):
        assert _sanitize_key("my-file.conf") == "my-file.conf"

    def test_special_chars(self):
        key = _sanitize_key("/var/log/siem/consolidated/all.log")
        assert "/" not in key
        assert key == "var-log-siem-consolidated-all.log"


# ---------------------------------------------------------------------------
# Payload files with spec.files
# ---------------------------------------------------------------------------


class TestPayloadFiles:
    def test_files_routed_to_correct_service(self, renderer):
        spec = SnapshotSpec(
            topology=_minimal_topology(),
            files={
                "web:/var/www/html/index.php": "<?php ?>",
                "db:sql": "SELECT 1;",
                "siem:/var/log/siem/all.log": "log line\n",
            },
        )
        values = _render_values(renderer, spec)
        web_paths = {p["mountPath"] for p in values["services"]["web"].get("payloads", [])}
        db_paths = {p["mountPath"] for p in values["services"]["db"].get("payloads", [])}
        assert "/var/www/html/index.php" in web_paths
        assert "/docker-entrypoint-initdb.d/99-openrange-init.sh" in db_paths

    def test_no_files_produces_only_base_schema(self, renderer):
        spec = SnapshotSpec(topology=_minimal_topology(), files={})
        values = _render_values(renderer, spec)
        for name, svc in values["services"].items():
            payloads = svc.get("payloads", [])
            if name == "db":
                # db always gets the base schema init script
                assert len(payloads) == 1
                assert payloads[0]["key"] == "00-base-schema.sql"
            else:
                assert payloads == []
