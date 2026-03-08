"""Tests for SnapshotRenderer -- template rendering pipeline."""

import tempfile
import json
from pathlib import Path

import pytest

from open_range.builder.renderer import SnapshotRenderer, _build_context
from open_range.protocols import (
    FlagSpec,
    GoldenPathStep,
    NPCTrafficSpec,
    SnapshotSpec,
    TaskSpec,
    TruthGraph,
    Vulnerability,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def renderer():
    return SnapshotRenderer()


@pytest.fixture
def sqli_spec():
    """SnapshotSpec with a SQLi vuln -- exercises search_endpoint in nginx."""
    return SnapshotSpec(
        topology={
            "hosts": [
                "attacker", "firewall", "web", "mail",
                "db", "files", "ldap", "siem",
            ],
            "zones": {
                "external": ["attacker"],
                "dmz": ["web", "mail"],
                "internal": ["db", "files"],
                "management": ["ldap", "siem"],
            },
            "users": [
                {
                    "username": "admin",
                    "password": "Adm1n!Test",
                    "groups": ["admins"],
                    "hosts": ["web", "db"],
                },
                {
                    "username": "testuser",
                    "password": "Test!2024",
                    "groups": ["users"],
                    "hosts": ["web"],
                },
            ],
            "firewall_rules": [
                {
                    "action": "allow",
                    "from_zone": "external",
                    "to_zone": "dmz",
                    "ports": [80, 443, 25],
                },
                {
                    "action": "deny",
                    "from_zone": "internal",
                    "to_zone": "external",
                    "ports": [],
                },
            ],
        },
        truth_graph=TruthGraph(
            vulns=[
                Vulnerability(
                    id="vuln_sqli",
                    type="sqli",
                    host="web",
                    service="nginx+php",
                    injection_point="/search?q=",
                    root_cause="Unsanitized user input",
                )
            ]
        ),
        flags=[
            FlagSpec(
                id="flag1",
                value="FLAG{sql1_t3st_f1ag}",
                path="/var/flags/flag1.txt",
                host="web",
            ),
        ],
        golden_path=[
            GoldenPathStep(step=1, command="nmap -sV 10.0.1.0/24", expect_in_stdout="80/tcp"),
        ],
        npc_traffic=NPCTrafficSpec(level=0, rate_lambda=10.0),
        task=TaskSpec(red_briefing="Find vulns.", blue_briefing="Monitor."),
    )


@pytest.fixture
def path_traversal_spec():
    """SnapshotSpec with a path traversal vuln -- exercises download_endpoint."""
    return SnapshotSpec(
        topology={
            "hosts": ["web", "db"],
            "zones": {"dmz": ["web"], "internal": ["db"]},
            "users": [],
            "firewall_rules": [],
        },
        truth_graph=TruthGraph(
            vulns=[
                Vulnerability(
                    id="vuln_pt",
                    type="path_traversal",
                    host="web",
                    injection_point="/download?file=",
                )
            ]
        ),
        flags=[
            FlagSpec(
                id="flag1",
                value="FLAG{p4th_tr4v}",
                path="/var/flags/flag1.txt",
                host="web",
            ),
        ],
        golden_path=[],
        task=TaskSpec(red_briefing="Go.", blue_briefing="Watch."),
    )


@pytest.fixture
def db_flag_spec():
    """SnapshotSpec with a flag stored in the database."""
    return SnapshotSpec(
        topology={
            "hosts": ["web", "db"],
            "zones": {"dmz": ["web"], "internal": ["db"]},
            "users": [
                {
                    "username": "dbadmin",
                    "password": "DbP@ss!",
                    "groups": ["admins"],
                    "hosts": ["db"],
                },
            ],
            "firewall_rules": [],
        },
        truth_graph=TruthGraph(
            vulns=[
                Vulnerability(id="vuln_idor", type="idor", host="web")
            ]
        ),
        flags=[
            FlagSpec(
                id="flag1",
                value="FLAG{1d0r_fl4g}",
                path="db:flags.secrets.flag",
                host="db",
            ),
        ],
        golden_path=[],
        task=TaskSpec(red_briefing="Go.", blue_briefing="Watch."),
    )


# ---------------------------------------------------------------------------
# Render tests -- all output files exist
# ---------------------------------------------------------------------------


def test_render_creates_output_dir(renderer, sqli_spec):
    with tempfile.TemporaryDirectory() as tmpdir:
        out = Path(tmpdir) / "snapshot_out"
        result = renderer.render(sqli_spec, out)
        assert result == out
        assert out.is_dir()


def test_render_produces_all_files(renderer, sqli_spec):
    with tempfile.TemporaryDirectory() as tmpdir:
        out = Path(tmpdir) / "snapshot_out"
        renderer.render(sqli_spec, out)
        expected_files = [
            "docker-compose.yml",
            "Dockerfile.web",
            "Dockerfile.db",
            "nginx.conf",
            "init.sql",
            "iptables.rules",
        ]
        for fname in expected_files:
            assert (out / fname).exists(), f"Missing output file: {fname}"
            content = (out / fname).read_text()
            assert len(content) > 0, f"Empty output file: {fname}"


def test_render_idempotent(renderer, sqli_spec):
    """Rendering twice to the same dir should overwrite cleanly."""
    with tempfile.TemporaryDirectory() as tmpdir:
        out = Path(tmpdir) / "snapshot_out"
        renderer.render(sqli_spec, out)
        content1 = (out / "docker-compose.yml").read_text()
        renderer.render(sqli_spec, out)
        content2 = (out / "docker-compose.yml").read_text()
        assert content1 == content2


def test_render_writes_payload_manifest_and_files(renderer, sqli_spec):
    with tempfile.TemporaryDirectory() as tmpdir:
        out = Path(tmpdir) / "snapshot_out"
        spec = sqli_spec.model_copy(deep=True)
        spec.files = {
            "web:/var/www/portal/search.php": "<?php echo 'ok'; ?>\n",
            "siem:/var/log/siem/consolidated/all.log": "Suspicious activity detected\n",
            "db:sql": "USE flags;\nSELECT 1;\n",
        }

        renderer.render(spec, out)

        manifest = json.loads((out / "file-payloads.json").read_text())
        assert "web:/var/www/portal/search.php" in manifest
        assert "siem:/var/log/siem/consolidated/all.log" in manifest
        assert "db:sql" in manifest

        assert (out / manifest["web:/var/www/portal/search.php"]).read_text() == "<?php echo 'ok'; ?>\n"
        assert (out / manifest["siem:/var/log/siem/consolidated/all.log"]).read_text() == "Suspicious activity detected\n"
        assert (out / manifest["db:sql"]).read_text() == "USE flags;\nSELECT 1;\n"


# ---------------------------------------------------------------------------
# docker-compose.yml content checks
# ---------------------------------------------------------------------------


def test_compose_contains_services(renderer, sqli_spec):
    with tempfile.TemporaryDirectory() as tmpdir:
        out = Path(tmpdir) / "out"
        renderer.render(sqli_spec, out)
        compose = (out / "docker-compose.yml").read_text()
        assert "services:" in compose
        assert "web:" in compose
        assert "db:" in compose
        assert "firewall:" in compose
        assert "siem:" in compose
        assert "attacker:" in compose


def test_compose_contains_networks(renderer, sqli_spec):
    with tempfile.TemporaryDirectory() as tmpdir:
        out = Path(tmpdir) / "out"
        renderer.render(sqli_spec, out)
        compose = (out / "docker-compose.yml").read_text()
        assert "networks:" in compose
        assert "external:" in compose
        assert "dmz:" in compose
        assert "internal:" in compose


def test_compose_web_depends_on_db(renderer, sqli_spec):
    with tempfile.TemporaryDirectory() as tmpdir:
        out = Path(tmpdir) / "out"
        renderer.render(sqli_spec, out)
        compose = (out / "docker-compose.yml").read_text()
        # The web service should depend on db
        assert "depends_on:" in compose


def test_compose_web_healthcheck_accepts_pre_overlay_http_statuses(renderer, sqli_spec):
    with tempfile.TemporaryDirectory() as tmpdir:
        out = Path(tmpdir) / "out"
        renderer.render(sqli_spec, out)
        compose = (out / "docker-compose.yml").read_text()
        assert "CMD-SHELL" in compose
        assert "http://localhost/ || true" in compose
        assert '$$status' in compose
        assert '2*|3*|4*) exit 0' in compose
        assert 'curl", "-sf", "http://localhost/"' not in compose


def test_compose_attacker_has_routed_host_aliases_and_nmap_runtime_lib(renderer, sqli_spec):
    with tempfile.TemporaryDirectory() as tmpdir:
        out = Path(tmpdir) / "out"
        renderer.render(sqli_spec, out)
        compose = (out / "docker-compose.yml").read_text()
        assert "libblas3 nmap" in compose
        assert 'extra_hosts:' in compose
        assert '"web:10.0.1.10"' in compose
        assert '"db:10.0.2.20"' in compose
        assert '"files:10.0.2.21"' in compose
        assert "nmap --version" in compose
        assert "iptables -C FORWARD" in compose


# ---------------------------------------------------------------------------
# Dockerfile.web content checks
# ---------------------------------------------------------------------------


def test_dockerfile_web_creates_users(renderer, sqli_spec):
    with tempfile.TemporaryDirectory() as tmpdir:
        out = Path(tmpdir) / "out"
        renderer.render(sqli_spec, out)
        dockerfile = (out / "Dockerfile.web").read_text()
        assert "useradd" in dockerfile
        assert "admin" in dockerfile
        assert "testuser" in dockerfile


def test_dockerfile_web_plants_flag(renderer, sqli_spec):
    """Flag on web host with a file path should appear in Dockerfile."""
    with tempfile.TemporaryDirectory() as tmpdir:
        out = Path(tmpdir) / "out"
        renderer.render(sqli_spec, out)
        dockerfile = (out / "Dockerfile.web").read_text()
        assert "FLAG{sql1_t3st_f1ag}" in dockerfile
        assert "/var/flags/flag1.txt" in dockerfile


def test_dockerfile_web_no_db_flag(renderer, db_flag_spec):
    """Flag stored in db should NOT appear in Dockerfile.web."""
    with tempfile.TemporaryDirectory() as tmpdir:
        out = Path(tmpdir) / "out"
        renderer.render(db_flag_spec, out)
        dockerfile = (out / "Dockerfile.web").read_text()
        assert "FLAG{1d0r_fl4g}" not in dockerfile


# ---------------------------------------------------------------------------
# nginx.conf content checks
# ---------------------------------------------------------------------------


def test_nginx_has_search_for_sqli(renderer, sqli_spec):
    with tempfile.TemporaryDirectory() as tmpdir:
        out = Path(tmpdir) / "out"
        renderer.render(sqli_spec, out)
        nginx = (out / "nginx.conf").read_text()
        assert "/search" in nginx


def test_nginx_has_download_for_path_traversal(renderer, path_traversal_spec):
    with tempfile.TemporaryDirectory() as tmpdir:
        out = Path(tmpdir) / "out"
        renderer.render(path_traversal_spec, out)
        nginx = (out / "nginx.conf").read_text()
        assert "/download" in nginx


def test_nginx_no_download_for_sqli(renderer, sqli_spec):
    """SQLi spec should not enable download endpoint."""
    with tempfile.TemporaryDirectory() as tmpdir:
        out = Path(tmpdir) / "out"
        renderer.render(sqli_spec, out)
        nginx = (out / "nginx.conf").read_text()
        # The download location block should not be rendered
        assert "download.php" not in nginx


def test_compose_firewall_nat_is_subnet_based(renderer, sqli_spec):
    with tempfile.TemporaryDirectory() as tmpdir:
        out = Path(tmpdir) / "out"
        renderer.render(sqli_spec, out)
        compose = (out / "docker-compose.yml").read_text()
        assert "-s 10.0.0.0/24 -d 10.0.1.0/24 -j MASQUERADE" in compose
        assert "-s 10.0.1.0/24 -d 10.0.2.0/24 -j MASQUERADE" in compose
        assert "-o eth1 -j MASQUERADE" not in compose


# ---------------------------------------------------------------------------
# init.sql content checks
# ---------------------------------------------------------------------------


def test_init_sql_creates_tables(renderer, sqli_spec):
    with tempfile.TemporaryDirectory() as tmpdir:
        out = Path(tmpdir) / "out"
        renderer.render(sqli_spec, out)
        sql = (out / "init.sql").read_text()
        assert "CREATE TABLE" in sql
        assert "users" in sql
        assert "patients" in sql
        assert "secrets" in sql


def test_init_sql_creates_referral_db(renderer, sqli_spec):
    """Template creates referral_db with healthcare tables."""
    with tempfile.TemporaryDirectory() as tmpdir:
        out = Path(tmpdir) / "out"
        renderer.render(sqli_spec, out)
        sql = (out / "init.sql").read_text()
        assert "referral_db" in sql
        assert "patient_referrals" in sql
        assert "billing" in sql


def test_init_sql_grants_runtime_db_user(renderer, db_flag_spec):
    """Template grants privileges to the runtime-selected DB account."""
    with tempfile.TemporaryDirectory() as tmpdir:
        out = Path(tmpdir) / "out"
        renderer.render(db_flag_spec, out)
        sql = (out / "init.sql").read_text()
        assert "GRANT" in sql
        assert "TO '" in sql
        assert "app_user" not in sql


def test_init_sql_no_file_flag(renderer, sqli_spec):
    """Flag with a file path should not be inserted into SQL."""
    with tempfile.TemporaryDirectory() as tmpdir:
        out = Path(tmpdir) / "out"
        renderer.render(sqli_spec, out)
        sql = (out / "init.sql").read_text()
        # The flag value should NOT be in SQL (it's a file-based flag)
        assert "FLAG{sql1_t3st_f1ag}" not in sql


# ---------------------------------------------------------------------------
# iptables.rules content checks
# ---------------------------------------------------------------------------


def test_iptables_has_rules(renderer, sqli_spec):
    with tempfile.TemporaryDirectory() as tmpdir:
        out = Path(tmpdir) / "out"
        renderer.render(sqli_spec, out)
        rules = (out / "iptables.rules").read_text()
        assert "*filter" in rules
        assert "COMMIT" in rules
        assert "FORWARD" in rules


def test_iptables_allow_rules(renderer, sqli_spec):
    with tempfile.TemporaryDirectory() as tmpdir:
        out = Path(tmpdir) / "out"
        renderer.render(sqli_spec, out)
        rules = (out / "iptables.rules").read_text()
        assert "--dport 80" in rules
        assert "ACCEPT" in rules


def test_iptables_deny_rules(renderer, sqli_spec):
    with tempfile.TemporaryDirectory() as tmpdir:
        out = Path(tmpdir) / "out"
        renderer.render(sqli_spec, out)
        rules = (out / "iptables.rules").read_text()
        assert "DROP" in rules


# ---------------------------------------------------------------------------
# Context builder unit tests
# ---------------------------------------------------------------------------


def test_build_context_has_expected_keys(sqli_spec):
    ctx = _build_context(sqli_spec)
    # These keys are always present
    expected_keys = [
        "snapshot_id", "networks", "hosts", "host_names",
        "db_host", "db_user", "db_pass", "mysql_root_password",
        "domain", "users", "flags", "server_name",
        "firewall_rules", "zone_cidrs", "app_files",
    ]
    for key in expected_keys:
        assert key in ctx, f"Missing context key: {key}"
    # search_endpoint/download_endpoint are conditionally present
    # (only when True, because templates use `is defined`)
    assert ctx.get("search_endpoint") is True  # sqli -> search enabled


def test_build_context_hosts_are_dicts(sqli_spec):
    ctx = _build_context(sqli_spec)
    for h in ctx["hosts"]:
        assert isinstance(h, dict)
        assert "name" in h
        assert "zone" in h
        assert "networks" in h


def test_build_context_networks_have_names(sqli_spec):
    ctx = _build_context(sqli_spec)
    net_names = [n["name"] for n in ctx["networks"]]
    assert "external" in net_names
    assert "dmz" in net_names


def test_build_context_search_enabled_for_sqli(sqli_spec):
    ctx = _build_context(sqli_spec)
    assert ctx.get("search_endpoint") is True


def test_build_context_download_disabled_for_sqli(sqli_spec):
    ctx = _build_context(sqli_spec)
    assert "download_endpoint" not in ctx  # omitted = undefined in template


def test_build_context_download_enabled_for_path_traversal(path_traversal_spec):
    ctx = _build_context(path_traversal_spec)
    assert ctx.get("download_endpoint") is True


# ---------------------------------------------------------------------------
# Minimal / empty spec
# ---------------------------------------------------------------------------


def test_render_minimal_spec(renderer):
    """Even a near-empty spec should render without errors."""
    spec = SnapshotSpec(
        topology={
            "hosts": ["web"],
            "zones": {"dmz": ["web"]},
            "users": [],
            "firewall_rules": [],
        },
    )
    with tempfile.TemporaryDirectory() as tmpdir:
        out = Path(tmpdir) / "minimal"
        renderer.render(spec, out)
        assert (out / "docker-compose.yml").exists()
        assert (out / "init.sql").exists()


# ---------------------------------------------------------------------------
# Integration: TemplateOnlyBuilder -> Renderer
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_builder_to_renderer_pipeline(tier1_manifest):
    """Full pipeline: TemplateOnlyBuilder generates spec, Renderer renders it."""
    from open_range.builder.builder import TemplateOnlyBuilder
    from open_range.protocols import BuildContext

    builder = TemplateOnlyBuilder()
    ctx = BuildContext(seed=42, tier=1)
    spec = await builder.build(tier1_manifest, ctx)

    renderer = SnapshotRenderer()
    with tempfile.TemporaryDirectory() as tmpdir:
        out = Path(tmpdir) / "pipeline_out"
        renderer.render(spec, out)

        # All 6 artifacts should exist
        for fname in [
            "docker-compose.yml", "Dockerfile.web", "Dockerfile.db",
            "nginx.conf", "init.sql", "iptables.rules",
        ]:
            assert (out / fname).exists(), f"Missing: {fname}"

        # docker-compose should reference the web service
        compose = (out / "docker-compose.yml").read_text()
        assert "web:" in compose

        # At least one flag should be in the rendered artifacts
        flag_value = spec.flags[0].value
        all_content = ""
        for fname in ["Dockerfile.web", "Dockerfile.db", "init.sql"]:
            all_content += (out / fname).read_text()
        assert flag_value in all_content, (
            f"Flag {flag_value} not found in any rendered artifact"
        )
