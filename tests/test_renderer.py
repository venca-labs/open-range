"""Tests for KindRenderer -- Helm chart + Kind config rendering pipeline."""

import tempfile
from pathlib import Path

import pytest
import yaml

from open_range.builder.renderer import KindRenderer, _find_db_user, _find_db_pass
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
    return KindRenderer()


@pytest.fixture
def sqli_spec():
    """SnapshotSpec with a SQLi vuln."""
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
        files={
            "web:/var/www/html/index.php": "<?php echo 'hello'; ?>",
            "db:sql": "USE flags;\nINSERT INTO secrets(flag_name, flag) VALUES ('flag1', 'FLAG{sql1_t3st_f1ag}');\n",
        },
    )


@pytest.fixture
def minimal_spec():
    return SnapshotSpec(
        topology={
            "hosts": ["web", "db"],
            "zones": {"dmz": ["web"], "internal": ["db"]},
            "users": [],
            "firewall_rules": [],
        },
    )


# ---------------------------------------------------------------------------
# Output structure tests
# ---------------------------------------------------------------------------


def test_render_creates_output_dir(renderer, sqli_spec):
    with tempfile.TemporaryDirectory() as tmpdir:
        out = Path(tmpdir) / "snapshot_out"
        result = renderer.render(sqli_spec, out)
        assert result == out
        assert out.is_dir()


def test_render_produces_kind_config(renderer, sqli_spec):
    with tempfile.TemporaryDirectory() as tmpdir:
        out = Path(tmpdir) / "out"
        renderer.render(sqli_spec, out)
        kind_cfg = out / "kind-config.yaml"
        assert kind_cfg.exists()
        data = yaml.safe_load(kind_cfg.read_text())
        assert data["kind"] == "Cluster"
        assert data["apiVersion"] == "kind.x-k8s.io/v1alpha4"


def test_render_produces_helm_chart(renderer, sqli_spec):
    with tempfile.TemporaryDirectory() as tmpdir:
        out = Path(tmpdir) / "out"
        renderer.render(sqli_spec, out)
        chart = out / "openrange"
        assert chart.is_dir()
        assert (chart / "Chart.yaml").exists()
        assert (chart / "values.yaml").exists()
        assert (chart / "templates").is_dir()


def test_render_chart_has_all_templates(renderer, sqli_spec):
    with tempfile.TemporaryDirectory() as tmpdir:
        out = Path(tmpdir) / "out"
        renderer.render(sqli_spec, out)
        templates = out / "openrange" / "templates"
        expected = [
            "_helpers.tpl",
            "namespaces.yaml",
            "networkpolicies.yaml",
            "deployments.yaml",
            "services.yaml",
            "configmaps.yaml",
            "secrets.yaml",
        ]
        for name in expected:
            assert (templates / name).exists(), f"Missing template: {name}"


def test_render_idempotent(renderer, sqli_spec):
    with tempfile.TemporaryDirectory() as tmpdir:
        out = Path(tmpdir) / "out"
        renderer.render(sqli_spec, out)
        v1 = (out / "openrange" / "values.yaml").read_text()
        renderer.render(sqli_spec, out)
        v2 = (out / "openrange" / "values.yaml").read_text()
        assert v1 == v2


# ---------------------------------------------------------------------------
# values.yaml content tests
# ---------------------------------------------------------------------------


def test_values_has_global(renderer, sqli_spec):
    with tempfile.TemporaryDirectory() as tmpdir:
        out = Path(tmpdir) / "out"
        renderer.render(sqli_spec, out)
        values = yaml.safe_load((out / "openrange" / "values.yaml").read_text())
        assert "global" in values
        assert values["global"]["namePrefix"] == "openrange"


def test_values_has_zones(renderer, sqli_spec):
    with tempfile.TemporaryDirectory() as tmpdir:
        out = Path(tmpdir) / "out"
        renderer.render(sqli_spec, out)
        values = yaml.safe_load((out / "openrange" / "values.yaml").read_text())
        zones = values["zones"]
        assert "external" in zones
        assert "dmz" in zones
        assert "internal" in zones
        assert "management" in zones
        assert "web" in zones["dmz"]["hosts"]


def test_values_has_services(renderer, sqli_spec):
    with tempfile.TemporaryDirectory() as tmpdir:
        out = Path(tmpdir) / "out"
        renderer.render(sqli_spec, out)
        values = yaml.safe_load((out / "openrange" / "values.yaml").read_text())
        services = values["services"]
        assert "web" in services
        assert "db" in services
        assert "attacker" in services
        assert services["web"]["zone"] == "dmz"
        assert services["db"]["zone"] == "internal"


def test_values_firewall_skipped(renderer, sqli_spec):
    """Firewall host has no image and should not appear in services."""
    with tempfile.TemporaryDirectory() as tmpdir:
        out = Path(tmpdir) / "out"
        renderer.render(sqli_spec, out)
        values = yaml.safe_load((out / "openrange" / "values.yaml").read_text())
        assert "firewall" not in values["services"]


def test_values_has_firewall_rules(renderer, sqli_spec):
    with tempfile.TemporaryDirectory() as tmpdir:
        out = Path(tmpdir) / "out"
        renderer.render(sqli_spec, out)
        values = yaml.safe_load((out / "openrange" / "values.yaml").read_text())
        rules = values["firewallRules"]
        assert len(rules) >= 1
        allow = [r for r in rules if r["action"] == "allow"]
        assert len(allow) >= 1
        assert allow[0]["fromZone"] == "external"
        assert allow[0]["toZone"] == "dmz"


def test_values_web_has_db_env(renderer, sqli_spec):
    with tempfile.TemporaryDirectory() as tmpdir:
        out = Path(tmpdir) / "out"
        renderer.render(sqli_spec, out)
        values = yaml.safe_load((out / "openrange" / "values.yaml").read_text())
        env = values["services"]["web"]["env"]
        assert "DB_HOST" in env
        assert env["DB_HOST"] == "db"
        assert "DB_USER" in env


def test_values_db_has_mysql_env(renderer, sqli_spec):
    with tempfile.TemporaryDirectory() as tmpdir:
        out = Path(tmpdir) / "out"
        renderer.render(sqli_spec, out)
        values = yaml.safe_load((out / "openrange" / "values.yaml").read_text())
        env = values["services"]["db"]["env"]
        assert env["MYSQL_DATABASE"] == "referral_db"
        assert "MYSQL_ROOT_PASSWORD" in env


def test_values_attacker_has_sleep_command(renderer, sqli_spec):
    with tempfile.TemporaryDirectory() as tmpdir:
        out = Path(tmpdir) / "out"
        renderer.render(sqli_spec, out)
        values = yaml.safe_load((out / "openrange" / "values.yaml").read_text())
        cmd = values["services"]["attacker"]["command"]
        assert "sleep" in cmd
        assert "infinity" in cmd


def test_values_has_users(renderer, sqli_spec):
    with tempfile.TemporaryDirectory() as tmpdir:
        out = Path(tmpdir) / "out"
        renderer.render(sqli_spec, out)
        values = yaml.safe_load((out / "openrange" / "values.yaml").read_text())
        usernames = {u["username"] for u in values["users"]}
        assert "admin" in usernames
        assert "testuser" in usernames


def test_values_has_flags(renderer, sqli_spec):
    with tempfile.TemporaryDirectory() as tmpdir:
        out = Path(tmpdir) / "out"
        renderer.render(sqli_spec, out)
        values = yaml.safe_load((out / "openrange" / "values.yaml").read_text())
        assert len(values["flags"]) == 1
        assert values["flags"][0]["value"] == "FLAG{sql1_t3st_f1ag}"


# ---------------------------------------------------------------------------
# Payload / ConfigMap tests
# ---------------------------------------------------------------------------


def test_web_payloads_in_values(renderer, sqli_spec):
    with tempfile.TemporaryDirectory() as tmpdir:
        out = Path(tmpdir) / "out"
        renderer.render(sqli_spec, out)
        values = yaml.safe_load((out / "openrange" / "values.yaml").read_text())
        web_payloads = values["services"]["web"]["payloads"]
        mount_paths = {p["mountPath"] for p in web_payloads}
        assert "/var/www/html/index.php" in mount_paths


def test_db_sql_mapped_to_entrypoint(renderer, sqli_spec):
    with tempfile.TemporaryDirectory() as tmpdir:
        out = Path(tmpdir) / "out"
        renderer.render(sqli_spec, out)
        values = yaml.safe_load((out / "openrange" / "values.yaml").read_text())
        db_payloads = values["services"]["db"]["payloads"]
        mount_paths = {p["mountPath"] for p in db_payloads}
        assert "/docker-entrypoint-initdb.d/99-openrange-init.sh" in mount_paths


def test_flag_file_in_web_payloads(renderer, sqli_spec):
    """File-based flags should be added as payloads on the flag's host."""
    with tempfile.TemporaryDirectory() as tmpdir:
        out = Path(tmpdir) / "out"
        renderer.render(sqli_spec, out)
        values = yaml.safe_load((out / "openrange" / "values.yaml").read_text())
        web_payloads = values["services"]["web"]["payloads"]
        flag_payloads = [p for p in web_payloads if "FLAG{" in p.get("content", "")]
        assert len(flag_payloads) >= 1
        assert flag_payloads[0]["mountPath"] == "/var/flags/flag1.txt"


def test_db_flag_not_in_web_payloads(renderer):
    """DB-path flags should NOT appear as web payloads."""
    spec = SnapshotSpec(
        topology={
            "hosts": ["web", "db"],
            "zones": {"dmz": ["web"], "internal": ["db"]},
            "users": [],
            "firewall_rules": [],
        },
        flags=[
            FlagSpec(id="f1", value="FLAG{db_only}", path="db:flags.secrets.flag", host="db"),
        ],
    )
    with tempfile.TemporaryDirectory() as tmpdir:
        out = Path(tmpdir) / "out"
        KindRenderer().render(spec, out)
        values = yaml.safe_load((out / "openrange" / "values.yaml").read_text())
        web_svc = values["services"].get("web", {})
        web_payloads = web_svc.get("payloads", [])
        for p in web_payloads:
            assert "FLAG{db_only}" not in p.get("content", "")


# ---------------------------------------------------------------------------
# Kind config tests
# ---------------------------------------------------------------------------


def test_kind_config_has_port_mappings(renderer, sqli_spec):
    with tempfile.TemporaryDirectory() as tmpdir:
        out = Path(tmpdir) / "out"
        renderer.render(sqli_spec, out)
        data = yaml.safe_load((out / "kind-config.yaml").read_text())
        nodes = data["nodes"]
        assert len(nodes) == 1
        mappings = nodes[0]["extraPortMappings"]
        assert len(mappings) >= 1


def test_kind_config_disables_default_cni(renderer, sqli_spec):
    with tempfile.TemporaryDirectory() as tmpdir:
        out = Path(tmpdir) / "out"
        renderer.render(sqli_spec, out)
        data = yaml.safe_load((out / "kind-config.yaml").read_text())
        assert data["networking"]["disableDefaultCNI"] is True


# ---------------------------------------------------------------------------
# Helper function tests
# ---------------------------------------------------------------------------


def test_find_db_user_non_admin():
    users = [
        {"username": "worker", "password": "Pass!", "groups": ["users"], "hosts": ["db"]},
    ]
    assert _find_db_user(users) == "worker"
    assert _find_db_pass(users) == "Pass!"


def test_find_db_user_skips_admin():
    users = [
        {"username": "root_admin", "password": "X", "groups": ["admins"], "hosts": ["db"]},
    ]
    assert _find_db_user(users) == "app_user"


def test_find_db_user_default():
    assert _find_db_user([]) == "app_user"
    assert _find_db_pass([]) == "AppUs3r!2024"


# ---------------------------------------------------------------------------
# Minimal / empty specs
# ---------------------------------------------------------------------------


def test_render_minimal_spec(renderer, minimal_spec):
    with tempfile.TemporaryDirectory() as tmpdir:
        out = Path(tmpdir) / "minimal"
        renderer.render(minimal_spec, out)
        assert (out / "kind-config.yaml").exists()
        assert (out / "openrange" / "values.yaml").exists()


def test_render_empty_topology(renderer):
    spec = SnapshotSpec(topology={})
    with tempfile.TemporaryDirectory() as tmpdir:
        out = Path(tmpdir) / "empty"
        renderer.render(spec, out)
        values = yaml.safe_load((out / "openrange" / "values.yaml").read_text())
        assert values["zones"] == {}
        assert values["services"] == {}


# ---------------------------------------------------------------------------
# Integration: TemplateOnlyBuilder -> KindRenderer
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_builder_to_renderer_pipeline(tier1_manifest):
    """Full pipeline: TemplateOnlyBuilder generates spec, KindRenderer renders it."""
    from open_range.builder.builder import TemplateOnlyBuilder
    from open_range.protocols import BuildContext

    builder = TemplateOnlyBuilder()
    ctx = BuildContext(seed=42, tier=1)
    spec = await builder.build(tier1_manifest, ctx)

    renderer = KindRenderer()
    with tempfile.TemporaryDirectory() as tmpdir:
        out = Path(tmpdir) / "pipeline_out"
        renderer.render(spec, out)

        assert (out / "kind-config.yaml").exists()
        chart = out / "openrange"
        assert (chart / "Chart.yaml").exists()
        assert (chart / "values.yaml").exists()

        values = yaml.safe_load((chart / "values.yaml").read_text())
        assert "web" in values["services"]
        assert len(values["flags"]) >= 1
