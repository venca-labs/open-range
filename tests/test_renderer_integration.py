"""Integration tests for the full renderer pipeline.

Loads real LLM output from snapshots/llm_tier1_test.json, parses it
through _parse_llm_response(), renders through SnapshotRenderer.render(),
and verifies all output files contain expected content.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from open_range.builder.builder import _parse_llm_response
from open_range.builder.renderer import SnapshotRenderer

ROOT = Path(__file__).parent.parent
SNAPSHOT_PATH = ROOT / "snapshots" / "llm_tier1_test.json"


@pytest.fixture
def llm_output() -> dict:
    """Load the real LLM output JSON."""
    if not SNAPSHOT_PATH.exists():
        pytest.skip("llm_tier1_test.json fixture not present")
    return json.loads(SNAPSHOT_PATH.read_text())


@pytest.fixture
def parsed_spec(llm_output):
    """Parse real LLM output through _parse_llm_response."""
    return _parse_llm_response(json.dumps(llm_output))


@pytest.fixture
def rendered_dir(parsed_spec):
    """Render the parsed spec and yield the output directory."""
    renderer = SnapshotRenderer()
    with tempfile.TemporaryDirectory() as tmpdir:
        out = Path(tmpdir) / "integration_out"
        renderer.render(parsed_spec, out)
        yield out


# ---------------------------------------------------------------------------
# Pipeline: parse -> render round-trip
# ---------------------------------------------------------------------------


class TestParseLLMOutput:
    """Verify _parse_llm_response correctly handles real LLM output."""

    def test_parse_produces_snapshot_spec(self, parsed_spec):
        from open_range.protocols import SnapshotSpec
        assert isinstance(parsed_spec, SnapshotSpec)

    def test_parse_has_topology(self, parsed_spec):
        assert "hosts" in parsed_spec.topology
        assert len(parsed_spec.topology["hosts"]) == 8

    def test_parse_has_vulns(self, parsed_spec):
        assert len(parsed_spec.truth_graph.vulns) >= 1
        vuln_types = {v.type for v in parsed_spec.truth_graph.vulns}
        assert "sqli" in vuln_types

    def test_parse_has_flags(self, parsed_spec):
        assert len(parsed_spec.flags) >= 2

    def test_parse_has_golden_path(self, parsed_spec):
        assert len(parsed_spec.golden_path) >= 1
        # Golden path steps should have commands
        for step in parsed_spec.golden_path:
            assert step.command, f"Step {step.step} has empty command"

    def test_parse_has_task_briefings(self, parsed_spec):
        assert parsed_spec.task.red_briefing
        assert parsed_spec.task.blue_briefing

    def test_parse_has_files(self, parsed_spec):
        assert len(parsed_spec.files) > 0
        # Should include web files and db:sql
        web_files = [k for k in parsed_spec.files if k.startswith("web:")]
        assert len(web_files) > 0

    def test_parse_has_npc_personas(self, parsed_spec):
        assert len(parsed_spec.npc_personas) >= 1

    def test_golden_path_uses_command_field(self, parsed_spec):
        """LLM output uses 'cmd', parser should map to 'command'."""
        for step in parsed_spec.golden_path:
            assert step.command  # Should be populated from 'cmd' key

    def test_golden_path_uses_expect_in_stdout(self, parsed_spec):
        """LLM output uses 'expect_stdout', parser maps to 'expect_in_stdout'."""
        for step in parsed_spec.golden_path:
            assert step.expect_in_stdout


# ---------------------------------------------------------------------------
# All output files exist
# ---------------------------------------------------------------------------


class TestRenderedFilesExist:
    """Verify all 6 template outputs are created."""

    EXPECTED_FILES = [
        "docker-compose.yml",
        "Dockerfile.web",
        "Dockerfile.db",
        "nginx.conf",
        "init.sql",
        "iptables.rules",
    ]

    def test_all_output_files_exist(self, rendered_dir):
        for fname in self.EXPECTED_FILES:
            path = rendered_dir / fname
            assert path.exists(), f"Missing output file: {fname}"

    def test_all_output_files_non_empty(self, rendered_dir):
        for fname in self.EXPECTED_FILES:
            content = (rendered_dir / fname).read_text()
            assert len(content) > 0, f"Empty output file: {fname}"


# ---------------------------------------------------------------------------
# nginx.conf content verification
# ---------------------------------------------------------------------------


class TestNginxConf:
    """Verify rendered nginx.conf has correct content."""

    def test_references_php_fpm_socket(self, rendered_dir):
        nginx = (rendered_dir / "nginx.conf").read_text()
        assert "php8.1-fpm.sock" in nginx

    def test_has_server_block(self, rendered_dir):
        nginx = (rendered_dir / "nginx.conf").read_text()
        assert "server {" in nginx
        assert "listen 80" in nginx

    def test_has_php_location(self, rendered_dir):
        nginx = (rendered_dir / "nginx.conf").read_text()
        assert "location ~ \\.php$" in nginx

    def test_has_fastcgi_pass(self, rendered_dir):
        nginx = (rendered_dir / "nginx.conf").read_text()
        assert "fastcgi_pass unix:/run/php/php8.1-fpm.sock" in nginx


# ---------------------------------------------------------------------------
# docker-compose.yml content verification
# ---------------------------------------------------------------------------


class TestDockerCompose:
    """Verify rendered docker-compose.yml has correct static IPs and structure."""

    def test_has_services_section(self, rendered_dir):
        compose = (rendered_dir / "docker-compose.yml").read_text()
        assert "services:" in compose

    def test_has_all_core_services(self, rendered_dir):
        compose = (rendered_dir / "docker-compose.yml").read_text()
        for service in ["attacker:", "firewall:", "web:", "mail:", "db:", "siem:", "ldap:", "files:"]:
            assert service in compose, f"Missing service: {service}"

    def test_has_network_definitions(self, rendered_dir):
        compose = (rendered_dir / "docker-compose.yml").read_text()
        assert "networks:" in compose
        assert "external:" in compose
        assert "dmz:" in compose
        assert "internal:" in compose
        assert "management:" in compose

    def test_has_static_ips(self, rendered_dir):
        compose = (rendered_dir / "docker-compose.yml").read_text()
        # Key static IPs from the template
        assert "10.0.0.10" in compose  # attacker
        assert "10.0.0.2" in compose   # firewall external
        assert "10.0.1.10" in compose  # web dmz
        assert "10.0.2.20" in compose  # db internal
        assert "10.0.3.20" in compose  # ldap management
        assert "10.0.3.21" in compose  # siem management

    def test_web_depends_on_db(self, rendered_dir):
        compose = (rendered_dir / "docker-compose.yml").read_text()
        # web service should have depends_on db
        assert "depends_on:" in compose

    def test_has_subnet_definitions(self, rendered_dir):
        compose = (rendered_dir / "docker-compose.yml").read_text()
        assert "10.0.0.0/24" in compose  # external
        assert "10.0.1.0/24" in compose  # dmz
        assert "10.0.2.0/24" in compose  # internal
        assert "10.0.3.0/24" in compose  # management

    def test_has_healthchecks(self, rendered_dir):
        compose = (rendered_dir / "docker-compose.yml").read_text()
        assert "healthcheck:" in compose

    def test_web_healthcheck_does_not_require_pre_overlay_2xx(self, rendered_dir):
        compose = (rendered_dir / "docker-compose.yml").read_text()
        assert "CMD-SHELL" in compose
        assert "http://localhost/ || true" in compose
        assert "$$status" in compose
        assert '2*|3*|4*) exit 0' in compose
        assert 'curl", "-sf", "http://localhost/"' not in compose

    def test_attacker_has_net_admin(self, rendered_dir):
        compose = (rendered_dir / "docker-compose.yml").read_text()
        assert "NET_ADMIN" in compose

    def test_db_has_mysql_env_vars(self, rendered_dir):
        compose = (rendered_dir / "docker-compose.yml").read_text()
        assert "MYSQL_ROOT_PASSWORD" in compose
        assert "MYSQL_DATABASE=" in compose
        assert "MYSQL_USER=" in compose


# ---------------------------------------------------------------------------
# init.sql content verification
# ---------------------------------------------------------------------------


class TestInitSQL:
    """Verify rendered init.sql has referral_db and runtime-selected DB grants."""

    def test_creates_referral_db(self, rendered_dir):
        sql = (rendered_dir / "init.sql").read_text()
        assert "referral_db" in sql

    def test_creates_flags_db(self, rendered_dir):
        sql = (rendered_dir / "init.sql").read_text()
        assert "flags" in sql

    def test_creates_core_tables(self, rendered_dir):
        sql = (rendered_dir / "init.sql").read_text()
        assert "CREATE TABLE" in sql
        assert "users" in sql
        assert "patients" in sql
        assert "secrets" in sql

    def test_creates_healthcare_tables(self, rendered_dir):
        sql = (rendered_dir / "init.sql").read_text()
        assert "patient_referrals" in sql
        assert "billing" in sql

    def test_grants_runtime_db_user(self, rendered_dir):
        sql = (rendered_dir / "init.sql").read_text()
        assert "GRANT" in sql
        assert "TO '" in sql

    def test_has_flush_privileges(self, rendered_dir):
        sql = (rendered_dir / "init.sql").read_text()
        assert "FLUSH PRIVILEGES" in sql


# ---------------------------------------------------------------------------
# Dockerfile.web content verification
# ---------------------------------------------------------------------------


class TestDockerfileWeb:
    """Verify rendered Dockerfile.web creates users from topology."""

    def test_creates_users_from_topology(self, rendered_dir, parsed_spec):
        dockerfile = (rendered_dir / "Dockerfile.web").read_text()
        # Should have useradd for users from topology
        users = parsed_spec.topology.get("users", [])
        assert len(users) > 0, "Parsed spec should have users"
        for user in users:
            username = user.get("username", "")
            if username:
                assert "useradd" in dockerfile

    def test_has_php_fpm(self, rendered_dir):
        dockerfile = (rendered_dir / "Dockerfile.web").read_text()
        assert "php8.1-fpm" in dockerfile

    def test_has_nginx(self, rendered_dir):
        dockerfile = (rendered_dir / "Dockerfile.web").read_text()
        assert "nginx" in dockerfile

    def test_copies_nginx_conf(self, rendered_dir):
        dockerfile = (rendered_dir / "Dockerfile.web").read_text()
        assert "COPY nginx.conf" in dockerfile

    def test_exposes_ports(self, rendered_dir):
        dockerfile = (rendered_dir / "Dockerfile.web").read_text()
        assert "EXPOSE" in dockerfile
        assert "80" in dockerfile

    def test_plants_file_flags(self, rendered_dir, parsed_spec):
        """Flags with file paths on web host should appear in Dockerfile."""
        dockerfile = (rendered_dir / "Dockerfile.web").read_text()
        for flag in parsed_spec.flags:
            if flag.host == "web" and "/" in flag.path:
                assert flag.value in dockerfile, (
                    f"Flag {flag.id} ({flag.value}) not in Dockerfile.web"
                )

    def test_db_flags_not_in_dockerfile(self, rendered_dir, parsed_spec):
        """Flags with db: paths should NOT appear in Dockerfile.web."""
        dockerfile = (rendered_dir / "Dockerfile.web").read_text()
        for flag in parsed_spec.flags:
            if flag.path.startswith("mysql:") or flag.path.startswith("db:"):
                assert flag.value not in dockerfile, (
                    f"DB flag {flag.id} ({flag.value}) should not be in Dockerfile.web"
                )


# ---------------------------------------------------------------------------
# iptables.rules content verification
# ---------------------------------------------------------------------------


class TestIptablesRules:
    """Verify rendered iptables.rules has correct structure."""

    def test_has_filter_table(self, rendered_dir):
        rules = (rendered_dir / "iptables.rules").read_text()
        assert "*filter" in rules
        assert "COMMIT" in rules

    def test_has_forward_chain(self, rendered_dir):
        rules = (rendered_dir / "iptables.rules").read_text()
        assert "FORWARD" in rules


# ---------------------------------------------------------------------------
# Full round-trip: files dict is preserved through parse
# ---------------------------------------------------------------------------


class TestFilesPreserved:
    """Verify that files from LLM output survive the parse pipeline."""

    def test_files_dict_has_web_files(self, parsed_spec):
        web_files = {k: v for k, v in parsed_spec.files.items() if k.startswith("web:")}
        assert len(web_files) > 0

    def test_files_dict_has_sql(self, parsed_spec):
        assert "db:sql" in parsed_spec.files

    def test_index_php_content(self, parsed_spec):
        key = "web:/var/www/portal/index.php"
        assert key in parsed_spec.files
        assert "Meridian Referral Portal" in parsed_spec.files[key]

    def test_lookup_php_has_sqli(self, parsed_spec):
        key = "web:/var/www/portal/lookup.php"
        assert key in parsed_spec.files
        content = parsed_spec.files[key]
        # Should contain the vulnerable SQL query
        assert "last_name LIKE" in content or "$last" in content

    def test_compliance_report_has_flag(self, parsed_spec):
        key = "web:/var/www/portal/reports/hipaa_audit.txt"
        assert key in parsed_spec.files
        assert "FLAG{1a2b3c4d5e6f7788}" in parsed_spec.files[key]

    def test_sql_has_user_inserts(self, parsed_spec):
        sql = parsed_spec.files.get("db:sql", "")
        assert "dthompson" in sql
        assert "kwilliams" in sql

    def test_sql_has_flag_insert(self, parsed_spec):
        sql = parsed_spec.files.get("db:sql", "")
        assert "FLAG{9f3a2b4c5d6e7f80}" in sql

    def test_files_samba_shares(self, parsed_spec):
        files_entries = {k: v for k, v in parsed_spec.files.items() if k.startswith("files:")}
        assert len(files_entries) > 0

    def test_db_backup_script(self, parsed_spec):
        key = "db:/opt/scripts/db_backup.sh"
        assert key in parsed_spec.files
        assert "mysqldump" in parsed_spec.files[key]
