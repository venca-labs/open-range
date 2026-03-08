"""Tests for ServiceSpec, ReadinessCheck, and generate_service_specs().

Covers:
- ServiceSpec / ReadinessCheck serialization round-trips
- generate_service_specs() with compose input (tier-1 and tier-3 services)
- generate_service_specs() with topology fallback (no compose)
- Backward compatibility: SnapshotSpec without services field
- Unknown images produce no specs (graceful skip)
- Environment service lifecycle integration
- Renderer generates services field in snapshot
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from open_range.builder.service_manifest import (
    _HOST_NAME_HINTS,
    _IMAGE_SERVICE_HINTS,
    _match_image_hint,
    generate_service_specs,
)
from open_range.protocols import (
    ReadinessCheck,
    ServiceSpec,
    SnapshotSpec,
    TaskSpec,
)


# ---------------------------------------------------------------------------
# ServiceSpec / ReadinessCheck serialization
# ---------------------------------------------------------------------------


class TestReadinessCheck:
    """ReadinessCheck model basics and serialization."""

    def test_defaults(self):
        rc = ReadinessCheck()
        assert rc.type == "tcp"
        assert rc.port == 0
        assert rc.url == ""
        assert rc.command == ""
        assert rc.timeout_s == 30
        assert rc.interval_s == 1.0

    def test_tcp_check(self):
        rc = ReadinessCheck(type="tcp", port=80, timeout_s=10)
        assert rc.type == "tcp"
        assert rc.port == 80

    def test_http_check(self):
        rc = ReadinessCheck(type="http", url="http://localhost:8080/health")
        assert rc.type == "http"
        assert rc.url == "http://localhost:8080/health"

    def test_command_check(self):
        rc = ReadinessCheck(type="command", command="pgrep -x nginx")
        assert rc.type == "command"
        assert rc.command == "pgrep -x nginx"

    def test_roundtrip_json(self):
        rc = ReadinessCheck(type="http", url="http://localhost:9090", timeout_s=15)
        data = rc.model_dump()
        rc2 = ReadinessCheck(**data)
        assert rc2.type == rc.type
        assert rc2.url == rc.url
        assert rc2.timeout_s == rc.timeout_s


class TestServiceSpec:
    """ServiceSpec model basics and serialization."""

    def test_required_fields(self):
        svc = ServiceSpec(host="web", daemon="nginx", start_command="nginx &")
        assert svc.host == "web"
        assert svc.daemon == "nginx"
        assert svc.start_command == "nginx &"

    def test_defaults(self):
        svc = ServiceSpec(host="web", daemon="nginx", start_command="nginx &")
        assert svc.packages == []
        assert svc.init_commands == []
        assert svc.env_vars == {}
        assert svc.log_dir == ""
        assert isinstance(svc.readiness, ReadinessCheck)

    def test_full_spec(self):
        svc = ServiceSpec(
            host="db",
            daemon="mysqld",
            packages=["default-mysql-server"],
            init_commands=["mkdir -p /var/run/mysqld"],
            start_command="mysqld --user=mysql &",
            readiness=ReadinessCheck(
                type="command",
                command="mysqladmin ping",
                timeout_s=30,
            ),
            log_dir="/var/log/siem",
            env_vars={"MYSQL_ROOT_PASSWORD": "secret"},
        )
        assert svc.daemon == "mysqld"
        assert len(svc.init_commands) == 1
        assert svc.readiness.type == "command"
        assert svc.env_vars["MYSQL_ROOT_PASSWORD"] == "secret"

    def test_roundtrip_json(self):
        svc = ServiceSpec(
            host="web",
            daemon="nginx",
            packages=["nginx"],
            init_commands=["mkdir -p /var/log/nginx"],
            start_command="nginx -g 'daemon off;' &",
            readiness=ReadinessCheck(type="tcp", port=80),
            log_dir="/var/log/siem",
            env_vars={"SERVER_NAME": "web.corp.local"},
        )
        data = json.loads(svc.model_dump_json())
        svc2 = ServiceSpec(**data)
        assert svc2.host == svc.host
        assert svc2.daemon == svc.daemon
        assert svc2.packages == svc.packages
        assert svc2.readiness.port == 80
        assert svc2.env_vars == svc.env_vars


# ---------------------------------------------------------------------------
# SnapshotSpec backward compatibility
# ---------------------------------------------------------------------------


class TestSnapshotSpecServices:
    """SnapshotSpec.services field: default and serialization."""

    def test_default_empty(self):
        spec = SnapshotSpec()
        assert spec.services == []

    def test_with_services(self):
        spec = SnapshotSpec(
            topology={"hosts": ["web"]},
            services=[
                ServiceSpec(host="web", daemon="nginx", start_command="nginx &"),
            ],
        )
        assert len(spec.services) == 1
        assert spec.services[0].daemon == "nginx"

    def test_roundtrip_preserves_services(self):
        svc = ServiceSpec(
            host="db",
            daemon="mysqld",
            start_command="mysqld &",
            readiness=ReadinessCheck(type="tcp", port=3306),
        )
        spec = SnapshotSpec(
            topology={"hosts": ["db"]},
            services=[svc],
        )
        data = json.loads(spec.model_dump_json())
        spec2 = SnapshotSpec(**data)
        assert len(spec2.services) == 1
        assert spec2.services[0].daemon == "mysqld"
        assert spec2.services[0].readiness.port == 3306

    def test_old_snapshot_without_services_parses(self):
        """Simulate loading a JSON snapshot that predates the services field."""
        old_data = {
            "topology": {"hosts": ["web", "db"]},
            "flags": [],
            "golden_path": [],
        }
        spec = SnapshotSpec(**old_data)
        assert spec.services == []


# ---------------------------------------------------------------------------
# generate_service_specs() — compose input
# ---------------------------------------------------------------------------


class TestGenerateFromCompose:
    """generate_service_specs() with compose services dict."""

    def test_tier1_basic_compose(self):
        """Tier 1 compose with common services maps correctly."""
        compose = {
            "services": {
                "web": {"image": "nginx:1.25"},
                "db": {"image": "mysql:8.0"},
                "ldap": {"image": "osixia/openldap:1.5"},
                "siem": {"image": "rsyslog:latest"},
                "files": {"image": "samba:latest"},
                "mail": {"image": "postfix:latest"},
                "attacker": {"image": "kali:latest"},
            }
        }
        topology = {"hosts": ["attacker", "web", "db", "ldap", "siem", "files", "mail"]}
        specs = generate_service_specs(compose, topology)

        daemon_names = {s.daemon for s in specs}
        assert "nginx" in daemon_names
        assert "mysqld" in daemon_names
        assert "slapd" in daemon_names
        assert "rsyslogd" in daemon_names
        assert "smbd" in daemon_names
        assert "master" in daemon_names  # postfix

    def test_tier3_compose_with_extra_services(self):
        """Tier 3 compose with redis, postgres, jenkins."""
        compose = {
            "services": {
                "web": {"image": "nginx:1.25"},
                "cache": {"image": "redis:7"},
                "db": {"image": "postgres:16"},
                "ci_cd": {"image": "jenkins/jenkins:lts"},
                "monitoring": {"image": "prometheus:latest"},
            }
        }
        topology = {"hosts": ["web", "cache", "db", "ci_cd", "monitoring"]}
        specs = generate_service_specs(compose, topology)

        daemon_names = {s.daemon for s in specs}
        assert "nginx" in daemon_names
        assert "redis-server" in daemon_names
        assert "postgres" in daemon_names
        assert "java" in daemon_names  # jenkins
        assert "prometheus" in daemon_names

    def test_unknown_image_skipped(self):
        """Custom images with no hint produce no specs."""
        compose = {
            "services": {
                "custom_app": {"image": "mycompany/custom-app:1.0"},
                "web": {"image": "nginx:1.25"},
            }
        }
        specs = generate_service_specs(compose, {"hosts": []})
        assert len(specs) == 1
        assert specs[0].daemon == "nginx"

    def test_empty_compose(self):
        """Empty compose falls through to topology."""
        specs = generate_service_specs({}, {"hosts": ["web", "db"]})
        daemon_names = {s.daemon for s in specs}
        assert "nginx" in daemon_names
        assert "mysqld" in daemon_names

    def test_compose_env_vars_extracted(self):
        """Environment variables from compose are passed to ServiceSpec."""
        compose = {
            "services": {
                "db": {
                    "image": "mysql:8.0",
                    "environment": {"MYSQL_ROOT_PASSWORD": "secret"},
                },
            }
        }
        specs = generate_service_specs(compose, {"hosts": []})
        assert len(specs) == 1
        assert specs[0].env_vars.get("MYSQL_ROOT_PASSWORD") == "secret"

    def test_compose_env_vars_list_form(self):
        """Environment in list form (KEY=VALUE) is handled."""
        compose = {
            "services": {
                "db": {
                    "image": "mysql:8.0",
                    "environment": ["MYSQL_ROOT_PASSWORD=secret", "MYSQL_DATABASE=app"],
                },
            }
        }
        specs = generate_service_specs(compose, {"hosts": []})
        assert specs[0].env_vars["MYSQL_ROOT_PASSWORD"] == "secret"
        assert specs[0].env_vars["MYSQL_DATABASE"] == "app"

    def test_repeated_daemons_on_different_hosts_are_preserved(self):
        """Two hosts may intentionally run the same daemon family."""
        compose = {
            "services": {
                "siem": {"image": "rsyslog:latest"},
                "firewall": {"image": "rsyslog:latest"},
            }
        }
        specs = generate_service_specs(compose, {"hosts": []})
        assert len(specs) == 2
        assert {spec.host for spec in specs} == {"siem", "firewall"}
        assert all(spec.daemon == "rsyslogd" for spec in specs)

    def test_same_daemon_across_multiple_web_hosts(self):
        compose = {
            "services": {
                "web1": {"image": "nginx:1.25"},
                "web2": {"image": "nginx:1.25"},
            }
        }
        specs = generate_service_specs(compose, {"hosts": ["web1", "web2"]})
        assert len(specs) == 2
        assert {spec.host for spec in specs} == {"web1", "web2"}
        assert all(spec.daemon == "nginx" for spec in specs)


# ---------------------------------------------------------------------------
# generate_service_specs() — topology fallback
# ---------------------------------------------------------------------------


class TestGenerateFromTopology:
    """generate_service_specs() falls back to topology when compose is empty."""

    def test_basic_topology_hosts(self):
        topology = {
            "hosts": ["attacker", "web", "db", "ldap", "siem", "files", "mail"],
        }
        specs = generate_service_specs({}, topology)

        daemon_names = {s.daemon for s in specs}
        assert "nginx" in daemon_names
        assert "mysqld" in daemon_names
        assert "slapd" in daemon_names
        assert "rsyslogd" in daemon_names
        assert "smbd" in daemon_names
        assert "master" in daemon_names

    def test_unknown_host_skipped(self):
        topology = {"hosts": ["attacker", "custom_box"]}
        specs = generate_service_specs({}, topology)
        assert len(specs) == 0

    def test_dict_hosts(self):
        """Hosts as dicts with 'name' key."""
        topology = {
            "hosts": [
                {"name": "web", "zone": "dmz"},
                {"name": "db", "zone": "internal"},
            ],
        }
        specs = generate_service_specs({}, topology)
        daemon_names = {s.daemon for s in specs}
        assert "nginx" in daemon_names
        assert "mysqld" in daemon_names

    def test_empty_topology(self):
        specs = generate_service_specs({}, {})
        assert specs == []


# ---------------------------------------------------------------------------
# _match_image_hint internals
# ---------------------------------------------------------------------------


class TestMatchImageHint:
    """_match_image_hint matches Docker image strings to hint entries."""

    def test_exact_match(self):
        hint = _match_image_hint("nginx")
        assert hint is not None
        assert hint[0] == "nginx"

    def test_tagged_image(self):
        hint = _match_image_hint("mysql:8.0")
        assert hint is not None
        assert hint[0] == "mysqld"

    def test_namespaced_image(self):
        hint = _match_image_hint("osixia/openldap:1.5")
        assert hint is not None
        assert hint[0] == "slapd"

    def test_basename_fallback(self):
        """bitnami/redis:7 should match via basename 'redis'."""
        hint = _match_image_hint("bitnami/redis:7")
        assert hint is not None
        assert hint[0] == "redis-server"

    def test_unknown_image(self):
        hint = _match_image_hint("mycompany/custom-service:v2")
        assert hint is None

    def test_empty_image(self):
        hint = _match_image_hint("")
        assert hint is None


# ---------------------------------------------------------------------------
# Environment integration: service lifecycle methods
# ---------------------------------------------------------------------------


class TestEnvironmentServiceLifecycle:
    """RangeEnvironment service lifecycle methods."""

    def test_start_snapshot_services_noop_in_docker_mode(self):
        """_start_snapshot_services is a no-op when execution_mode != subprocess."""
        from open_range.server.environment import RangeEnvironment

        env = RangeEnvironment(docker_available=False)
        # execution_mode defaults to "docker" when docker_available=False (mock)
        snapshot = SnapshotSpec(
            topology={"hosts": ["web"]},
            services=[ServiceSpec(host="web", daemon="nginx", start_command="nginx &")],
        )
        # Should not raise or attempt to start anything
        env._start_snapshot_services(snapshot)

    @patch("subprocess.Popen")
    @patch("subprocess.run")
    def test_start_snapshot_services_subprocess_mode(self, mock_run, mock_popen):
        """_start_snapshot_services starts declared services in subprocess mode."""
        from open_range.server.environment import RangeEnvironment

        # Mock Popen to return an object with a wait() method
        mock_proc = MagicMock()
        mock_popen.return_value = mock_proc

        env = RangeEnvironment(docker_available=False, execution_mode="subprocess")
        snapshot = SnapshotSpec(
            topology={"hosts": ["web"]},
            services=[
                ServiceSpec(
                    host="web",
                    daemon="nginx",
                    init_commands=["mkdir -p /var/log/nginx"],
                    start_command="nginx &",
                    readiness=ReadinessCheck(type="tcp", port=80, timeout_s=0),
                ),
            ],
        )
        env._start_snapshot_services(snapshot)
        # Init commands use subprocess.run, daemon start uses Popen
        assert mock_run.call_count >= 1  # init command
        assert mock_popen.call_count >= 1  # daemon start

    def test_start_services_empty_skips(self):
        """When no services are declared, logs and skips provisioning."""
        from open_range.server.environment import RangeEnvironment

        env = RangeEnvironment(docker_available=False, execution_mode="subprocess")
        snapshot = SnapshotSpec(
            topology={"hosts": ["web", "db"]},
            services=[],  # empty
        )
        # Should not raise — just logs and returns
        env._start_snapshot_services(snapshot)

    @patch("subprocess.run")
    def test_stop_services_uses_snapshot_daemons(self, mock_run):
        """_stop_services uses daemon names from snapshot.services."""
        from open_range.server.environment import RangeEnvironment

        env = RangeEnvironment(docker_available=False, execution_mode="subprocess")
        env._snapshot = SnapshotSpec(
            topology={"hosts": ["web"]},
            services=[
                ServiceSpec(host="web", daemon="nginx", start_command="nginx &"),
                ServiceSpec(host="db", daemon="mysqld", start_command="mysqld &"),
            ],
        )
        env._stop_services()

        # Should have called pkill for each daemon (either individually or via bash -c)
        all_call_strs = []
        for call in mock_run.call_args_list:
            args = call[0][0] if call[0] else call.kwargs.get("args", [])
            all_call_strs.append(" ".join(str(a) for a in args))
        combined = " ".join(all_call_strs)
        assert "nginx" in combined
        assert "mysqld" in combined

    def test_stop_services_no_services_skips_pkill(self):
        """_stop_services skips pkill when snapshot has no services."""
        from open_range.server.environment import RangeEnvironment

        env = RangeEnvironment(docker_available=False, execution_mode="subprocess")
        env._snapshot = SnapshotSpec(topology={"hosts": ["web"]})
        # Should not raise — just skips pkill since no service specs
        env._stop_services()

    def test_stop_services_no_snapshot(self):
        """_stop_services handles None snapshot gracefully."""
        from open_range.server.environment import RangeEnvironment

        env = RangeEnvironment(docker_available=False, execution_mode="subprocess")
        env._snapshot = None
        # Should not raise
        env._stop_services()

    def test_probe_readiness_tcp_unreachable(self):
        """TCP probe returns False for unreachable port."""
        from open_range.server.environment import RangeEnvironment

        check = ReadinessCheck(type="tcp", port=19999)
        assert RangeEnvironment._probe_readiness(check) is False

    def test_probe_readiness_command_success(self):
        """Command probe returns True for 'true' command."""
        from open_range.server.environment import RangeEnvironment

        check = ReadinessCheck(type="command", command="true")
        assert RangeEnvironment._probe_readiness(check) is True

    def test_probe_readiness_command_failure(self):
        """Command probe returns False for 'false' command."""
        from open_range.server.environment import RangeEnvironment

        check = ReadinessCheck(type="command", command="false")
        assert RangeEnvironment._probe_readiness(check) is False

    def test_reset_calls_service_lifecycle(self):
        """reset() calls _stop_services and _start_snapshot_services."""
        from open_range.server.environment import RangeEnvironment

        env = RangeEnvironment(docker_available=False)
        stop_called = []
        start_called = []

        env._stop_services = lambda: stop_called.append(True)  # type: ignore
        env._start_snapshot_services = lambda s: start_called.append(s)  # type: ignore

        snapshot = SnapshotSpec(
            topology={"hosts": ["attacker", "web"]},
            task=TaskSpec(red_briefing="Test.", blue_briefing="Test."),
        )
        env.reset(snapshot=snapshot)
        assert len(stop_called) == 1
        assert len(start_called) == 1


# ---------------------------------------------------------------------------
# Renderer generates services in snapshot
# ---------------------------------------------------------------------------


class TestRendererServiceGeneration:
    """SnapshotRenderer._build_service_specs() populates spec.services."""

    def test_renderer_populates_services_from_topology(self):
        from open_range.builder.renderer import SnapshotRenderer

        renderer = SnapshotRenderer()
        spec = SnapshotSpec(
            topology={
                "hosts": ["web", "db", "ldap"],
                "zones": {"dmz": ["web"], "internal": ["db", "ldap"]},
                "users": [],
                "firewall_rules": [],
            },
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            renderer.render(spec, Path(tmpdir) / "out")

        # After rendering, services should be populated
        assert len(spec.services) >= 2
        daemon_names = {s.daemon for s in spec.services}
        assert "nginx" in daemon_names
        assert "mysqld" in daemon_names

    def test_renderer_skips_if_services_already_present(self):
        from open_range.builder.renderer import SnapshotRenderer

        renderer = SnapshotRenderer()
        existing_svc = ServiceSpec(host="web", daemon="nginx", start_command="nginx &")
        spec = SnapshotSpec(
            topology={
                "hosts": ["web", "db"],
                "zones": {"dmz": ["web"], "internal": ["db"]},
                "users": [],
                "firewall_rules": [],
            },
            services=[existing_svc],
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            renderer.render(spec, Path(tmpdir) / "out")

        # Should not have overwritten — still just the one we provided
        assert len(spec.services) == 1
        assert spec.services[0].daemon == "nginx"


# ---------------------------------------------------------------------------
# Hint table coverage
# ---------------------------------------------------------------------------


class TestHintTableCoverage:
    """All image hints produce valid ServiceSpec entries."""

    @pytest.mark.parametrize("image_key", list(_IMAGE_SERVICE_HINTS.keys()))
    def test_hint_produces_valid_spec(self, image_key):
        """Each entry in the hint table produces a valid ServiceSpec."""
        compose = {"services": {"svc": {"image": image_key}}}
        specs = generate_service_specs(compose, {"hosts": []})
        assert len(specs) == 1
        svc = specs[0]
        assert svc.daemon
        assert svc.start_command
        assert isinstance(svc.readiness, ReadinessCheck)

    @pytest.mark.parametrize("host_name", list(_HOST_NAME_HINTS.keys()))
    def test_host_hint_produces_valid_spec(self, host_name):
        """Each entry in the host-name hint table produces a valid ServiceSpec."""
        specs = generate_service_specs({}, {"hosts": [host_name]})
        assert len(specs) >= 1
        svc = specs[0]
        assert svc.daemon
        assert svc.start_command
