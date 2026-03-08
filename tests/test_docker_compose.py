"""Tests for docker-compose.yml and docker/ Dockerfiles.

Validates the base development stack structure without requiring Docker to be
running. These are parse-level and structural checks only.
"""

from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).parent.parent
COMPOSE_PATH = ROOT / "docker-compose.yml"
DOCKER_DIR = ROOT / "docker"


class TestComposeFileStructure:
    """docker-compose.yml parses and has the expected top-level keys."""

    @pytest.fixture(autouse=True)
    def load_compose(self):
        with open(COMPOSE_PATH) as f:
            self.compose = yaml.safe_load(f)

    def test_compose_file_exists(self):
        assert COMPOSE_PATH.exists()

    def test_has_networks(self):
        assert "networks" in self.compose

    def test_has_services(self):
        assert "services" in self.compose

    def test_has_volumes(self):
        assert "volumes" in self.compose


class TestNetworks:
    """All four zone networks are defined with correct subnets."""

    @pytest.fixture(autouse=True)
    def load_compose(self):
        with open(COMPOSE_PATH) as f:
            self.compose = yaml.safe_load(f)
        self.networks = self.compose["networks"]

    def test_four_networks_defined(self):
        expected = {"external", "dmz", "internal", "management"}
        assert expected == set(self.networks.keys())

    @pytest.mark.parametrize(
        "name,subnet",
        [
            ("external", "10.0.0.0/24"),
            ("dmz", "10.0.1.0/24"),
            ("internal", "10.0.2.0/24"),
            ("management", "10.0.3.0/24"),
        ],
    )
    def test_network_subnets(self, name, subnet):
        net = self.networks[name]
        ipam_config = net["ipam"]["config"]
        subnets = [c["subnet"] for c in ipam_config]
        assert subnet in subnets

    def test_all_networks_are_bridge(self):
        for name, net in self.networks.items():
            assert net["driver"] == "bridge", f"Network {name} should use bridge driver"


class TestServices:
    """Every required service is present with correct configuration."""

    EXPECTED_SERVICES = {
        "server", "attacker", "firewall", "web", "mail",
        "db", "files", "ldap", "siem",
    }

    @pytest.fixture(autouse=True)
    def load_compose(self):
        with open(COMPOSE_PATH) as f:
            self.compose = yaml.safe_load(f)
        self.services = self.compose["services"]

    def test_all_services_present(self):
        assert self.EXPECTED_SERVICES == set(self.services.keys())

    def test_all_services_have_healthchecks(self):
        for name, svc in self.services.items():
            assert "healthcheck" in svc, f"Service '{name}' missing healthcheck"

    def test_server_mounts_docker_sock(self):
        volumes = self.services["server"]["volumes"]
        sock_mounts = [v for v in volumes if "docker.sock" in v]
        assert len(sock_mounts) == 1

    def test_server_exposes_port_8000(self):
        ports = self.services["server"]["ports"]
        assert any("8000" in str(p) for p in ports)

    def test_attacker_on_external_network(self):
        networks = self.services["attacker"]["networks"]
        assert "external" in networks

    def test_firewall_on_all_networks(self):
        networks = self.services["firewall"]["networks"]
        expected = {"external", "dmz", "internal", "management"}
        assert expected == set(networks)

    def test_firewall_has_net_admin(self):
        cap_add = self.services["firewall"]["cap_add"]
        assert "NET_ADMIN" in cap_add

    def test_web_on_dmz(self):
        networks = self.services["web"]["networks"]
        assert "dmz" in networks

    def test_web_exposes_port_80(self):
        ports = self.services["web"]["ports"]
        assert any("80" in str(p) for p in ports)

    def test_mail_on_dmz(self):
        networks = self.services["mail"]["networks"]
        assert "dmz" in networks

    def test_db_on_internal(self):
        networks = self.services["db"]["networks"]
        assert "internal" in networks

    def test_db_uses_mysql_57(self):
        image = self.services["db"]["image"]
        assert "mysql:5.7" in image

    def test_files_on_internal(self):
        networks = self.services["files"]["networks"]
        assert "internal" in networks

    def test_ldap_on_management(self):
        networks = self.services["ldap"]["networks"]
        assert "management" in networks

    def test_siem_on_management(self):
        networks = self.services["siem"]["networks"]
        assert "management" in networks


class TestDockerfiles:
    """All required Dockerfiles exist and are non-empty."""

    EXPECTED_DOCKERFILES = [
        "attacker.Dockerfile",
        "firewall.Dockerfile",
        "web.Dockerfile",
        "mail.Dockerfile",
        "files.Dockerfile",
        "siem.Dockerfile",
    ]

    @pytest.mark.parametrize("dockerfile", EXPECTED_DOCKERFILES)
    def test_dockerfile_exists(self, dockerfile):
        path = DOCKER_DIR / dockerfile
        assert path.exists(), f"Missing {dockerfile}"

    @pytest.mark.parametrize("dockerfile", EXPECTED_DOCKERFILES)
    def test_dockerfile_has_from(self, dockerfile):
        path = DOCKER_DIR / dockerfile
        content = path.read_text()
        assert content.strip().startswith("FROM"), (
            f"{dockerfile} should start with a FROM instruction"
        )

    def test_server_dockerfile_exists(self):
        path = ROOT / "src" / "open_range" / "server" / "Dockerfile"
        assert path.exists()


class TestSupportFiles:
    """Entrypoint scripts, config files, and init SQL exist."""

    EXPECTED_FILES = [
        "firewall-default.rules",
        "firewall-entrypoint.sh",
        "web-nginx-default.conf",
        "web-entrypoint.sh",
        "mail-entrypoint.sh",
        "files-entrypoint.sh",
        "siem-entrypoint.sh",
        "samba-smb.conf",
        "db-init.sql",
    ]

    @pytest.mark.parametrize("filename", EXPECTED_FILES)
    def test_support_file_exists(self, filename):
        path = DOCKER_DIR / filename
        assert path.exists(), f"Missing support file: {filename}"

    def test_entrypoint_scripts_are_executable_content(self):
        """Entrypoint scripts should start with a shebang."""
        for f in DOCKER_DIR.glob("*-entrypoint.sh"):
            content = f.read_text()
            assert content.startswith("#!/bin/bash"), (
                f"{f.name} should start with #!/bin/bash"
            )

    def test_init_sql_creates_referral_db(self):
        content = (DOCKER_DIR / "db-init.sql").read_text()
        assert "referral_db" in content

    def test_iptables_rules_have_zone_subnets(self):
        content = (DOCKER_DIR / "firewall-default.rules").read_text()
        assert "10.0.0.0/24" in content  # external
        assert "10.0.1.0/24" in content  # dmz
        assert "10.0.2.0/24" in content  # internal
        assert "10.0.3.0/24" in content  # management


class TestNetworkAlignment:
    """docker-compose networks match the tier1 manifest topology."""

    @pytest.fixture(autouse=True)
    def load_both(self):
        with open(COMPOSE_PATH) as f:
            self.compose = yaml.safe_load(f)
        manifest_path = ROOT / "manifests" / "tier1_basic.yaml"
        with open(manifest_path) as f:
            self.manifest = yaml.safe_load(f)

    def test_compose_networks_match_manifest_zones(self):
        compose_nets = set(self.compose["networks"].keys())
        manifest_nets = {n["name"] for n in self.manifest["topology"]["networks"]}
        assert manifest_nets.issubset(compose_nets), (
            f"Manifest networks {manifest_nets} not all in compose {compose_nets}"
        )

    def test_compose_services_match_manifest_hosts(self):
        compose_svcs = set(self.compose["services"].keys()) - {"server"}
        manifest_hosts = {h["name"] for h in self.manifest["topology"]["hosts"]}
        assert manifest_hosts == compose_svcs, (
            f"Manifest hosts {manifest_hosts} != compose services {compose_svcs}"
        )
