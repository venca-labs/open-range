"""Render SnapshotSpec into a Helm chart targeting Kind (Kubernetes-in-Docker).

Takes a validated SnapshotSpec and produces:
  - A Helm chart (openrange/) with generated values.yaml
  - A Kind cluster config (kind-config.yaml)

Zone isolation is achieved via namespace-per-zone with NetworkPolicies.
Payload files (PHP code, SQL seeds, configs) are injected as ConfigMaps.
"""

from __future__ import annotations

import logging
import re
import shutil
from copy import deepcopy
from pathlib import Path
from typing import Any

import yaml

from open_range.protocols import SnapshotSpec

logger = logging.getLogger(__name__)

# Static Helm chart shipped alongside this module
_CHART_DIR = Path(__file__).parent / "chart"

# Default zone CIDR mappings (used for documentation / NetworkPolicy context)
_ZONE_CIDRS: dict[str, str] = {
    "external": "10.0.0.0/24",
    "dmz": "10.0.1.0/24",
    "internal": "10.0.2.0/24",
    "management": "10.0.3.0/24",
}

# Default container images per service role
_SERVICE_IMAGES: dict[str, str | None] = {
    "web": "php:8.1-apache",
    "db": "mysql:8.0",
    "files": "dperson/samba:latest",
    "mail": "mailhog/mailhog:latest",
    "ldap": "osixia/openldap:1.5.0",
    "siem": "balabit/syslog-ng:latest",
    "attacker": "kalilinux/kali-rolling",
    "firewall": None,  # handled by NetworkPolicies
}

# Default ports per service role
_SERVICE_PORTS: dict[str, list[dict[str, Any]]] = {
    "web": [{"name": "http", "port": 80}, {"name": "https", "port": 443}],
    "db": [{"name": "mysql", "port": 3306}],
    "files": [{"name": "smb", "port": 445}],
    "mail": [{"name": "smtp", "port": 25}, {"name": "imap", "port": 143}],
    "ldap": [{"name": "ldap", "port": 389}, {"name": "ldaps", "port": 636}],
    "siem": [{"name": "syslog", "port": 514}],
    "attacker": [],
}


def _sanitize_key(path: str) -> str:
    """Convert a file path to a ConfigMap-safe key (RFC 1123 subdomain)."""
    return re.sub(r"[^a-zA-Z0-9._-]", "-", path.strip("/"))


class KindRenderer:
    """Render a SnapshotSpec into a Helm chart and Kind cluster config.

    The chart uses namespace-per-zone isolation with NetworkPolicies
    replacing iptables rules.  Payload files are mounted via ConfigMaps.
    """

    def __init__(self, chart_dir: Path | None = None) -> None:
        self.chart_dir = chart_dir or _CHART_DIR

    def render(self, spec: SnapshotSpec, output_dir: Path) -> Path:
        """Render the Helm chart and Kind config to *output_dir*.

        Returns the output directory path.
        """
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        # 1. Kind cluster config
        kind_config = self._build_kind_config(spec)
        (output_dir / "kind-config.yaml").write_text(
            yaml.dump(kind_config, default_flow_style=False, sort_keys=False),
            encoding="utf-8",
        )

        # 2. Copy static chart structure
        chart_out = output_dir / "openrange"
        if chart_out.exists():
            shutil.rmtree(chart_out)
        shutil.copytree(self.chart_dir, chart_out)

        # 3. Generate values.yaml from SnapshotSpec
        values = self._build_values(spec)
        (chart_out / "values.yaml").write_text(
            yaml.dump(values, default_flow_style=False, sort_keys=False),
            encoding="utf-8",
        )

        logger.info(
            "KindRenderer: rendered chart to %s (%d services, %d zones)",
            chart_out,
            len(values.get("services", {})),
            len(values.get("zones", {})),
        )
        return output_dir

    # ------------------------------------------------------------------
    # Values generation
    # ------------------------------------------------------------------

    def _build_values(self, spec: SnapshotSpec) -> dict[str, Any]:
        """Convert a SnapshotSpec into the Helm values dict."""
        topology = spec.topology
        zones = topology.get("zones", {})
        users = topology.get("users", [])
        hosts_raw = topology.get("hosts", [])

        # Zone config
        zone_config: dict[str, dict[str, Any]] = {}
        for zone_name, zone_hosts in zones.items():
            zone_config[zone_name] = {
                "hosts": list(zone_hosts) if isinstance(zone_hosts, list) else [],
                "cidr": _ZONE_CIDRS.get(zone_name, "10.0.0.0/24"),
            }

        # Host → zone reverse map
        host_to_zone: dict[str, str] = {}
        for zone_name, zone_hosts in zones.items():
            if isinstance(zone_hosts, list):
                for h in zone_hosts:
                    host_to_zone[h] = zone_name

        # Service configs
        services: dict[str, dict[str, Any]] = {}
        for h in hosts_raw:
            name = h["name"] if isinstance(h, dict) else str(h)
            image = _SERVICE_IMAGES.get(name)
            if image is None:
                continue
            zone = host_to_zone.get(name, "default")

            svc: dict[str, Any] = {
                "enabled": True,
                "image": image,
                "zone": zone,
                "ports": deepcopy(_SERVICE_PORTS.get(name, [])),
                "env": self._service_env(name, topology),
            }

            cmd = self._service_command(name)
            if cmd:
                svc["command"] = cmd

            payloads = self._service_payloads(name, spec)
            if payloads:
                svc["payloads"] = payloads

            services[name] = svc

        # Firewall rules
        fw_rules: list[dict[str, Any]] = []
        for rule in topology.get("firewall_rules", []):
            if isinstance(rule, dict):
                fw_rules.append({
                    "action": rule.get("action", "allow"),
                    "fromZone": rule.get("from_zone", ""),
                    "toZone": rule.get("to_zone", ""),
                    "ports": rule.get("ports", []),
                })

        return {
            "global": {
                "namePrefix": "openrange",
                "domain": topology.get("domain", "acmecorp.local"),
                "orgName": topology.get("org_name", "AcmeCorp"),
                "snapshotId": topology.get("snapshot_id", "generated"),
            },
            "zones": zone_config,
            "services": services,
            "users": deepcopy(users) if isinstance(users, list) else [],
            "flags": [f.model_dump() for f in spec.flags],
            "firewallRules": fw_rules,
        }

    # ------------------------------------------------------------------
    # Per-service helpers
    # ------------------------------------------------------------------

    def _service_env(self, name: str, topology: dict[str, Any]) -> dict[str, str]:
        """Build environment variables for a service."""
        domain = topology.get("domain", "acmecorp.local")
        org_name = topology.get("org_name", "AcmeCorp")
        prefix = "openrange"
        users = topology.get("users", [])
        users = users if isinstance(users, list) else []

        env: dict[str, str] = {}
        if name == "web":
            env.update({
                "DB_HOST": "db",
                "DB_USER": _find_db_user(users),
                "DB_PASS": _find_db_pass(users),
                "DB_NAME": "referral_db",
                "LDAP_HOST": "ldap",
                "LDAP_BASE_DN": ",".join(f"dc={p}" for p in domain.split(".")),
            })
        elif name == "db":
            env.update({
                "MYSQL_ROOT_PASSWORD": str(
                    topology.get("mysql_root_password", "r00tP@ss!")
                ),
                "MYSQL_DATABASE": "referral_db",
                "MYSQL_USER": _find_db_user(users),
                "MYSQL_PASSWORD": _find_db_pass(users),
            })
        elif name == "ldap":
            env.update({
                "LDAP_ORGANISATION": org_name,
                "LDAP_DOMAIN": domain,
                "LDAP_ADMIN_PASSWORD": "LdapAdm1n!",
                "HOSTNAME": "ldap",
                # K8s auto-injects LDAP_PORT from the Service named "ldap",
                # which collides with osixia/openldap's own LDAP_PORT env var.
                # Override to the correct value.
                "LDAP_PORT": "389",
            })
        elif name == "attacker":
            env["TERM"] = "xterm-256color"
        return env

    @staticmethod
    def _service_command(name: str) -> list[str] | None:
        """Return a startup command override, or ``None``."""
        if name == "web":
            return [
                "bash", "-c",
                (
                    "docker-php-ext-install mysqli pdo_mysql > /dev/null 2>&1; "
                    "apache2-foreground"
                ),
            ]
        if name == "attacker":
            return [
                "bash", "-c",
                (
                    "apt-get update -qq > /dev/null 2>&1; "
                    "apt-get install -y -qq nmap curl wget smbclient sqlmap "
                    "hydra nikto netcat-traditional ssh dnsutils "
                    "mysql-client python3 > /dev/null 2>&1; "
                    "sleep infinity"
                ),
            ]
        return None

    @staticmethod
    def _service_payloads(
        name: str,
        spec: SnapshotSpec,
    ) -> list[dict[str, str]]:
        """Extract payload file mounts for a given container.

        Deduplicates by mountPath — last writer wins for content, but
        each mountPath appears only once (K8s rejects duplicate volumeMounts).
        """
        by_mount: dict[str, dict[str, str]] = {}

        # Inject base DB schema so LLM-generated SQL can reference tables
        if name == "db":
            mp = "/docker-entrypoint-initdb.d/00-base-schema.sql"
            by_mount[mp] = {
                "key": "00-base-schema.sql",
                "mountPath": mp,
                "content": _BASE_DB_SCHEMA,
            }

        for file_key, content in spec.files.items():
            if ":" not in file_key:
                continue
            container, path = file_key.split(":", 1)
            if container != name:
                continue

            # db:sql → shell wrapper that runs LLM SQL with --force
            # so MySQL continues past individual statement errors
            # (LLM may generate slightly wrong column names).
            if name == "db" and path == "sql":
                mount_path = "/docker-entrypoint-initdb.d/99-openrange-init.sh"
                content = _wrap_sql_in_shell(content)
            else:
                mount_path = path if path.startswith("/") else f"/{path}"

            by_mount[mount_path] = {
                "key": _sanitize_key(path),
                "mountPath": mount_path,
                "content": content,
            }

        # Flag files for this host
        for flag in spec.flags:
            if (
                flag.host == name
                and "/" in flag.path
                and not flag.path.startswith("db:")
            ):
                by_mount.setdefault(flag.path, {
                    "key": _sanitize_key(flag.path),
                    "mountPath": flag.path,
                    "content": f"{flag.value}\n",
                })

        return list(by_mount.values())

    # ------------------------------------------------------------------
    # Kind cluster config
    # ------------------------------------------------------------------

    @staticmethod
    def _build_kind_config(spec: SnapshotSpec) -> dict[str, Any]:
        """Generate a Kind cluster config with port mappings for DMZ access."""
        zones = spec.topology.get("zones", {})
        dmz_hosts = zones.get("dmz", [])
        if not isinstance(dmz_hosts, list):
            dmz_hosts = []

        # Map DMZ service ports to host ports starting at 30080
        port_mappings: list[dict[str, Any]] = []
        host_port = 30080
        for host_name in dmz_hosts:
            for port_info in _SERVICE_PORTS.get(host_name, []):
                port_mappings.append({
                    "containerPort": host_port,
                    "hostPort": host_port,
                    "protocol": "TCP",
                })
                host_port += 1

        if not port_mappings:
            port_mappings = [
                {"containerPort": 30080, "hostPort": 30080, "protocol": "TCP"},
            ]

        return {
            "apiVersion": "kind.x-k8s.io/v1alpha4",
            "kind": "Cluster",
            "name": "openrange",
            "networking": {
                "disableDefaultCNI": True,
                "podSubnet": "192.168.0.0/16",
            },
            "nodes": [
                {
                    "role": "control-plane",
                    "extraPortMappings": port_mappings,
                },
            ],
        }


# ---------------------------------------------------------------------------
# Helpers (ported from old renderer, used by _build_values)
# ---------------------------------------------------------------------------


def _find_db_user(users: list[dict[str, Any]]) -> str:
    """Find the database user from topology users, default to app_user."""
    for u in users:
        hosts = u.get("hosts", [])
        if "db" in hosts and "admins" not in u.get("groups", []):
            return u.get("username", "app_user")
    return "app_user"


def _find_db_pass(users: list[dict[str, Any]]) -> str:
    """Find the database user password."""
    for u in users:
        hosts = u.get("hosts", [])
        if "db" in hosts and "admins" not in u.get("groups", []):
            return u.get("password", "AppUs3r!2024")
    return "AppUs3r!2024"


# Base MySQL schema — runs as 00-base-schema.sql so LLM-generated SQL
# (99-openrange-init.sql) can INSERT into these tables safely.
_BASE_DB_SCHEMA = """\
CREATE DATABASE IF NOT EXISTS referral_db;
CREATE DATABASE IF NOT EXISTS flags;
USE referral_db;

CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(64) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    email VARCHAR(128),
    full_name VARCHAR(128),
    role VARCHAR(64),
    department VARCHAR(64),
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS patients (
    id INT AUTO_INCREMENT PRIMARY KEY,
    first_name VARCHAR(64),
    last_name VARCHAR(64),
    dob DATE,
    phone VARCHAR(20),
    email VARCHAR(128),
    insurance_id VARCHAR(64),
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS patient_referrals (
    id INT AUTO_INCREMENT PRIMARY KEY,
    patient_id INT,
    referring_physician VARCHAR(128),
    specialist VARCHAR(128),
    reason TEXT,
    status VARCHAR(32) DEFAULT 'pending',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (patient_id) REFERENCES patients(id)
);

CREATE TABLE IF NOT EXISTS billing (
    id INT AUTO_INCREMENT PRIMARY KEY,
    patient_id INT,
    amount DECIMAL(10,2),
    insurance_claim VARCHAR(64),
    status VARCHAR(32) DEFAULT 'pending',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (patient_id) REFERENCES patients(id)
);

CREATE TABLE IF NOT EXISTS sessions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    session_token VARCHAR(128),
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME
);

CREATE TABLE IF NOT EXISTS access_log (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    action VARCHAR(64),
    resource VARCHAR(128),
    ip_address VARCHAR(45),
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

USE flags;
CREATE TABLE IF NOT EXISTS secrets (
    id INT AUTO_INCREMENT PRIMARY KEY,
    flag_name VARCHAR(64),
    flag VARCHAR(128),
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

USE referral_db;
"""


def _wrap_sql_in_shell(sql: str) -> str:
    """Wrap LLM-generated SQL in a shell script that tolerates errors.

    MySQL's docker-entrypoint runs ``.sql`` files via ``mysql < file``
    which aborts on the first error.  By using a ``.sh`` wrapper with
    ``mysql --force``, individual bad statements (wrong column names,
    duplicate keys, etc.) are logged but don't crash the pod.

    NOTE: MySQL entrypoint ``source``s ``.sh`` files (same process),
    so we must NOT use ``exit`` — that would kill the entrypoint.
    We just let the script return naturally.
    """
    return (
        'echo "[openrange] Running LLM-generated seed SQL (--force) ..."\n'
        "mysql --force -u root -p\"$MYSQL_ROOT_PASSWORD\" <<'OPENRANGE_SQL_EOF'\n"
        f"{sql}\n"
        "OPENRANGE_SQL_EOF\n"
        'echo "[openrange] Seed SQL complete (errors above are non-fatal)"\n'
    )
