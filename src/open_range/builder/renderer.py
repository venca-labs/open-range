"""Render SnapshotSpec into Docker artifacts via Jinja2 templates.

Takes a validated SnapshotSpec and produces the concrete files needed
to boot a range: docker-compose.yml, Dockerfiles, nginx.conf, init.sql,
and iptables.rules.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import jinja2

from open_range.protocols import SnapshotSpec

logger = logging.getLogger(__name__)

# Template directory lives alongside this module
_TEMPLATE_DIR = Path(__file__).parent / "templates"

# Map of template filename -> output filename
_TEMPLATE_MAP: dict[str, str] = {
    "docker-compose.yml.j2": "docker-compose.yml",
    "Dockerfile.web.j2": "Dockerfile.web",
    "Dockerfile.db.j2": "Dockerfile.db",
    "nginx.conf.j2": "nginx.conf",
    "init.sql.j2": "init.sql",
    "iptables.rules.j2": "iptables.rules",
}


class SnapshotRenderer:
    """Render Jinja2 templates from a SnapshotSpec to an output directory."""

    def __init__(self, template_dir: Path | None = None) -> None:
        self.template_dir = template_dir or _TEMPLATE_DIR
        self.env = jinja2.Environment(
            loader=jinja2.FileSystemLoader(str(self.template_dir)),
            keep_trailing_newline=True,
            undefined=jinja2.Undefined,
        )

    def render(self, spec: SnapshotSpec, output_dir: Path) -> Path:
        """Render all templates and write artifacts to *output_dir*.

        Returns the output directory path.
        """
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        context = _build_context(spec)

        for template_name, output_name in _TEMPLATE_MAP.items():
            template = self.env.get_template(template_name)
            rendered = template.render(**context)
            dest = output_dir / output_name
            dest.write_text(rendered)
            logger.info("Rendered %s -> %s", template_name, dest)

        return output_dir


def _build_context(spec: SnapshotSpec) -> dict[str, Any]:
    """Build the Jinja2 template context from a SnapshotSpec.

    Flattens and adapts the SnapshotSpec fields into the variable names
    expected by the templates.
    """
    topology = spec.topology
    hosts_raw = topology.get("hosts", [])
    zones = topology.get("zones", {})
    users = topology.get("users", [])

    # Build host objects with name, zone, networks, depends_on
    hosts = _build_hosts(hosts_raw, zones)
    host_names = [h["name"] for h in hosts]

    # Build network objects from zones
    networks = _build_networks(zones)

    # Zone -> CIDR mapping for iptables template
    zone_cidrs = _build_zone_cidrs(zones)

    # Firewall rules (from topology if present, else empty)
    firewall_rules = topology.get("firewall_rules", [])

    # Flags as dicts for templates
    flags = [f.model_dump() for f in spec.flags]

    # Detect vuln types for nginx conditional blocks
    vuln_types = {v.type for v in spec.truth_graph.vulns}
    vuln_injection_points = {v.injection_point for v in spec.truth_graph.vulns}

    # App files placeholder (templates reference app_files but we provide
    # an empty dict -- actual PHP files would be generated separately)
    app_files: dict[str, str] = {}
    if spec.files:
        app_files = spec.files

    # Determine which nginx endpoint blocks to enable.
    # Templates use `{% if X is defined %}` so we only include these keys
    # when they should be True (omitting = undefined = block not rendered).
    has_search = (
        any("search" in ip or "q=" in ip for ip in vuln_injection_points)
        or "sqli" in vuln_types
    )
    has_download = (
        any("download" in ip or "file=" in ip for ip in vuln_injection_points)
        or "path_traversal" in vuln_types
    )

    context: dict[str, Any] = {
        # docker-compose.yml.j2
        "snapshot_id": topology.get("snapshot_id", "generated"),
        "networks": networks,
        "hosts": hosts,
        "host_names": host_names,
        "db_host": "db",
        "db_user": _find_db_user(users),
        "db_pass": _find_db_pass(users),
        "mysql_root_password": _find_mysql_root_pass(users),
        "domain": topology.get("domain", "acmecorp.local"),
        "org_name": topology.get("org_name", "AcmeCorp"),
        "ldap_admin_pass": "LdapAdm1n!",
        # Dockerfile.web.j2
        "users": users,
        "app_files": app_files,
        "flags": flags,
        # nginx.conf.j2
        "server_name": topology.get("domain", "web.corp.local"),
        # iptables.rules.j2
        "firewall_rules": firewall_rules,
        "zone_cidrs": zone_cidrs,
    }

    # Only include endpoint keys when enabled (templates use `is defined`)
    if has_search:
        context["search_endpoint"] = True
    if has_download:
        context["download_endpoint"] = True

    return context


def _build_hosts(
    hosts_raw: list[str] | list[dict[str, Any]],
    zones: dict[str, list[str]],
) -> list[dict[str, Any]]:
    """Convert host list (strings or dicts) into template-ready dicts."""
    # Build reverse map: host_name -> zone
    host_to_zone: dict[str, str] = {}
    for zone_name, zone_hosts in zones.items():
        for h in zone_hosts:
            host_to_zone[h] = zone_name

    hosts = []
    for h in hosts_raw:
        if isinstance(h, dict):
            name = h["name"]
            zone = h.get("zone", host_to_zone.get(name, "default"))
            networks = h.get("networks", [zone])
            depends_on = h.get("depends_on", [])
            hosts.append(
                {
                    "name": name,
                    "zone": zone,
                    "networks": networks,
                    "depends_on": depends_on,
                }
            )
        else:
            # Simple string host name
            zone = host_to_zone.get(h, "default")
            hosts.append(
                {
                    "name": h,
                    "zone": zone,
                    "networks": [zone],
                    "depends_on": [],
                }
            )
    return hosts


def _build_networks(zones: dict[str, list[str]]) -> list[dict[str, str]]:
    """Build network objects from zone definitions.

    Uses conventional CIDRs: dmz=10.0.1.0/24, internal=10.0.2.0/24,
    management=10.0.3.0/24. External gets no CIDR (bridge default).
    """
    default_cidrs = {
        "dmz": "10.0.1.0/24",
        "internal": "10.0.2.0/24",
        "management": "10.0.3.0/24",
    }
    networks = []
    for zone_name in zones:
        net: dict[str, str] = {"name": zone_name}
        if zone_name in default_cidrs:
            net["cidr"] = default_cidrs[zone_name]
        networks.append(net)
    return networks


def _build_zone_cidrs(zones: dict[str, list[str]]) -> dict[str, str]:
    """Map zone names to CIDR blocks for iptables rules."""
    default_cidrs = {
        "external": "0.0.0.0/0",
        "dmz": "10.0.1.0/24",
        "internal": "10.0.2.0/24",
        "management": "10.0.3.0/24",
    }
    return {z: default_cidrs.get(z, "0.0.0.0/0") for z in zones}


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


def _find_mysql_root_pass(users: list[dict[str, Any]]) -> str:
    """Find MySQL root password from admin user or use default."""
    for u in users:
        if u.get("username") == "admin" and "db" in u.get("hosts", []):
            return u.get("password", "r00tP@ss!")
    return "r00tP@ss!"
