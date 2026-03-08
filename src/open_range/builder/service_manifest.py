"""Generate ServiceSpec entries from Docker Compose and topology definitions.

Translates Docker Compose service definitions into subprocess-mode daemon
lifecycle declarations.  The primary consumer is ``SnapshotRenderer`` which
stores the generated list in ``SnapshotSpec.services`` so that
``RangeEnvironment._start_snapshot_services()`` can start the correct daemons
at episode reset time without relying on a hardcoded host-to-service map.

The ``_IMAGE_SERVICE_HINTS`` mapping is intentionally a *hint* table, not a
hard requirement.  Unknown images are skipped with a warning rather than
raising an error — this keeps the system forward-compatible with new services
that haven't been catalogued yet.
"""

from __future__ import annotations

import logging
from typing import Any

from open_range.protocols import ReadinessCheck, ServiceSpec

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Image hint table
# ---------------------------------------------------------------------------
# Maps Docker image name prefixes to a tuple of:
#   (daemon_name, packages, init_commands, start_command, readiness)
#
# Values are *templates* — callers may override port, log_dir, env_vars.
# The start_command may contain ``{log_dir}`` which is interpolated at
# generation time.

_ImageHint = tuple[
    str,               # daemon
    list[str],         # packages
    list[str],         # init_commands
    str,               # start_command
    ReadinessCheck,    # readiness
]

_IMAGE_SERVICE_HINTS: dict[str, _ImageHint] = {
    # ── Web ──────────────────────────────────────────────────────────
    "nginx": (
        "nginx",
        ["nginx"],
        ["mkdir -p /var/log/nginx"],
        "nginx -g 'daemon off;' > {log_dir}/nginx.log 2>&1 &",
        ReadinessCheck(type="tcp", port=80, timeout_s=10),
    ),

    # ── Databases ────────────────────────────────────────────────────
    "mysql": (
        "mysqld",
        ["default-mysql-server", "default-mysql-client"],
        [
            "mkdir -p /var/run/mysqld && chown mysql:mysql /var/run/mysqld 2>/dev/null || true",
            "mkdir -p /var/log/mysql && chown mysql:mysql /var/log/mysql 2>/dev/null || true",
        ],
        "mysqld --user=mysql --log-error={log_dir}/mysql.log &",
        ReadinessCheck(type="command", command="mysqladmin ping --silent 2>/dev/null || mariadb-admin ping --silent 2>/dev/null", timeout_s=30),
    ),
    "mariadb": (
        "mariadbd",
        ["default-mysql-server", "default-mysql-client"],
        [
            "mkdir -p /var/run/mysqld && chown mysql:mysql /var/run/mysqld 2>/dev/null || true",
            "mkdir -p /var/log/mysql && chown mysql:mysql /var/log/mysql 2>/dev/null || true",
        ],
        "mariadbd --user=mysql --log-error={log_dir}/mysql.log &",
        ReadinessCheck(type="command", command="mariadb-admin ping --silent 2>/dev/null || mysqladmin ping --silent 2>/dev/null", timeout_s=30),
    ),
    "postgres": (
        "postgres",
        ["postgresql"],
        [
            "mkdir -p /var/run/postgresql && chown postgres:postgres /var/run/postgresql 2>/dev/null || true",
        ],
        "su - postgres -c 'pg_ctl start -D /var/lib/postgresql/data -l {log_dir}/postgres.log' &",
        ReadinessCheck(type="tcp", port=5432, timeout_s=30),
    ),

    # ── Directory ────────────────────────────────────────────────────
    "openldap": (
        "slapd",
        ["slapd", "ldap-utils"],
        ["mkdir -p /var/run/slapd"],
        "slapd -h 'ldap:/// ldapi:///' -u openldap -g openldap > {log_dir}/slapd.log 2>&1 &",
        ReadinessCheck(type="command", command="ldapsearch -x -H ldap://localhost -b '' -s base namingContexts >/dev/null 2>&1", timeout_s=10),
    ),
    "osixia/openldap": (
        "slapd",
        ["slapd", "ldap-utils"],
        ["mkdir -p /var/run/slapd"],
        "slapd -h 'ldap:/// ldapi:///' -u openldap -g openldap > {log_dir}/slapd.log 2>&1 &",
        ReadinessCheck(type="command", command="ldapsearch -x -H ldap://localhost -b '' -s base namingContexts >/dev/null 2>&1", timeout_s=10),
    ),

    # ── Logging ──────────────────────────────────────────────────────
    "rsyslog": (
        "rsyslogd",
        ["rsyslog"],
        [],
        "rsyslogd -n > {log_dir}/rsyslog.log 2>&1 &",
        ReadinessCheck(type="command", command="pgrep -x rsyslogd", timeout_s=5),
    ),

    # ── File sharing ─────────────────────────────────────────────────
    "samba": (
        "smbd",
        ["samba"],
        ["mkdir -p /var/lib/samba/private"],
        "smbd --foreground --no-process-group > {log_dir}/smbd.log 2>&1 &",
        ReadinessCheck(type="tcp", port=445, timeout_s=10),
    ),

    # ── Mail ─────────────────────────────────────────────────────────
    "postfix": (
        "master",
        ["postfix"],
        [],
        "postfix start > {log_dir}/postfix.log 2>&1 || true",
        ReadinessCheck(type="tcp", port=25, timeout_s=10),
    ),

    # ── Cache ────────────────────────────────────────────────────────
    "redis": (
        "redis-server",
        ["redis-server"],
        [],
        "redis-server --daemonize yes --logfile {log_dir}/redis.log",
        ReadinessCheck(type="tcp", port=6379, timeout_s=10),
    ),

    # ── CI/CD ────────────────────────────────────────────────────────
    "jenkins": (
        "java",
        ["default-jdk"],
        [],
        "java -jar /usr/share/jenkins/jenkins.war --httpPort=8080 > {log_dir}/jenkins.log 2>&1 &",
        ReadinessCheck(type="http", url="http://localhost:8080/login", timeout_s=60),
    ),

    # ── Monitoring ───────────────────────────────────────────────────
    "prometheus": (
        "prometheus",
        ["prometheus"],
        [],
        "prometheus --config.file=/etc/prometheus/prometheus.yml --web.listen-address=:9090 > {log_dir}/prometheus.log 2>&1 &",
        ReadinessCheck(type="http", url="http://localhost:9090/-/ready", timeout_s=15),
    ),
    "grafana": (
        "grafana-server",
        ["grafana"],
        [],
        "grafana-server --homepath=/usr/share/grafana > {log_dir}/grafana.log 2>&1 &",
        ReadinessCheck(type="http", url="http://localhost:3000/api/health", timeout_s=15),
    ),

    # ── Remote access ────────────────────────────────────────────────
    "openssh": (
        "sshd",
        ["openssh-server"],
        ["mkdir -p /var/run/sshd"],
        "/usr/sbin/sshd -E {log_dir}/sshd.log",
        ReadinessCheck(type="tcp", port=22, timeout_s=5),
    ),
    "linuxserver/openssh-server": (
        "sshd",
        ["openssh-server"],
        ["mkdir -p /var/run/sshd"],
        "/usr/sbin/sshd -E {log_dir}/sshd.log",
        ReadinessCheck(type="tcp", port=22, timeout_s=5),
    ),
}

# ---------------------------------------------------------------------------
# Topology host-name hints (fallback when compose services are absent)
# ---------------------------------------------------------------------------
# Maps logical host names commonly used in manifests to the same hint keys.

_HOST_NAME_HINTS: dict[str, str] = {
    "web": "nginx",
    "db": "mysql",
    "ldap": "openldap",
    "siem": "rsyslog",
    "files": "samba",
    "mail": "postfix",
    "firewall": "rsyslog",
    "cache": "redis",
    "redis": "redis",
    "ci_cd": "jenkins",
    "ci": "jenkins",
    "monitoring": "prometheus",
    "ssh": "openssh",
}

# Default log directory used when none is specified.
_DEFAULT_LOG_DIR = "/var/log/siem"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def generate_service_specs(
    compose: dict[str, Any],
    topology: dict[str, Any],
) -> list[ServiceSpec]:
    """Generate ServiceSpec entries from compose and topology.

    Translates Docker Compose service definitions into subprocess-mode
    daemon lifecycle declarations.

    The function examines ``compose["services"]`` first.  For each service
    whose image matches a known hint, a ``ServiceSpec`` is produced.  If
    the compose dict is empty or missing, the function falls back to the
    topology host list using ``_HOST_NAME_HINTS``.

    Services that cannot be mapped (e.g. custom images with no hint) are
    skipped with a debug-level log message.

    Parameters
    ----------
    compose:
        Parsed docker-compose dict (may be empty).
    topology:
        Parsed topology dict from the manifest / snapshot.

    Returns
    -------
    list[ServiceSpec]
        One entry per recognised service.  Order follows the compose
        services dict (or the topology hosts list as fallback).
    """
    specs: list[ServiceSpec] = []
    seen_identities: set[tuple[str, str]] = set()

    services = compose.get("services", {}) if compose else {}

    if services:
        specs = _from_compose(services, seen_identities)
    else:
        specs = _from_topology(topology, seen_identities)

    return specs


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _match_image_hint(image: str) -> _ImageHint | None:
    """Match a Docker image string to the closest hint entry.

    Strips tags (``mysql:8.0`` -> ``mysql``), handles namespaced images
    (``osixia/openldap:1.5`` -> ``osixia/openldap``), and falls back to
    substring matching on the image basename.
    """
    if not image:
        return None

    # Remove tag
    base = image.split(":")[0].strip()

    # Exact match (with or without namespace)
    if base in _IMAGE_SERVICE_HINTS:
        return _IMAGE_SERVICE_HINTS[base]

    # Try basename only (e.g. ``bitnami/redis`` -> ``redis``)
    basename = base.rsplit("/", 1)[-1]
    if basename in _IMAGE_SERVICE_HINTS:
        return _IMAGE_SERVICE_HINTS[basename]

    # Substring match as last resort (e.g. ``mysql/mysql-server`` -> ``mysql``)
    for key, hint in _IMAGE_SERVICE_HINTS.items():
        if "/" not in key and key in basename:
            return hint

    return None


def _env_from_compose_service(svc_def: dict[str, Any]) -> dict[str, str]:
    """Extract environment variables from a compose service definition.

    Handles both the ``list`` form (``- KEY=VALUE``) and the ``dict`` form.
    """
    raw = svc_def.get("environment", {})
    if isinstance(raw, list):
        env: dict[str, str] = {}
        for entry in raw:
            if "=" in entry:
                k, v = entry.split("=", 1)
                env[k] = v
        return env
    if isinstance(raw, dict):
        return {str(k): str(v) for k, v in raw.items()}
    return {}


def _build_service_spec(
    host: str,
    hint: _ImageHint,
    log_dir: str = _DEFAULT_LOG_DIR,
    env_vars: dict[str, str] | None = None,
) -> ServiceSpec:
    """Build a ServiceSpec from a matched hint tuple."""
    daemon, packages, init_commands, start_command, readiness = hint
    return ServiceSpec(
        host=host,
        daemon=daemon,
        packages=list(packages),
        init_commands=list(init_commands),
        start_command=start_command.format(log_dir=log_dir),
        readiness=readiness.model_copy(),
        log_dir=log_dir,
        env_vars=env_vars or {},
    )


def _from_compose(
    services: dict[str, Any],
    seen_identities: set[tuple[str, str]],
) -> list[ServiceSpec]:
    """Generate specs from the compose services section."""
    specs: list[ServiceSpec] = []

    for svc_name, svc_def in services.items():
        if not isinstance(svc_def, dict):
            continue

        image = svc_def.get("image", "")
        hint = _match_image_hint(image)

        # If no image, try matching the service name itself
        if hint is None and svc_name in _HOST_NAME_HINTS:
            fallback_key = _HOST_NAME_HINTS[svc_name]
            hint = _IMAGE_SERVICE_HINTS.get(fallback_key)

        if hint is None:
            logger.debug(
                "No service hint for compose service %r (image=%r) — skipping",
                svc_name,
                image,
            )
            continue

        daemon = hint[0]
        identity = (svc_name, daemon)
        if identity in seen_identities:
            continue
        seen_identities.add(identity)

        env_vars = _env_from_compose_service(svc_def)
        spec = _build_service_spec(
            host=svc_name,
            hint=hint,
            env_vars=env_vars,
        )
        specs.append(spec)

    return specs


def _from_topology(
    topology: dict[str, Any],
    seen_identities: set[tuple[str, str]],
) -> list[ServiceSpec]:
    """Generate specs from the topology hosts list (fallback path)."""
    specs: list[ServiceSpec] = []
    hosts = topology.get("hosts", [])

    for host_entry in hosts:
        host_name = host_entry if isinstance(host_entry, str) else host_entry.get("name", "")
        if not host_name:
            continue

        hint_key = _HOST_NAME_HINTS.get(host_name)
        if hint_key is None:
            continue

        hint = _IMAGE_SERVICE_HINTS.get(hint_key)
        if hint is None:
            continue

        daemon = hint[0]
        identity = (host_name, daemon)
        if identity in seen_identities:
            continue
        seen_identities.add(identity)

        spec = _build_service_spec(host=host_name, hint=hint)
        specs.append(spec)

    return specs
