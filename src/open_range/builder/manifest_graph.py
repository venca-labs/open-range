"""Manifest-to-topology compilation helpers for root snapshot hydration.

These helpers turn a manifest's declared company world into the canonical
topology fields the mutator, validators, and runtime expect to reason about.
They intentionally keep "real login users" separate from trust-only narrative
principals so the trust graph can be compiled without silently creating extra
accounts in rendered services.
"""

from __future__ import annotations

from copy import deepcopy
import re
from typing import Any


def build_host_catalog(manifest: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Return the manifest-defined host catalog keyed by host name."""
    catalog: dict[str, dict[str, Any]] = {}
    for raw in manifest.get("topology", {}).get("hosts", []):
        if not isinstance(raw, dict):
            continue
        name = str(raw.get("name", "")).strip()
        if not name:
            continue
        catalog[name] = {
            "zone": str(raw.get("zone", "")),
            "services": deepcopy(raw.get("services", [])),
            "connects_to": deepcopy(raw.get("connects_to", [])),
            "purpose": str(raw.get("purpose", "")),
            "hostname": str(raw.get("hostname", "")),
            "os": str(raw.get("os", "")),
            "exposure": deepcopy(raw.get("exposure", {})),
        }
    return catalog


def build_principal_catalog(
    manifest: dict[str, Any],
    existing: dict[str, Any] | None = None,
) -> tuple[dict[str, dict[str, Any]], list[str]]:
    """Return a canonical principal catalog plus normalized trust-only names."""
    catalog: dict[str, dict[str, Any]] = {}
    trust_only: set[str] = set()

    if isinstance(existing, dict):
        for name, raw in existing.items():
            principal = str(name).strip()
            if not principal or not isinstance(raw, dict):
                continue
            catalog[principal] = deepcopy(raw)

    for raw in manifest.get("users", []):
        if not isinstance(raw, dict):
            continue
        username = str(raw.get("username", "")).strip()
        if not username:
            continue
        principal = catalog.setdefault(username, {})
        principal.update(
            {
                "username": username,
                "kind": "user",
                "is_login_account": True,
                "hosts": deepcopy(raw.get("hosts", [])),
                "department": str(raw.get("department", "")),
                "role": str(raw.get("role", "")),
                "email": str(raw.get("email", "")),
                "full_name": str(raw.get("full_name", "")),
            }
        )

    for raw in manifest.get("trust_relationships", []):
        if not isinstance(raw, dict):
            continue
        source = str(raw.get("source") or raw.get("from") or "").strip()
        target = str(raw.get("target") or raw.get("to") or "").strip()
        for principal_name in (source, target):
            if not principal_name:
                continue
            principal = catalog.setdefault(principal_name, {})
            if not principal.get("is_login_account", False):
                trust_only.add(principal_name)
            principal.setdefault("username", principal_name)
            principal.setdefault("kind", "trust_principal")
            principal.setdefault("is_login_account", False)
            principal.setdefault("hosts", [])
            principal.setdefault("department", "")
            principal.setdefault("role", "")
            principal.setdefault("email", "")
            principal.setdefault("full_name", "")

    return catalog, sorted(trust_only)


def compile_manifest_topology(
    manifest: dict[str, Any],
    topology: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Compile manifest state into graph-friendly topology fields.

    Existing topology fields are preserved where possible so builder-generated
    details such as passwords or payload-specific knobs survive root hydration.
    """
    compiled = deepcopy(topology) if isinstance(topology, dict) else {}
    company = manifest.get("company", {}) if isinstance(manifest.get("company"), dict) else {}

    compiled.setdefault("tier", int(manifest.get("tier", compiled.get("tier", 1)) or 1))
    compiled.setdefault("domain", company.get("domain", "acmecorp.local"))
    compiled.setdefault("org_name", company.get("name", "AcmeCorp"))
    compiled.setdefault("manifest_name", manifest.get("name", ""))
    compiled.setdefault("difficulty", deepcopy(manifest.get("difficulty", {})))
    compiled.setdefault(
        "networks",
        deepcopy(manifest.get("topology", {}).get("networks", [])),
    )
    compiled.setdefault(
        "firewall_rules",
        deepcopy(manifest.get("topology", {}).get("firewall_rules", [])),
    )

    host_catalog = build_host_catalog(manifest)
    compiled["host_catalog"] = host_catalog
    compiled["hosts"] = _merge_hosts(compiled.get("hosts"), host_catalog)
    compiled["zones"] = _merge_zones(compiled.get("zones"), host_catalog)
    compiled["users"] = _merge_users(compiled.get("users"), manifest)
    compiled["host_details"] = _merge_host_details(compiled.get("host_details"), host_catalog)
    compiled["dependency_edges"] = _merge_dependency_edges(
        compiled.get("dependency_edges"),
        host_catalog,
    )

    principal_catalog, trust_only = build_principal_catalog(
        manifest,
        existing=compiled.get("principal_catalog")
        if isinstance(compiled.get("principal_catalog"), dict)
        else None,
    )
    compiled["principal_catalog"] = principal_catalog
    compiled["trust_edges"] = _merge_trust_edges(compiled.get("trust_edges"), manifest)
    compiled["manifest_normalization"] = {
        "trust_only_principals": trust_only,
        "notes": [
            (
                "Normalized trust principals not present in manifest users into "
                "principal_catalog only"
            )
        ]
        if trust_only
        else [],
    }
    return compiled


def runtime_contract_from_topology(
    topology: dict[str, Any],
    *,
    manifest: dict[str, Any] | None = None,
) -> dict[str, str]:
    """Derive the template/runtime contract used by template mutations.

    ``builder.py`` now expects a canonical runtime contract after manifest
    normalization. Keep any existing explicit values, then fill the rest from
    the normalized topology and manifest infrastructure hints.
    """

    contract = (
        deepcopy(topology.get("runtime_contract"))
        if isinstance(topology.get("runtime_contract"), dict)
        else {}
    )
    manifest_obj = manifest if isinstance(manifest, dict) else {}
    infra = (
        manifest_obj.get("infrastructure", {})
        if isinstance(manifest_obj.get("infrastructure"), dict)
        else {}
    )

    domain = str(
        topology.get("domain")
        or manifest_obj.get("company", {}).get("domain")
        or "corp.local"
    ).strip() or "corp.local"
    ldap_base_dn = ",".join(
        f"dc={part}"
        for part in domain.split(".")
        if str(part).strip()
    ) or "dc=corp,dc=local"

    host_catalog = (
        topology.get("host_catalog")
        if isinstance(topology.get("host_catalog"), dict)
        else {}
    )
    host_names = _merge_hosts(topology.get("hosts"), host_catalog)

    db_host_from_conn, db_user_from_conn, db_password_from_conn, db_name_from_conn = (
        _extract_mysql_contract(str(infra.get("db_connection", "")))
    )
    web_doc_root = str(
        contract.get("web_doc_root")
        or infra.get("web_docroot")
        or topology.get("web_doc_root")
        or "/var/www/html"
    ).strip() or "/var/www/html"

    contract.setdefault(
        "web_host",
        _pick_runtime_host(
            contract.get("web_host"),
            host_names=host_names,
            host_catalog=host_catalog,
            preferred_name="web",
            service_hints={"nginx", "php-fpm", "apache", "http"},
        ),
    )
    contract.setdefault(
        "db_host",
        _pick_runtime_host(
            contract.get("db_host") or db_host_from_conn,
            host_names=host_names,
            host_catalog=host_catalog,
            preferred_name="db",
            service_hints={"mysql", "mariadb", "postgres", "postgresql"},
        ),
    )
    contract.setdefault(
        "ldap_host",
        _pick_runtime_host(
            contract.get("ldap_host"),
            host_names=host_names,
            host_catalog=host_catalog,
            preferred_name="ldap",
            service_hints={"ldap", "openldap", "kerberos"},
        ),
    )
    contract.setdefault("web_doc_root", web_doc_root)
    contract.setdefault(
        "web_config_path",
        _default_web_config_path(
            str(contract.get("web_config_path") or topology.get("web_config_path") or "")
            or web_doc_root
        ),
    )
    contract.setdefault("db_name", db_name_from_conn or "referral_db")
    contract.setdefault("db_user", db_user_from_conn or "app_user")
    contract.setdefault("db_password", db_password_from_conn or "AppUs3r!2024")
    contract.setdefault("ldap_search_base_dn", ldap_base_dn)
    contract.setdefault("ldap_bind_dn", f"cn=admin,{ldap_base_dn}")
    contract.setdefault("ldap_bind_pw", "LdapAdm1n!")

    reuse_user = _first_service_account_name(manifest_obj) or str(contract.get("db_user") or "")
    contract.setdefault("credential_reuse_user", reuse_user or "svc_backup")
    contract.setdefault("credential_reuse_host", str(contract["db_host"]))
    contract.setdefault("credential_reuse_password", str(contract["ldap_bind_pw"]))
    return {str(key): str(value) for key, value in contract.items() if value is not None}


def _merge_hosts(
    raw_hosts: object,
    host_catalog: dict[str, dict[str, Any]],
) -> list[str]:
    hosts: list[str] = []
    seen: set[str] = set()
    if isinstance(raw_hosts, list):
        for raw in raw_hosts:
            if isinstance(raw, dict):
                name = str(raw.get("name", "")).strip()
            else:
                name = str(raw).strip()
            if not name or name in seen:
                continue
            seen.add(name)
            hosts.append(name)
    for host in host_catalog:
        if host in seen:
            continue
        seen.add(host)
        hosts.append(host)
    return hosts


def _merge_zones(
    raw_zones: object,
    host_catalog: dict[str, dict[str, Any]],
) -> dict[str, list[str]]:
    zones: dict[str, list[str]] = {}
    if isinstance(raw_zones, dict):
        for zone, raw_hosts in raw_zones.items():
            zone_name = str(zone).strip()
            if not zone_name:
                continue
            zone_hosts: list[str] = []
            if isinstance(raw_hosts, list):
                for raw_host in raw_hosts:
                    host = str(raw_host).strip()
                    if host and host not in zone_hosts:
                        zone_hosts.append(host)
            zones[zone_name] = zone_hosts

    for host, raw_catalog in host_catalog.items():
        zone = str(raw_catalog.get("zone", "")).strip() or "default"
        zone_hosts = zones.setdefault(zone, [])
        if host not in zone_hosts:
            zone_hosts.append(host)
    return zones


def _service_names(raw_services: object) -> set[str]:
    names: set[str] = set()
    if not isinstance(raw_services, list):
        return names
    for raw in raw_services:
        if isinstance(raw, dict):
            name = str(raw.get("name", "")).strip().lower()
            if name:
                names.add(name)
        else:
            name = str(raw).strip().lower()
            if name:
                names.add(name)
    return names


def _pick_runtime_host(
    explicit: object,
    *,
    host_names: list[str],
    host_catalog: dict[str, dict[str, Any]],
    preferred_name: str,
    service_hints: set[str],
) -> str:
    candidate = str(explicit or "").strip()
    if candidate:
        return candidate
    if preferred_name in host_names:
        return preferred_name
    for host_name in host_names:
        raw_catalog = host_catalog.get(host_name, {})
        if _service_names(raw_catalog.get("services")) & service_hints:
            return host_name
    return preferred_name


def _extract_mysql_contract(db_connection: str) -> tuple[str, str, str, str]:
    if not db_connection:
        return "", "", "", ""
    match = re.search(
        r"new\s+mysqli\(\s*['\"]([^'\"]+)['\"]\s*,\s*['\"]([^'\"]+)['\"]\s*,\s*['\"]([^'\"]+)['\"]\s*,\s*['\"]([^'\"]+)['\"]\s*\)",
        db_connection,
    )
    if not match:
        return "", "", "", ""
    return match.group(1), match.group(2), match.group(3), match.group(4)


def _default_web_config_path(raw_path: str) -> str:
    path = str(raw_path).strip() or "/var/www/portal"
    if path.endswith(".php"):
        return path
    normalized = path.rstrip("/")
    if not normalized:
        return "/var/www/config.php"
    parent = normalized.rsplit("/", 1)[0] if "/" in normalized else ""
    if not parent:
        return "/config.php"
    return f"{parent}/config.php"


def _first_service_account_name(manifest: dict[str, Any]) -> str:
    policy = (
        manifest.get("credential_policy", {})
        if isinstance(manifest.get("credential_policy"), dict)
        else {}
    )
    entries = policy.get("service_accounts", [])
    if not isinstance(entries, list):
        return ""
    for raw in entries:
        if not isinstance(raw, dict):
            continue
        username = str(raw.get("username") or raw.get("account") or raw.get("name") or "").strip()
        if username:
            return username
    return ""


def _merge_users(raw_users: object, manifest: dict[str, Any]) -> list[dict[str, Any]]:
    existing: dict[str, dict[str, Any]] = {}
    extras: list[dict[str, Any]] = []
    if isinstance(raw_users, list):
        for raw in raw_users:
            if not isinstance(raw, dict):
                continue
            username = str(raw.get("username", "")).strip()
            if not username:
                continue
            existing[username] = deepcopy(raw)

    merged: list[dict[str, Any]] = []
    seen: set[str] = set()
    for raw in manifest.get("users", []):
        if not isinstance(raw, dict):
            continue
        username = str(raw.get("username", "")).strip()
        if not username:
            continue
        record = existing.pop(username, {})
        record.setdefault("username", username)
        record.setdefault("password", "")
        record.setdefault("groups", [])
        record.setdefault("hosts", deepcopy(raw.get("hosts", [])))
        record.setdefault("email", str(raw.get("email", "")))
        record.setdefault("full_name", str(raw.get("full_name", "")))
        record.setdefault("department", str(raw.get("department", "")))
        record.setdefault("role", str(raw.get("role", "")))
        merged.append(record)
        seen.add(username)

    for username, record in existing.items():
        if username in seen:
            continue
        extras.append(record)
    merged.extend(extras)
    return merged


def _merge_host_details(
    raw_details: object,
    host_catalog: dict[str, dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    host_details: dict[str, dict[str, Any]] = {}
    if isinstance(raw_details, dict):
        for host, raw_detail in raw_details.items():
            host_name = str(host).strip()
            if not host_name or not isinstance(raw_detail, dict):
                continue
            host_details[host_name] = deepcopy(raw_detail)

    for host, raw_catalog in host_catalog.items():
        detail = host_details.setdefault(host, {})
        detail.setdefault("zone", str(raw_catalog.get("zone", "")))
        detail.setdefault("services", deepcopy(raw_catalog.get("services", [])))
        detail.setdefault("connects_to", deepcopy(raw_catalog.get("connects_to", [])))
        detail.setdefault("purpose", str(raw_catalog.get("purpose", "")))
        detail.setdefault("hostname", str(raw_catalog.get("hostname", "")))
        detail.setdefault("os", str(raw_catalog.get("os", "")))
        detail.setdefault("exposure", deepcopy(raw_catalog.get("exposure", {})))
    return host_details


def _merge_dependency_edges(
    raw_edges: object,
    host_catalog: dict[str, dict[str, Any]],
) -> list[dict[str, str]]:
    edges: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    if isinstance(raw_edges, list):
        for raw in raw_edges:
            if not isinstance(raw, dict):
                continue
            source = str(raw.get("source", "")).strip()
            target = str(raw.get("target", "")).strip()
            if not source or not target or (source, target) in seen:
                continue
            edges.append({"source": source, "target": target})
            seen.add((source, target))

    for source, raw_catalog in host_catalog.items():
        raw_targets = raw_catalog.get("connects_to", [])
        if not isinstance(raw_targets, list):
            continue
        for raw_target in raw_targets:
            target = str(raw_target).strip()
            if not target or (source, target) in seen:
                continue
            edges.append({"source": source, "target": target})
            seen.add((source, target))
    return edges


def _merge_trust_edges(
    raw_edges: object,
    manifest: dict[str, Any],
) -> list[dict[str, str]]:
    edges: list[dict[str, str]] = []
    seen: set[tuple[str, str, str]] = set()
    if isinstance(raw_edges, list):
        for raw in raw_edges:
            if not isinstance(raw, dict):
                continue
            source = str(raw.get("source", "")).strip()
            target = str(raw.get("target", "")).strip()
            edge_type = str(raw.get("type", "")).strip()
            if not source or not target or (source, target, edge_type) in seen:
                continue
            edges.append(
                {
                    "source": source,
                    "target": target,
                    "type": edge_type,
                    "context": str(raw.get("context", "")),
                }
            )
            seen.add((source, target, edge_type))

    for raw in manifest.get("trust_relationships", []):
        if not isinstance(raw, dict):
            continue
        source = str(raw.get("source") or raw.get("from") or "").strip()
        target = str(raw.get("target") or raw.get("to") or "").strip()
        edge_type = str(raw.get("type", "")).strip()
        if not source or not target or (source, target, edge_type) in seen:
            continue
        edges.append(
            {
                "source": source,
                "target": target,
                "type": edge_type,
                "context": str(raw.get("context") or raw.get("description") or ""),
            }
        )
        seen.add((source, target, edge_type))
    return edges
