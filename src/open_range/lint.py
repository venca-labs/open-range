"""Manifest authoring lint for OpenRange.

Validates YAML manifest files with cross-field consistency checks beyond
what Pydantic schema validation covers.

Usage::

    python -m open_range.lint manifests/tier1_basic.yaml
    python -m open_range.lint manifests/*.yaml
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from typing import Any

from manifests.schema import Manifest, load_manifest


# ---------------------------------------------------------------------------
# Cross-field checks
# ---------------------------------------------------------------------------


def _check_connects_to(manifest: Manifest) -> list[str]:
    """All hosts referenced in connects_to must exist."""
    host_names = {h.name for h in manifest.topology.hosts}
    errors: list[str] = []
    for host in manifest.topology.hosts:
        for target in host.connects_to:
            if target not in host_names:
                errors.append(
                    f"Host '{host.name}' connects_to '{target}' "
                    f"which is not a defined host. "
                    f"Valid hosts: {sorted(host_names)}"
                )
    return errors


def _check_firewall_zones(manifest: Manifest) -> list[str]:
    """All firewall rules reference valid zones."""
    zone_names = {n.name for n in manifest.topology.networks}
    errors: list[str] = []
    for rule in manifest.topology.firewall_rules:
        if rule.from_zone not in zone_names:
            errors.append(
                f"Firewall rule from_zone '{rule.from_zone}' "
                f"is not a defined zone. Valid zones: {sorted(zone_names)}"
            )
        if rule.to_zone not in zone_names:
            errors.append(
                f"Firewall rule to_zone '{rule.to_zone}' "
                f"is not a defined zone. Valid zones: {sorted(zone_names)}"
            )
    return errors


def _check_user_hosts(manifest: Manifest) -> list[str]:
    """All user host references must be valid hosts."""
    host_names = {h.name for h in manifest.topology.hosts}
    errors: list[str] = []
    for user in manifest.users:
        for host in user.hosts:
            if host not in host_names:
                errors.append(
                    f"User '{user.username}' references host '{host}' "
                    f"which is not a defined host. "
                    f"Valid hosts: {sorted(host_names)}"
                )
    return errors


def _check_npc_usernames(manifest: Manifest) -> list[str]:
    """All NPC personas must reference valid usernames from the users list."""
    user_names = {u.username for u in manifest.users}
    errors: list[str] = []
    for npc in manifest.npc_personas:
        if npc.username not in user_names:
            errors.append(
                f"NPC persona references username '{npc.username}' "
                f"which is not in the users list. "
                f"Valid usernames: {sorted(user_names)}"
            )
    return errors


def _check_data_inventory_hosts(manifest: Manifest) -> list[str]:
    """All data inventory items must reference valid hosts."""
    host_names = {h.name for h in manifest.topology.hosts}
    errors: list[str] = []
    for asset in manifest.data_inventory:
        if asset.host not in host_names:
            errors.append(
                f"Data asset '{asset.name}' references host '{asset.host}' "
                f"which is not a defined host. "
                f"Valid hosts: {sorted(host_names)}"
            )
    return errors


def _check_business_process_flows(manifest: Manifest) -> list[str]:
    """All business process data_flow entries must reference valid host:service pairs."""
    # Build a set of valid host:service pairs
    host_services: dict[str, set[str]] = {}
    for host in manifest.topology.hosts:
        host_services[host.name] = set(host.services)

    errors: list[str] = []
    for process in manifest.business_processes:
        for entry in process.data_flow:
            if ":" not in entry:
                errors.append(
                    f"Business process '{process.name}' has data_flow entry "
                    f"'{entry}' that is not in host:service format"
                )
                continue
            host_part, service_part = entry.split(":", 1)
            if host_part not in host_services:
                errors.append(
                    f"Business process '{process.name}' references host "
                    f"'{host_part}' in data_flow entry '{entry}' "
                    f"which is not a defined host. "
                    f"Valid hosts: {sorted(host_services.keys())}"
                )
            elif service_part not in host_services[host_part]:
                errors.append(
                    f"Business process '{process.name}' references service "
                    f"'{service_part}' on host '{host_part}' in data_flow "
                    f"entry '{entry}', but host '{host_part}' only has "
                    f"services: {sorted(host_services[host_part])}"
                )
    return errors


_PRINCIPAL_RE = re.compile(r"^[A-Za-z0-9._@-]+$")


def _check_trust_relationships(manifest: Manifest) -> list[str]:
    """Trust principals must be well-formed identifiers.

    Trust edges may reference people who are not login accounts. Those are
    normalized into the canonical principal catalog at build time, so lint
    should validate identifier quality rather than requiring every principal to
    appear in ``users``.
    """
    errors: list[str] = []
    for rel in manifest.trust_relationships:
        if rel.source and not _PRINCIPAL_RE.match(rel.source):
            errors.append(
                f"Trust relationship source '{rel.source}' is not a valid "
                "principal identifier"
            )
        if rel.target and not _PRINCIPAL_RE.match(rel.target):
            errors.append(
                f"Trust relationship target '{rel.target}' is not a valid "
                "principal identifier"
            )
    return errors


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

ALL_CHECKS = [
    ("connects_to references", _check_connects_to),
    ("firewall zone references", _check_firewall_zones),
    ("user host references", _check_user_hosts),
    ("NPC persona usernames", _check_npc_usernames),
    ("data inventory hosts", _check_data_inventory_hosts),
    ("business process data flows", _check_business_process_flows),
    ("trust relationship principals", _check_trust_relationships),
]


def lint_manifest(manifest: Manifest) -> dict[str, list[str]]:
    """Run all cross-field checks on a validated manifest.

    Returns:
        Dict mapping check name to list of error messages.
        Empty list means the check passed.
    """
    results: dict[str, list[str]] = {}
    for name, check_fn in ALL_CHECKS:
        results[name] = check_fn(manifest)
    return results


def lint_file(path: str | Path) -> dict[str, Any]:
    """Load and lint a manifest file.

    Returns:
        Dict with 'path', 'valid' (bool), 'schema_error' (str or None),
        and 'checks' (dict of check name -> error list).
    """
    path = Path(path)
    result: dict[str, Any] = {
        "path": str(path),
        "valid": True,
        "schema_error": None,
        "checks": {},
    }

    try:
        manifest = load_manifest(path)
    except FileNotFoundError as exc:
        result["valid"] = False
        result["schema_error"] = str(exc)
        return result
    except Exception as exc:
        result["valid"] = False
        result["schema_error"] = str(exc)
        return result

    checks = lint_manifest(manifest)
    result["checks"] = checks

    for errors in checks.values():
        if errors:
            result["valid"] = False
            break

    return result


# ---------------------------------------------------------------------------
# Terminal output
# ---------------------------------------------------------------------------

# ANSI color codes
_GREEN = "\033[32m"
_RED = "\033[31m"
_BOLD = "\033[1m"
_RESET = "\033[0m"


def _format_result(result: dict[str, Any]) -> str:
    """Format a lint result as colored terminal output."""
    lines: list[str] = []
    path = result["path"]

    if result["schema_error"]:
        lines.append(f"{_BOLD}{path}{_RESET}")
        lines.append(f"  {_RED}SCHEMA ERROR: {result['schema_error']}{_RESET}")
        return "\n".join(lines)

    lines.append(f"{_BOLD}{path}{_RESET}")
    all_passed = True
    for check_name, errors in result["checks"].items():
        if errors:
            all_passed = False
            lines.append(f"  {_RED}FAIL{_RESET} {check_name}")
            for err in errors:
                lines.append(f"    - {err}")
        else:
            lines.append(f"  {_GREEN}PASS{_RESET} {check_name}")

    if all_passed:
        lines.append(f"  {_GREEN}All checks passed.{_RESET}")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Lint OpenRange manifest YAML files",
    )
    parser.add_argument(
        "manifests",
        nargs="+",
        help="One or more manifest YAML file paths",
    )
    args = parser.parse_args()

    any_failed = False
    for manifest_path in args.manifests:
        result = lint_file(manifest_path)
        print(_format_result(result))
        print()
        if not result["valid"]:
            any_failed = True

    sys.exit(1 if any_failed else 0)


if __name__ == "__main__":
    main()
