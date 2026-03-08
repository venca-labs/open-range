#!/usr/bin/env python3
"""Render a snapshot through SnapshotRenderer and inspect the artifacts."""
from __future__ import annotations

import json
import sys
from pathlib import Path

__test__ = False

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))


def main():
    from open_range.builder.builder import _parse_llm_response
    from open_range.builder.renderer import SnapshotRenderer

    snapshot_path = Path(__file__).resolve().parent.parent / "snapshots" / "llm_tier1_test.json"
    if not snapshot_path.exists():
        print(f"ERROR: {snapshot_path} not found. Run test_tier1_llm.py first.")
        sys.exit(1)

    raw = snapshot_path.read_text()
    spec = _parse_llm_response(raw)

    print(f"Loaded snapshot: {len(spec.truth_graph.vulns)} vulns, {len(spec.flags)} flags")
    print(f"  Files: {len(spec.files)} entries")

    output_dir = Path(__file__).resolve().parent.parent / "snapshots" / "rendered_test" / "artifacts"
    renderer = SnapshotRenderer()
    renderer.render(spec, output_dir)

    print(f"\nRendered artifacts in {output_dir}:")
    for f in sorted(output_dir.iterdir()):
        size = f.stat().st_size
        print(f"  {f.name} ({size} bytes)")

    # Validate key artifacts
    print("\n--- docker-compose.yml (first 30 lines) ---")
    dc = (output_dir / "docker-compose.yml").read_text()
    for line in dc.splitlines()[:30]:
        print(f"  {line}")

    print("\n--- Dockerfile.web (full) ---")
    dweb = (output_dir / "Dockerfile.web").read_text()
    for line in dweb.splitlines():
        print(f"  {line}")

    print("\n--- nginx.conf (full) ---")
    nc = (output_dir / "nginx.conf").read_text()
    for line in nc.splitlines():
        print(f"  {line}")

    print("\n--- init.sql (first 40 lines) ---")
    sql = (output_dir / "init.sql").read_text()
    for line in sql.splitlines()[:40]:
        print(f"  {line}")

    # Checks
    errors = []

    # Check nginx uses /var/www/portal
    if "/var/www/html" in nc:
        errors.append("nginx.conf still references /var/www/html")
    if "/var/www/portal" not in nc:
        errors.append("nginx.conf missing /var/www/portal")

    # Check PHP-FPM socket
    if "php8.1-fpm.sock" not in nc:
        errors.append("nginx.conf uses wrong PHP-FPM socket")

    # Check Dockerfile.web uses php8.1
    if "php8.1-fpm" not in dweb:
        errors.append("Dockerfile.web missing php8.1-fpm")
    if "/var/www/portal" not in dweb:
        errors.append("Dockerfile.web missing /var/www/portal")

    # Check docker-compose has static IPs
    if "10.0.1.10" not in dc:
        errors.append("docker-compose missing web static IP 10.0.1.10")
    if "10.0.0.10" not in dc:
        errors.append("docker-compose missing attacker static IP 10.0.0.10")
    if "10.0.2.20" not in dc:
        errors.append("docker-compose missing db static IP 10.0.2.20")

    # Check init.sql uses referral_db
    if "referral_db" not in sql:
        errors.append("init.sql missing referral_db")
    if "patients" not in sql:
        errors.append("init.sql missing patients table")

    # Check docker-compose has NET_ADMIN for attacker
    if "NET_ADMIN" not in dc:
        errors.append("docker-compose missing NET_ADMIN for attacker")

    # Check mysql auth plugin
    if "mysql_native_password" not in dc:
        errors.append("docker-compose missing mysql_native_password")

    if errors:
        print(f"\nFAILED: {len(errors)} issues")
        for e in errors:
            print(f"  - {e}")
        sys.exit(1)
    else:
        print("\nALL CHECKS PASSED")


if __name__ == "__main__":
    main()
