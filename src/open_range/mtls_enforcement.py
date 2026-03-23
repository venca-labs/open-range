"""Check: mTLS Enforcement -- validates mTLS configuration is correctly applied.

Verifies that services configured for mTLS have certificate material
generated in the rendered artifact directory and that the CA trust chain
is consistent.

This check is advisory-safe: if mTLS is not enabled the check passes
immediately (mTLS is completely optional).
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

from open_range.admission import ValidatorCheckReport
from open_range.snapshot import KindArtifacts
from open_range.world_ir import WorldIR

logger = logging.getLogger(__name__)

_MTLS_CERT_FILES = ("ca.pem", "cert.pem", "key.pem")


def check_mtls_enforcement(
    world: WorldIR,
    artifacts: KindArtifacts,
    reference_bundle: object = None,
) -> ValidatorCheckReport:
    """Validate mTLS certificate config in rendered artifacts.

    Matches v1's ``CheckFunc`` signature so it can be registered as an
    advisory admission check.
    """
    security_dir = Path(artifacts.render_dir) / "security" / "mtls"
    config_path = security_dir / "config.json"

    if not config_path.exists():
        return ValidatorCheckReport(
            name="mtls_enforcement",
            passed=True,
            advisory=True,
            details={"note": "mTLS not configured -- vacuously passes"},
        )

    issues: list[str] = []

    try:
        mtls_config = json.loads(config_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        return ValidatorCheckReport(
            name="mtls_enforcement",
            passed=False,
            advisory=True,
            details={"error": f"cannot read mTLS config: {exc}"},
        )

    if not mtls_config.get("enabled", False):
        return ValidatorCheckReport(
            name="mtls_enforcement",
            passed=True,
            advisory=True,
            details={"note": "mTLS not enabled -- vacuously passes"},
        )

    mtls_services: list[str] = mtls_config.get("mtls_services", [])
    weaknesses: dict[str, list[str]] = mtls_config.get("weaknesses", {})

    if not mtls_services:
        issues.append("mTLS enabled but no services listed")

    # Check cert files exist for each service
    for svc_name in mtls_services:
        svc_dir = security_dir / svc_name
        missing = []
        for fname in _MTLS_CERT_FILES:
            if not (svc_dir / fname).exists():
                missing.append(fname)
        if missing:
            issues.append(f"{svc_name}: missing mTLS file(s): {', '.join(missing)}")

    # CA consistency: non-self_signed services should share the same CA
    consistent_cas: set[str] = set()
    for svc_name in mtls_services:
        svc_weaknesses = weaknesses.get(svc_name, [])
        if "self_signed" in svc_weaknesses:
            continue
        ca_path = security_dir / svc_name / "ca.pem"
        if ca_path.exists():
            consistent_cas.add(ca_path.read_text(encoding="utf-8"))

    if len(consistent_cas) > 1:
        issues.append(
            f"CA certificate inconsistent across mTLS services "
            f"(found {len(consistent_cas)} distinct CAs excluding self_signed)"
        )

    # At least one weakness should be planted for training value
    total_weaknesses = sum(len(v) for v in weaknesses.values())
    if total_weaknesses == 0:
        issues.append("No weaknesses planted in any mTLS service")

    passed = len(issues) == 0
    return ValidatorCheckReport(
        name="mtls_enforcement",
        passed=passed,
        advisory=True,
        details={
            "mtls_services": mtls_services,
            "weaknesses": weaknesses,
            "issues": issues,
        },
        error="" if passed else "; ".join(issues),
    )
