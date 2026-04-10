"""Check: Identity enforcement -- validates identity provider configuration.

Advisory check that verifies the simulated identity provider is correctly
configured when enabled.  This check never blocks admission on its own;
it logs warnings for Red/Blue training completeness.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from open_range.admission import ValidatorCheckReport
from open_range.snapshot import KindArtifacts
from open_range.world_ir import WorldIR

logger = logging.getLogger(__name__)

_CRITICAL_SERVICE_KINDS = {"web_app", "db", "idp"}


def check_identity_enforcement(
    world: WorldIR,
    artifacts: KindArtifacts,
    reference_bundle: object = None,
) -> ValidatorCheckReport:
    """Validate identity provider config in rendered artifacts.

    Matches v1's ``CheckFunc`` signature so it can be registered as an
    advisory admission check.
    """
    security_dir = Path(artifacts.render_dir) / "security" / "idp"
    config_path = security_dir / "config.json"

    if not config_path.exists():
        return ValidatorCheckReport(
            name="identity_enforcement",
            passed=True,
            advisory=True,
            details={"note": "identity_provider not configured -- vacuously passes"},
        )

    issues: list[str] = []
    details: dict[str, Any] = {}

    try:
        idp_raw = json.loads(config_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        return ValidatorCheckReport(
            name="identity_enforcement",
            passed=False,
            advisory=True,
            details={"error": f"cannot read IdP config: {exc}"},
        )

    enabled = bool(idp_raw.get("enabled", False))
    details["idp_enabled"] = enabled

    if not enabled:
        return ValidatorCheckReport(
            name="identity_enforcement",
            passed=True,
            advisory=True,
            details={"note": "identity_provider not enabled -- vacuously passes"},
        )

    # Validate config shape
    issuer = idp_raw.get("issuer", "")
    if not issuer:
        issues.append("identity_provider.issuer is empty")

    ttl = idp_raw.get("token_ttl_seconds", 0)
    if not isinstance(ttl, (int, float)) or ttl <= 0:
        issues.append("identity_provider.token_ttl_seconds must be positive")

    signing_alg = idp_raw.get("signing_algorithm", "RS256")
    if signing_alg not in ("RS256", "HS256", "ES256"):
        issues.append(
            f"identity_provider.signing_algorithm '{signing_alg}' is not recognized"
        )

    # Validate service identities
    service_identities = idp_raw.get("service_identities", {})
    details["service_identity_count"] = len(service_identities)

    if world is not None:
        world_service_kinds = {svc.kind for svc in world.services}
        for critical in _CRITICAL_SERVICE_KINDS:
            if critical in world_service_kinds:
                svc_ids = {svc.id for svc in world.services if svc.kind == critical}
                if not any(sid in service_identities for sid in svc_ids):
                    issues.append(
                        f"critical service kind '{critical}' present but has no "
                        "service_identity defined"
                    )

    # Validate SPIFFE URI format
    for svc_name, identity_raw in service_identities.items():
        if isinstance(identity_raw, dict):
            uri = identity_raw.get("identity_uri", "")
        else:
            uri = ""
        if uri and not uri.startswith("spiffe://"):
            issues.append(f"service_identity '{svc_name}' has non-SPIFFE URI: {uri}")

    # Validate weaknesses
    weaknesses = idp_raw.get("weaknesses", [])
    details["weakness_count"] = len(weaknesses)

    known = {
        "accept_expired",
        "no_audience_check",
        "weak_signing_hs256",
        "overly_broad_scopes",
        "predictable_jti",
        "missing_scope_check",
    }
    unknown = [w for w in weaknesses if w not in known]
    if unknown:
        issues.append(f"unknown weakness type(s): {', '.join(unknown)}")

    if not weaknesses:
        issues.append(
            "identity_provider enabled but no weaknesses planted -- "
            "Red has no identity-based attack surface"
        )

    # Token smoke test
    try:
        from open_range.identity_provider import (
            IdentityProviderConfig,
            ServiceIdentity,
            SimulatedIdentityProvider,
        )

        svc_identities = {}
        for svc_name, id_raw in service_identities.items():
            if isinstance(id_raw, dict):
                svc_identities[svc_name] = ServiceIdentity(
                    identity_uri=id_raw.get("identity_uri", ""),
                    allowed_scopes=id_raw.get("allowed_scopes", []),
                )

        idp_config = IdentityProviderConfig(
            enabled=True,
            issuer=str(issuer),
            token_ttl_seconds=int(ttl)
            if isinstance(ttl, (int, float)) and ttl > 0
            else 300,
            signing_algorithm=str(signing_alg),
            weaknesses=list(weaknesses),
            service_identities=svc_identities,
        )
        idp = SimulatedIdentityProvider(idp_config)

        test_token = idp.issue_token(
            subject="spiffe://range.local/ns/test/sa/validator",
            scopes=["test:validate:*"],
        )
        claims = idp.validate_token(test_token)
        if claims is None:
            issues.append("identity_provider smoke test failed: token did not validate")
        else:
            details["smoke_test"] = "passed"

        jwks = idp.jwks()
        if not jwks.get("keys") and "weak_signing_hs256" not in weaknesses:
            issues.append("JWKS is empty -- token verification will fail for RS256")

    except ImportError:
        details["smoke_test"] = "skipped (import unavailable)"
    except Exception as exc:  # noqa: BLE001
        issues.append(f"identity_provider smoke test error: {exc}")

    passed = len(issues) == 0
    details["issues"] = issues
    return ValidatorCheckReport(
        name="identity_enforcement",
        passed=passed,
        advisory=True,
        details=details,
        error="" if passed else "; ".join(issues),
    )
