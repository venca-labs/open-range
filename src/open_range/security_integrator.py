"""Wire security training modules into the v1 build pipeline.

The ``SecurityIntegrator`` orchestrates the four training-layer modules
(Identity Provider, Envelope Encryption, mTLS Simulation, NPC Credential
Lifecycle) so that rendered snapshots automatically include security
infrastructure appropriate for the world's tier.

Tier mapping (configurable):

- **Tier 1**: No security infrastructure (baseline application-level training).
- **Tier 2**: Identity provider + envelope encryption.
- **Tier 3+**: Full stack -- identity + encryption + mTLS + NPC credential
  lifecycle with authorization policies.

The integrator runs as a post-render enrichment step.  It reads the
``WorldIR``, generates security artefacts, and writes them as JSON
config files alongside the rendered Kind/Helm artifacts.

Ported from k3s-istio-vault-platform's orchestration patterns:
- App-of-apps component ordering (root-chart)
- Service identity registration (ClusterSPIFFEID CRDs)
- Post-deploy initialization (configure-vault.sh, seed-job)
"""

from __future__ import annotations

import json
import logging
import os
from copy import deepcopy
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from open_range.world_ir import WorldIR

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


class SecurityTierConfig(BaseModel):
    """Per-tier security feature flags."""

    identity_provider: bool = False
    envelope_encryption: bool = False
    mtls: bool = False
    npc_credential_lifecycle: bool = False


# Default tier mapping -- tier 1 has no security infra, tier 2 adds
# identity + encryption, tier 3+ adds mTLS + NPC credential lifecycle.
DEFAULT_TIER_MAP: dict[int, SecurityTierConfig] = {
    1: SecurityTierConfig(),
    2: SecurityTierConfig(identity_provider=True, envelope_encryption=True),
    3: SecurityTierConfig(
        identity_provider=True,
        envelope_encryption=True,
        mtls=True,
        npc_credential_lifecycle=True,
    ),
    4: SecurityTierConfig(
        identity_provider=True,
        envelope_encryption=True,
        mtls=True,
        npc_credential_lifecycle=True,
    ),
    5: SecurityTierConfig(
        identity_provider=True,
        envelope_encryption=True,
        mtls=True,
        npc_credential_lifecycle=True,
    ),
}


class SecurityIntegratorConfig(BaseModel):
    """Top-level configuration for the security integrator."""

    enabled: bool = Field(
        default=False,
        description="Master switch. When False the integrator is a no-op.",
    )
    tier_map: dict[int, SecurityTierConfig] = Field(
        default_factory=lambda: deepcopy(DEFAULT_TIER_MAP),
    )
    # Identity provider
    idp_issuer: str = "https://idp.range.local"
    idp_token_ttl_seconds: int = 300
    idp_weaknesses: list[str] = Field(
        default_factory=lambda: ["accept_expired", "overly_broad_scopes"],
    )
    # Envelope encryption
    encryption_fraction: float = Field(
        default=0.5,
        description="Fraction of credential secrets to encrypt (0.0-1.0).",
    )
    # mTLS
    mtls_weakness_pool: list[str] = Field(
        default_factory=lambda: [
            "expired_cert",
            "weak_key_1024",
            "no_client_verify",
            "wrong_san",
            "self_signed",
        ],
    )
    # NPC credential lifecycle
    npc_session_ttl_minutes: int = 30
    npc_token_ttl_minutes: int = 5
    npc_weaknesses: list[str] = Field(
        default_factory=lambda: ["predictable_session_id", "token_in_url"],
    )

    @classmethod
    def from_env(cls) -> SecurityIntegratorConfig:
        """Build config from environment variables."""
        enabled = os.environ.get("OPENRANGE_SECURITY_INTEGRATION", "").lower() in (
            "1",
            "true",
            "yes",
        )
        return cls(enabled=enabled)


# ---------------------------------------------------------------------------
# Security context returned by the integrator
# ---------------------------------------------------------------------------


class SecurityContext(BaseModel):
    """Result of a security integration pass."""

    tier: int = 1
    identity_provider: dict[str, Any] = Field(default_factory=dict)
    encryption: dict[str, Any] = Field(default_factory=dict)
    mtls: dict[str, Any] = Field(default_factory=dict)
    npc_credential_lifecycle: dict[str, Any] = Field(default_factory=dict)
    generated_files: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Integrator
# ---------------------------------------------------------------------------


class SecurityIntegrator:
    """Orchestrate security module integration into rendered snapshots.

    Usage::

        integrator = SecurityIntegrator(SecurityIntegratorConfig(enabled=True))
        ctx = integrator.integrate(world, render_dir=Path("/tmp/render"), tier=2)
    """

    def __init__(self, config: SecurityIntegratorConfig | None = None) -> None:
        self.config = config or SecurityIntegratorConfig()

    def integrate(
        self,
        world: WorldIR,
        *,
        render_dir: Path,
        tier: int = 1,
    ) -> SecurityContext:
        """Enrich rendered artifacts with security infrastructure.

        Writes security config and artefact files into *render_dir*.
        Returns a ``SecurityContext`` summarising what was generated.
        """
        ctx = SecurityContext(tier=tier)

        if not self.config.enabled:
            return ctx

        tier_cfg = self.config.tier_map.get(
            tier,
            self.config.tier_map.get(max(self.config.tier_map), SecurityTierConfig()),
        )

        # Build service→zone mapping from WorldIR
        services: dict[str, str] = {}
        host_by_id = {h.id: h for h in world.hosts}
        for svc in world.services:
            zone = host_by_id[svc.host].zone if svc.host in host_by_id else "default"
            services[svc.id] = zone

        domain = "range.local"
        security_dir = render_dir / "security"
        security_dir.mkdir(parents=True, exist_ok=True)

        if tier_cfg.identity_provider:
            self._integrate_identity(ctx, services, domain, security_dir)

        if tier_cfg.envelope_encryption:
            self._integrate_encryption(ctx, world, security_dir)

        if tier_cfg.mtls:
            self._integrate_mtls(ctx, services, domain, security_dir)

        if tier_cfg.npc_credential_lifecycle:
            self._integrate_npc_lifecycle(ctx, security_dir)

        # Write the security context summary
        ctx_path = security_dir / "security-context.json"
        ctx_path.write_text(
            json.dumps(ctx.model_dump(), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        ctx.generated_files.append(str(ctx_path))

        logger.info(
            "SecurityIntegrator: enriched render (tier=%d, idp=%s, enc=%s, mtls=%s, npc=%s)",
            tier,
            tier_cfg.identity_provider,
            tier_cfg.envelope_encryption,
            tier_cfg.mtls,
            tier_cfg.npc_credential_lifecycle,
        )
        return ctx

    # ------------------------------------------------------------------
    # Identity Provider
    # ------------------------------------------------------------------

    def _integrate_identity(
        self,
        ctx: SecurityContext,
        services: dict[str, str],
        domain: str,
        security_dir: Path,
    ) -> None:
        """Generate identity provider config and tokens."""
        try:
            from open_range.identity_provider import (
                IdentityProviderConfig,
                ServiceIdentity,
                SimulatedIdentityProvider,
                build_spiffe_id,
            )
        except ImportError:
            logger.warning(
                "identity_provider module not available; skipping IdP integration"
            )
            return

        identities: dict[str, ServiceIdentity] = {}
        for svc_name, zone in services.items():
            if svc_name in ("attacker",):
                continue
            spiffe_id = build_spiffe_id("range.local", zone, svc_name)
            scopes = _default_scopes_for_service(svc_name)
            identities[svc_name] = ServiceIdentity(
                identity_uri=spiffe_id,
                allowed_scopes=scopes,
            )

        idp_config = IdentityProviderConfig(
            enabled=True,
            issuer=self.config.idp_issuer,
            token_ttl_seconds=self.config.idp_token_ttl_seconds,
            weaknesses=list(self.config.idp_weaknesses),
            service_identities=identities,
        )

        ctx.identity_provider = idp_config.model_dump()

        # Generate startup script
        idp = SimulatedIdentityProvider(idp_config)
        startup_script = idp.generate_startup_script()

        # Write IdP artifacts
        idp_dir = security_dir / "idp"
        idp_dir.mkdir(parents=True, exist_ok=True)
        (idp_dir / "config.json").write_text(
            json.dumps(idp_config.model_dump(), indent=2) + "\n", encoding="utf-8"
        )
        (idp_dir / "server.py").write_text(startup_script, encoding="utf-8")
        ctx.generated_files.extend(
            [str(idp_dir / "config.json"), str(idp_dir / "server.py")]
        )

        logger.debug(
            "Identity provider integrated: %d service identities", len(identities)
        )

    # ------------------------------------------------------------------
    # Envelope Encryption
    # ------------------------------------------------------------------

    def _integrate_encryption(
        self,
        ctx: SecurityContext,
        world: WorldIR,
        security_dir: Path,
    ) -> None:
        """Generate envelope encryption config for credential secrets."""
        try:
            from open_range.envelope_crypto import (
                EncryptionConfig,
                EnvelopeCrypto,
            )
        except ImportError:
            logger.warning(
                "envelope_crypto module not available; skipping encryption integration"
            )
            return

        # Encrypt a subset of credential secret_refs
        import math
        import random as _random

        credentials = list(world.credentials)
        if not credentials:
            return

        n_encrypt = max(
            1, math.ceil(len(credentials) * self.config.encryption_fraction)
        )
        indices = _random.sample(
            list(range(len(credentials))),
            min(n_encrypt, len(credentials)),
        )

        master_key = EnvelopeCrypto.generate_master_key()
        import base64

        master_key_b64 = base64.b64encode(master_key).decode()

        encrypted_refs: list[str] = []
        dek_metadata: dict[str, Any] = {}

        prev_env = os.environ.get("OPENRANGE_MASTER_KEY")
        os.environ["OPENRANGE_MASTER_KEY"] = master_key_b64
        try:
            crypto = EnvelopeCrypto(master_key)
            for idx in indices:
                cred = credentials[idx]
                aad = f"openrange:range:{cred.subject}:{cred.id}"
                bundle = crypto.encrypt(cred.secret_ref, aad=aad)
                encrypted_refs.append(cred.id)
                dek_metadata[cred.id] = bundle.model_dump()
        finally:
            if prev_env is None:
                os.environ.pop("OPENRANGE_MASTER_KEY", None)
            else:
                os.environ["OPENRANGE_MASTER_KEY"] = prev_env

        if encrypted_refs:
            enc_dir = security_dir / "encryption"
            enc_dir.mkdir(parents=True, exist_ok=True)

            enc_config = EncryptionConfig(
                enabled=True,
                encrypted_paths=encrypted_refs,
                master_key_source="file",
                dek_storage_path="/etc/openrange/wrapped_dek.json",
            )
            ctx.encryption = enc_config.model_dump()

            (enc_dir / "config.json").write_text(
                json.dumps(enc_config.model_dump(), indent=2) + "\n", encoding="utf-8"
            )
            (enc_dir / "wrapped_dek.json").write_text(
                json.dumps(dek_metadata, indent=2) + "\n", encoding="utf-8"
            )
            ctx.generated_files.extend(
                [
                    str(enc_dir / "config.json"),
                    str(enc_dir / "wrapped_dek.json"),
                ]
            )

        logger.debug(
            "Encryption integrated: %d credentials encrypted", len(encrypted_refs)
        )

    # ------------------------------------------------------------------
    # mTLS Simulation
    # ------------------------------------------------------------------

    def _integrate_mtls(
        self,
        ctx: SecurityContext,
        services: dict[str, str],
        domain: str,
        security_dir: Path,
    ) -> None:
        """Generate TLS certificates for service-to-service mTLS."""
        try:
            from open_range.mtls_sim import MTLSConfig, MTLSSimulator
        except ImportError:
            logger.warning("mtls_sim module not available; skipping mTLS integration")
            return

        mtls_services = [svc for svc in services if svc not in ("attacker", "siem")]
        if not mtls_services:
            return

        import random as _random

        weaknesses: dict[str, list[str]] = {}
        if mtls_services and self.config.mtls_weakness_pool:
            target_svc = _random.choice(mtls_services)
            weakness = _random.choice(self.config.mtls_weakness_pool)
            weaknesses[target_svc] = [weakness]

        mtls_config = MTLSConfig(
            enabled=True,
            mtls_services=mtls_services,
            weaknesses=weaknesses,
        )

        sim = MTLSSimulator(mtls_config)
        # Build zones dict from services mapping
        zones_dict: dict[str, list[str]] = {}
        for svc_name, zone in services.items():
            zones_dict.setdefault(zone, []).append(svc_name)

        bundles = sim.generate_all_certs(services, zones_dict)

        mtls_dir = security_dir / "mtls"
        mtls_dir.mkdir(parents=True, exist_ok=True)

        for svc_name, bundle in bundles.items():
            svc_dir = mtls_dir / svc_name
            svc_dir.mkdir(parents=True, exist_ok=True)
            for payload in sim.get_payload_files(bundle):
                fname = payload["mountPath"].rsplit("/", 1)[-1]
                (svc_dir / fname).write_text(payload["content"], encoding="utf-8")
                ctx.generated_files.append(str(svc_dir / fname))

        ctx.mtls = mtls_config.model_dump()

        (mtls_dir / "config.json").write_text(
            json.dumps(mtls_config.model_dump(), indent=2) + "\n", encoding="utf-8"
        )
        ctx.generated_files.append(str(mtls_dir / "config.json"))

        logger.debug(
            "mTLS integrated: %d services, weaknesses=%s", len(bundles), weaknesses
        )

    # ------------------------------------------------------------------
    # NPC Credential Lifecycle
    # ------------------------------------------------------------------

    def _integrate_npc_lifecycle(
        self,
        ctx: SecurityContext,
        security_dir: Path,
    ) -> None:
        """Configure NPC credential lifecycle."""
        try:
            from open_range.credential_lifecycle import CredentialLifecycleConfig
        except ImportError:
            logger.warning(
                "credential_lifecycle module not available; skipping NPC lifecycle integration"
            )
            return

        lifecycle_config = CredentialLifecycleConfig(
            enabled=True,
            session_ttl_minutes=self.config.npc_session_ttl_minutes,
            token_ttl_minutes=self.config.npc_token_ttl_minutes,
            weaknesses=list(self.config.npc_weaknesses),
        )

        ctx.npc_credential_lifecycle = lifecycle_config.model_dump()

        npc_dir = security_dir / "npc"
        npc_dir.mkdir(parents=True, exist_ok=True)
        (npc_dir / "config.json").write_text(
            json.dumps(lifecycle_config.model_dump(), indent=2) + "\n", encoding="utf-8"
        )
        ctx.generated_files.append(str(npc_dir / "config.json"))

        logger.debug(
            "NPC credential lifecycle integrated: weaknesses=%s",
            self.config.npc_weaknesses,
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _default_scopes_for_service(service_name: str) -> list[str]:
    """Return default authorization scopes for a service."""
    scope_map: dict[str, list[str]] = {
        "web": ["data:read:patients/*", "data:read:referrals/*", "api:access:portal"],
        "db": ["data:read:*", "data:write:*"],
        "ldap": ["auth:bind:*", "auth:search:*"],
        "mail": ["mail:send:*", "mail:read:*"],
        "files": ["file:read:general/*", "file:read:hr/*"],
        "siem": ["log:read:*", "log:write:*", "alert:read:*"],
    }
    return scope_map.get(service_name, [f"service:access:{service_name}"])
