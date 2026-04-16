"""Plan security runtime intent for the v1 build pipeline.

The ``SecurityIntegrator`` orchestrates the four training-layer modules
(Identity Provider, Envelope Encryption, mTLS Simulation, NPC Credential
Lifecycle) so that rendered snapshots automatically include security
infrastructure appropriate for the world's tier.

Tier mapping (configurable):

- **Tier 1**: No security infrastructure (baseline application-level training).
- **Tier 2**: Identity provider + envelope encryption.
- **Tier 3+**: Full stack -- identity + encryption + mTLS + NPC credential
  lifecycle with authorization policies.

The integrator builds a security runtime plan from the ``WorldIR`` and build
tier. The plan is stored on ``WorldIR`` as source-of-truth intent, and render
later materializes the concrete files and runtime components from that plan.

Ported from k3s-istio-vault-platform's orchestration patterns:
- App-of-apps component ordering (root-chart)
- Service identity registration (ClusterSPIFFEID CRDs)
- Post-deploy initialization (configure-vault.sh, seed-job)
"""

from __future__ import annotations

import logging
import os
import random
from copy import deepcopy
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from open_range.image_policy import DB_MTLS_HELPER_IMAGE
from open_range.runtime_extensions import (
    RuntimePort,
    RuntimeSidecar,
)
from open_range.security_runtime import (
    SecurityPayloadSpec,
    SecurityRuntimeSpec,
    SecurityServiceRuntimeSpec,
    materialize_security_runtime,
)
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
# Mutable planning context
# ---------------------------------------------------------------------------


class SecurityServiceRuntimeBuilder(BaseModel):
    """Mutable runtime builder before freezing onto ``WorldIR``."""

    env: dict[str, str] = Field(default_factory=dict)
    payloads: list[SecurityPayloadSpec] = Field(default_factory=list)
    ports: list[RuntimePort] = Field(default_factory=list)
    sidecars: list[RuntimeSidecar] = Field(default_factory=list)


class SecurityContext(BaseModel):
    """Mutable planner context before freezing onto ``WorldIR``."""

    tier: int = 1
    identity_provider: dict[str, Any] = Field(default_factory=dict)
    encryption: dict[str, Any] = Field(default_factory=dict)
    mtls: dict[str, Any] = Field(default_factory=dict)
    npc_credential_lifecycle: dict[str, Any] = Field(default_factory=dict)
    service_runtime: dict[str, SecurityServiceRuntimeBuilder] = Field(
        default_factory=dict
    )

    def service_extension(self, service_id: str) -> SecurityServiceRuntimeBuilder:
        return self.service_runtime.setdefault(
            service_id, SecurityServiceRuntimeBuilder()
        )

    def append_payload(
        self, service_id: str, payload: SecurityPayloadSpec | None
    ) -> None:
        if payload is not None:
            self.service_extension(service_id).payloads.append(payload)

    def append_port(self, service_id: str, port: RuntimePort) -> None:
        self.service_extension(service_id).ports.append(port)

    def append_sidecar(self, service_id: str, sidecar: RuntimeSidecar) -> None:
        self.service_extension(service_id).sidecars.append(sidecar)

    def extend_env(self, service_id: str, env: dict[str, str]) -> None:
        if env:
            self.service_extension(service_id).env.update(env)

    @staticmethod
    def runtime_payload(
        *,
        key: str,
        mount_path: str,
        source_path: str,
    ) -> SecurityPayloadSpec:
        return SecurityPayloadSpec(
            key=key,
            mountPath=mount_path,
            source_path=source_path,
        )

    def build(self) -> SecurityRuntimeSpec:
        return SecurityRuntimeSpec(
            tier=self.tier,
            identity_provider=self.identity_provider,
            encryption=self.encryption,
            mtls=self.mtls,
            npc_credential_lifecycle=self.npc_credential_lifecycle,
            service_runtime={
                service_id: SecurityServiceRuntimeSpec(
                    env=dict(extension.env),
                    payloads=tuple(extension.payloads),
                    ports=tuple(extension.ports),
                    sidecars=tuple(extension.sidecars),
                )
                for service_id, extension in self.service_runtime.items()
            },
        )


# ---------------------------------------------------------------------------
# Integrator
# ---------------------------------------------------------------------------


class SecurityIntegrator:
    """Build security runtime intent from a world and security tier.

    Usage::

        integrator = SecurityIntegrator(SecurityIntegratorConfig(enabled=True))
        runtime = integrator.plan(world, tier=2)
    """

    def __init__(self, config: SecurityIntegratorConfig | None = None) -> None:
        self.config = config or SecurityIntegratorConfig()

    def plan(
        self,
        world: WorldIR,
        *,
        tier: int = 1,
    ) -> SecurityRuntimeSpec:
        """Build a security runtime plan that can be attached to ``WorldIR``."""
        ctx = SecurityContext(tier=tier)

        if not self.config.enabled:
            return ctx.build()

        rng = random.Random(f"{world.world_id}:{world.seed}:{tier}")
        tier_cfg = self.config.tier_map.get(
            tier,
            self.config.tier_map.get(max(self.config.tier_map), SecurityTierConfig()),
        )

        # Build service→zone mapping from WorldIR
        services: dict[str, str] = {}
        service_kinds: dict[str, str] = {}
        service_dependencies: dict[str, tuple[str, ...]] = {}
        host_by_id = {h.id: h for h in world.hosts}
        for svc in world.services:
            zone = host_by_id[svc.host].zone if svc.host in host_by_id else "default"
            services[svc.id] = zone
            service_kinds[svc.id] = svc.kind
            service_dependencies[svc.id] = tuple(svc.dependencies)

        domain = "range.local"

        if tier_cfg.identity_provider:
            self._integrate_identity(ctx, world, services, domain)

        if tier_cfg.envelope_encryption:
            self._integrate_encryption(ctx, world, services, rng)

        if tier_cfg.mtls:
            self._integrate_mtls(
                ctx,
                services,
                service_kinds,
                service_dependencies,
                domain,
                rng,
            )

        if tier_cfg.npc_credential_lifecycle:
            self._integrate_npc_lifecycle(ctx)

        logger.info(
            "SecurityIntegrator: planned security runtime (tier=%d, idp=%s, enc=%s, mtls=%s, npc=%s)",
            tier,
            tier_cfg.identity_provider,
            tier_cfg.envelope_encryption,
            tier_cfg.mtls,
            tier_cfg.npc_credential_lifecycle,
        )
        return ctx.build()

    def integrate(
        self,
        world: WorldIR,
        *,
        tier: int = 1,
        render_dir: object | None = None,
    ) -> SecurityRuntimeSpec:
        """Backward-compatible helper for callers still expecting file output."""

        runtime = self.plan(world, tier=tier)
        if render_dir is not None:
            render_world = world.model_copy(update={"security_runtime": runtime})
            materialize_security_runtime(render_world, Path(render_dir))
        return runtime

    # ------------------------------------------------------------------
    # Identity Provider
    # ------------------------------------------------------------------

    def _integrate_identity(
        self,
        ctx: SecurityContext,
        world: WorldIR,
        services: dict[str, str],
        domain: str,
    ) -> None:
        """Declare identity provider runtime intent."""
        try:
            from open_range.identity_provider import (
                IdentityProviderConfig,
                ServiceIdentity,
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

        idp_targets = [
            service.id for service in world.services if service.kind == "idp"
        ]
        if idp_targets:
            idp_id = idp_targets[0]
            ctx.append_payload(
                idp_id,
                ctx.runtime_payload(
                    key="security-idp-config.json",
                    mount_path="/etc/openrange/identity-provider.json",
                    source_path="security/idp/config.json",
                ),
            )
            ctx.append_payload(
                idp_id,
                ctx.runtime_payload(
                    key="security-idp-startup.sh",
                    mount_path="/opt/openrange/start_identity_provider.sh",
                    source_path="security/idp/startup.sh",
                ),
            )
            ctx.append_payload(
                idp_id,
                ctx.runtime_payload(
                    key="security-idp-server.py",
                    mount_path="/opt/openrange/identity_provider_server.py",
                    source_path="security/idp/identity_provider_server.py",
                ),
            )
            ctx.append_port(
                idp_id,
                RuntimePort(
                    name="idp-token",
                    port=int(
                        idp_config.token_endpoint_port
                        if hasattr(idp_config, "token_endpoint_port")
                        else 8443
                    ),
                ),
            )
            ctx.append_sidecar(
                idp_id,
                RuntimeSidecar(
                    name="idp-helper",
                    image_source="service",
                    command=("/bin/sh", "/opt/openrange/start_identity_provider.sh"),
                    include_service_payloads=True,
                ),
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
        services: dict[str, str],
        rng: random.Random,
    ) -> None:
        """Declare envelope encryption runtime intent."""
        try:
            from open_range.envelope_crypto import EncryptionConfig
        except ImportError:
            logger.warning(
                "envelope_crypto module not available; skipping encryption integration"
            )
            return

        # Encrypt a subset of credential secret_refs
        import math

        credentials = list(world.credentials)
        if not credentials:
            return

        n_encrypt = max(
            1, math.ceil(len(credentials) * self.config.encryption_fraction)
        )
        indices = rng.sample(
            list(range(len(credentials))),
            min(n_encrypt, len(credentials)),
        )

        encrypted_refs: list[str] = []
        for idx in indices:
            encrypted_refs.append(credentials[idx].id)

        if encrypted_refs:
            enc_config = EncryptionConfig(
                enabled=True,
                encrypted_paths=encrypted_refs,
                master_key_source="file",
                dek_storage_path="/etc/openrange/wrapped_dek.json",
            )
            ctx.encryption = enc_config.model_dump()

            for svc_name in services:
                ctx.append_payload(
                    svc_name,
                    ctx.runtime_payload(
                        key="security-encryption-config.json",
                        mount_path="/etc/openrange/encryption-config.json",
                        source_path="security/encryption/config.json",
                    ),
                )
                ctx.append_payload(
                    svc_name,
                    ctx.runtime_payload(
                        key="security-wrapped-dek.json",
                        mount_path="/etc/openrange/wrapped_dek.json",
                        source_path="security/encryption/wrapped_dek.json",
                    ),
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
        service_kinds: dict[str, str],
        service_dependencies: dict[str, tuple[str, ...]],
        domain: str,
        rng: random.Random,
    ) -> None:
        """Declare mTLS artifacts plus supported runtime hooks for services."""
        try:
            from open_range.mtls_sim import MTLSConfig, MTLSSimulator
        except ImportError:
            logger.warning("mtls_sim module not available; skipping mTLS integration")
            return

        mtls_services = [svc for svc in services if svc not in ("attacker", "siem")]
        if not mtls_services:
            return

        weaknesses: dict[str, list[str]] = {}
        if mtls_services and self.config.mtls_weakness_pool:
            target_svc = rng.choice(mtls_services)
            weakness = rng.choice(self.config.mtls_weakness_pool)
            weaknesses[target_svc] = [weakness]

        mtls_config = MTLSConfig(
            enabled=True,
            mtls_services=mtls_services,
            weaknesses=weaknesses,
        )
        for svc_name in mtls_services:
            ctx.append_payload(
                svc_name,
                ctx.runtime_payload(
                    key="security-mtls-ca.pem",
                    mount_path="/etc/mtls/ca.pem",
                    source_path=f"security/mtls/{svc_name}/ca.pem",
                ),
            )
            ctx.append_payload(
                svc_name,
                ctx.runtime_payload(
                    key="security-mtls-cert.pem",
                    mount_path="/etc/mtls/cert.pem",
                    source_path=f"security/mtls/{svc_name}/cert.pem",
                ),
            )
            ctx.append_payload(
                svc_name,
                ctx.runtime_payload(
                    key="security-mtls-key.pem",
                    mount_path="/etc/mtls/key.pem",
                    source_path=f"security/mtls/{svc_name}/key.pem",
                ),
            )
            service_kind = service_kinds.get(svc_name, "")
            if service_kind == "idp":
                ctx.extend_env(svc_name, MTLSSimulator.get_service_tls_env("openldap"))
                ctx.append_payload(
                    svc_name,
                    ctx.runtime_payload(
                        key="security-mtls-openldap-ca.crt",
                        mount_path="/container/service/slapd/assets/certs/ca.crt",
                        source_path=f"security/mtls/{svc_name}/ca.pem",
                    ),
                )
                ctx.append_payload(
                    svc_name,
                    ctx.runtime_payload(
                        key="security-mtls-openldap-ldap.crt",
                        mount_path="/container/service/slapd/assets/certs/ldap.crt",
                        source_path=f"security/mtls/{svc_name}/cert.pem",
                    ),
                )
                ctx.append_payload(
                    svc_name,
                    ctx.runtime_payload(
                        key="security-mtls-openldap-ldap.key",
                        mount_path="/container/service/slapd/assets/certs/ldap.key",
                        source_path=f"security/mtls/{svc_name}/key.pem",
                    ),
                )
                ctx.append_port(svc_name, RuntimePort(name="ldaps", port=636))
            if service_kind == "db":
                ctx.append_payload(
                    svc_name,
                    ctx.runtime_payload(
                        key="security-mtls-mysql.cnf",
                        mount_path="/etc/mysql/conf.d/openrange-mtls.cnf",
                        source_path=f"security/mtls/{svc_name}/mysql.cnf",
                    ),
                )
                ctx.append_payload(
                    svc_name,
                    ctx.runtime_payload(
                        key="security-mtls-mysql-init.sql",
                        mount_path="/docker-entrypoint-initdb.d/02-openrange-mtls.sql",
                        source_path=f"security/mtls/{svc_name}/mysql-init.sql",
                    ),
                )
            if "svc-db" in service_dependencies.get(svc_name, ()):
                ctx.append_payload(
                    svc_name,
                    ctx.runtime_payload(
                        key="security-mtls-mysql-client.cnf",
                        mount_path="/etc/mysql/conf.d/openrange-client-mtls.cnf",
                        source_path=f"security/mtls/{svc_name}/mysql-client.cnf",
                    ),
                )
            if service_kind == "web_app" and "svc-db" in service_dependencies.get(
                svc_name, ()
            ):
                ctx.append_sidecar(
                    svc_name,
                    RuntimeSidecar(
                        name="db-client-mtls",
                        image=DB_MTLS_HELPER_IMAGE,
                        command=("/bin/sh", "-lc", "sleep infinity"),
                        include_service_payloads=True,
                    ),
                )

        ctx.mtls = mtls_config.model_dump()

        logger.debug(
            "mTLS integrated: %d services, weaknesses=%s",
            len(mtls_services),
            weaknesses,
        )

    # ------------------------------------------------------------------
    # NPC Credential Lifecycle
    # ------------------------------------------------------------------

    def _integrate_npc_lifecycle(
        self,
        ctx: SecurityContext,
    ) -> None:
        """Declare NPC credential lifecycle runtime intent."""
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

        logger.debug(
            "NPC credential lifecycle integrated: weaknesses=%s",
            self.config.npc_weaknesses,
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _default_scopes_for_service(service_name: str) -> list[str]:
    """Return default authorization scopes for a service."""
    normalized = service_name.removeprefix("svc-").removeprefix("sandbox-")
    scope_map: dict[str, list[str]] = {
        "web": ["data:read:patients/*", "data:read:referrals/*", "api:access:portal"],
        "db": ["data:read:*", "data:write:*"],
        "ldap": ["auth:bind:*", "auth:search:*"],
        "mail": ["mail:send:*", "mail:read:*"],
        "files": ["file:read:general/*", "file:read:hr/*"],
        "siem": ["log:read:*", "log:write:*", "alert:read:*"],
    }
    return scope_map.get(normalized, [f"service:access:{normalized}"])
