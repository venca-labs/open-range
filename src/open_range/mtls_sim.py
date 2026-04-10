"""Simulated mTLS certificate infrastructure for range services.

Generates self-signed CA and per-service TLS certificates with configurable
weaknesses that Red agents must exploit and Blue agents must detect.

Ported from k3s-istio-vault-platform's Istio PeerAuthentication (STRICT mTLS)
and SPIFFE mTLS proxy patterns.  In production Istio, every pod gets an
x509-SVID via the Citadel CA and the mesh enforces mutual authentication.
Here we simulate the same topology with deliberately breakable certificates
so agents learn to assess TLS health.

Weaknesses catalogue
--------------------
- ``expired_cert``    : notAfter in the past — Red detects with ``openssl s_client``
- ``weak_key_1024``   : 1024-bit RSA key — weak, factorable with sufficient compute
- ``no_client_verify``: missing clientAuth EKU — server won't demand client cert
- ``wrong_san``       : SAN mismatches the service hostname
- ``self_signed``     : cert signed by a *different* CA (trust-chain break)
"""

from __future__ import annotations

import datetime
import logging
from typing import Any

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Attempt to import cryptography; fall back to None so callers can check.
# ---------------------------------------------------------------------------

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

    _HAS_CRYPTOGRAPHY = True
except ImportError:  # pragma: no cover — only when library absent
    _HAS_CRYPTOGRAPHY = False

# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------


class MTLSConfig(BaseModel):
    """Configuration for mTLS between range services."""

    enabled: bool = False
    ca_common_name: str = "OpenRange Internal CA"
    cert_validity_days: int = 365
    key_size: int = 2048
    # Services that require mTLS for incoming connections
    mtls_services: list[str] = Field(default_factory=list)
    # e.g. ["db", "ldap", "files"]
    # Configurable weaknesses per service
    weaknesses: dict[str, list[str]] = Field(default_factory=dict)
    # e.g. {"db": ["expired_cert"], "ldap": ["no_client_verify"], "files": ["weak_key_1024"]}


class CertificateBundle(BaseModel):
    """Generated certificate material for a service."""

    service_name: str
    ca_cert_pem: str
    cert_pem: str
    key_pem: str
    # Weakness applied (if any)
    weakness: str | None = None


# Supported weakness identifiers (used for validation).
SUPPORTED_WEAKNESSES: frozenset[str] = frozenset(
    {
        "expired_cert",
        "weak_key_1024",
        "no_client_verify",
        "wrong_san",
        "self_signed",
    }
)

# Service-specific TLS environment variable mappings.
_SERVICE_TLS_ENV: dict[str, dict[str, str]] = {
    "mysql": {
        "SSL_CERT": "/etc/mtls/cert.pem",
        "SSL_KEY": "/etc/mtls/key.pem",
        "SSL_CA": "/etc/mtls/ca.pem",
        "require_secure_transport": "ON",
    },
    "db": {
        "SSL_CERT": "/etc/mtls/cert.pem",
        "SSL_KEY": "/etc/mtls/key.pem",
        "SSL_CA": "/etc/mtls/ca.pem",
        "require_secure_transport": "ON",
    },
    "nginx": {
        "ssl_certificate": "/etc/mtls/cert.pem",
        "ssl_certificate_key": "/etc/mtls/key.pem",
        "ssl_client_certificate": "/etc/mtls/ca.pem",
    },
    "web": {
        "ssl_certificate": "/etc/mtls/cert.pem",
        "ssl_certificate_key": "/etc/mtls/key.pem",
        "ssl_client_certificate": "/etc/mtls/ca.pem",
    },
    "ldap": {
        "LDAP_TLS_CRT_FILENAME": "ldap.crt",
        "LDAP_TLS_KEY_FILENAME": "ldap.key",
        "LDAP_TLS_CA_CRT_FILENAME": "ca.crt",
        "LDAP_TLS_VERIFY_CLIENT": "demand",
    },
    "openldap": {
        "LDAP_TLS_CRT_FILENAME": "ldap.crt",
        "LDAP_TLS_KEY_FILENAME": "ldap.key",
        "LDAP_TLS_CA_CRT_FILENAME": "ca.crt",
        "LDAP_TLS_VERIFY_CLIENT": "demand",
    },
}


class MTLSSimulator:
    """Generate CA and per-service TLS certificates for range mTLS.

    Ported from k3s-istio-vault-platform's Istio PeerAuthentication
    and SPIFFE mTLS patterns.  Generates:

    - Self-signed root CA
    - Per-service server certificates with SANs
    - Per-service client certificates for mutual auth
    - Configurable weaknesses for Red to exploit

    Requires the ``cryptography`` library.  If not installed, instantiation
    raises :class:`RuntimeError` with installation instructions.
    """

    def __init__(self, config: MTLSConfig) -> None:
        if not _HAS_CRYPTOGRAPHY:
            raise RuntimeError(
                "The 'cryptography' package is required for mTLS simulation. "
                "Install it with: pip install cryptography"
            )
        self.config = config
        self._ca_cert: bytes | None = None
        self._ca_key: Any = None

    # ------------------------------------------------------------------
    # CA generation
    # ------------------------------------------------------------------

    def generate_ca(self) -> tuple[bytes, bytes]:
        """Generate a root CA cert + key.

        Returns ``(ca_cert_pem, ca_key_pem)`` as PEM-encoded bytes.
        The CA is cached on the instance for subsequent service cert calls.
        """
        ca_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=self.config.key_size,
        )

        subject = issuer = x509.Name(
            [
                x509.NameAttribute(NameOID.COMMON_NAME, self.config.ca_common_name),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "OpenRange"),
            ]
        )

        now = datetime.datetime.now(datetime.timezone.utc)
        ca_cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(
                now + datetime.timedelta(days=self.config.cert_validity_days * 2)
            )
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=None),
                critical=True,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_cert_sign=True,
                    crl_sign=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .sign(ca_key, hashes.SHA256())
        )

        self._ca_cert = ca_cert.public_bytes(serialization.Encoding.PEM)
        self._ca_key = ca_key

        ca_key_pem = ca_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )

        return self._ca_cert, ca_key_pem

    # ------------------------------------------------------------------
    # Per-service certificate generation
    # ------------------------------------------------------------------

    def generate_service_cert(
        self,
        service_name: str,
        zone: str,
        domain: str = "range.local",
        weakness: str | None = None,
    ) -> CertificateBundle:
        """Generate a certificate for a service.

        SANs include:
        - ``{service}.{zone}.svc.cluster.local``
        - ``{service}.{zone}``

        Weaknesses:
        - ``"expired_cert"``    : cert already expired (notAfter in the past)
        - ``"weak_key_1024"``    : use 512-bit RSA (easily factorable)
        - ``"no_client_verify"``: omit clientAuth extended key usage
        - ``"wrong_san"``       : SAN doesn't match service hostname
        - ``"self_signed"``     : use a different CA (trust-chain break)
        """
        if weakness and weakness not in SUPPORTED_WEAKNESSES:
            raise ValueError(
                f"Unknown weakness {weakness!r}. "
                f"Supported: {sorted(SUPPORTED_WEAKNESSES)}"
            )

        # Ensure CA exists
        if self._ca_cert is None or self._ca_key is None:
            self.generate_ca()

        signing_key = self._ca_key
        ca_cert_pem = self._ca_cert

        # --- Determine key size ---
        key_size = self.config.key_size
        if weakness == "weak_key_1024":
            key_size = 1024

        service_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
        )

        # --- Build SANs ---
        if weakness == "wrong_san":
            sans = [
                x509.DNSName(f"wrong-service.{zone}.svc.cluster.local"),
                x509.DNSName(f"wrong-service.{zone}"),
            ]
        else:
            sans = [
                x509.DNSName(f"{service_name}.{zone}.svc.cluster.local"),
                x509.DNSName(f"{service_name}.{zone}"),
            ]

        # --- Determine validity window ---
        now = datetime.datetime.now(datetime.timezone.utc)
        if weakness == "expired_cert":
            not_valid_before = now - datetime.timedelta(days=730)
            not_valid_after = now - datetime.timedelta(days=1)
        else:
            not_valid_before = now
            not_valid_after = now + datetime.timedelta(
                days=self.config.cert_validity_days
            )

        # --- Handle self_signed weakness (different CA) ---
        if weakness == "self_signed":
            rogue_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=self.config.key_size,
            )
            rogue_ca_name = x509.Name(
                [
                    x509.NameAttribute(NameOID.COMMON_NAME, "Rogue CA"),
                    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Untrusted"),
                ]
            )
            rogue_ca_cert = (
                x509.CertificateBuilder()
                .subject_name(rogue_ca_name)
                .issuer_name(rogue_ca_name)
                .public_key(rogue_key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now)
                .not_valid_after(now + datetime.timedelta(days=365))
                .add_extension(
                    x509.BasicConstraints(ca=True, path_length=None),
                    critical=True,
                )
                .sign(rogue_key, hashes.SHA256())
            )
            signing_key = rogue_key
            ca_cert_pem = rogue_ca_cert.public_bytes(serialization.Encoding.PEM)

        # --- Build EKU list ---
        eku_list = [ExtendedKeyUsageOID.SERVER_AUTH]
        if weakness != "no_client_verify":
            eku_list.append(ExtendedKeyUsageOID.CLIENT_AUTH)

        # --- Assemble certificate ---
        subject = x509.Name(
            [
                x509.NameAttribute(NameOID.COMMON_NAME, f"{service_name}.{domain}"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "OpenRange"),
            ]
        )

        # Issuer name from the signing CA
        if weakness == "self_signed":
            issuer_name = x509.Name(
                [
                    x509.NameAttribute(NameOID.COMMON_NAME, "Rogue CA"),
                    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Untrusted"),
                ]
            )
        else:
            issuer_name = x509.Name(
                [
                    x509.NameAttribute(NameOID.COMMON_NAME, self.config.ca_common_name),
                    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "OpenRange"),
                ]
            )

        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer_name)
            .public_key(service_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(not_valid_before)
            .not_valid_after(not_valid_after)
            .add_extension(
                x509.SubjectAlternativeName(sans),
                critical=False,
            )
            .add_extension(
                x509.ExtendedKeyUsage(eku_list),
                critical=False,
            )
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True,
            )
            .sign(signing_key, hashes.SHA256())
        )

        cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
        key_pem = service_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        ).decode()

        return CertificateBundle(
            service_name=service_name,
            ca_cert_pem=ca_cert_pem.decode()
            if isinstance(ca_cert_pem, bytes)
            else ca_cert_pem,
            cert_pem=cert_pem,
            key_pem=key_pem,
            weakness=weakness,
        )

    # ------------------------------------------------------------------
    # Bulk generation
    # ------------------------------------------------------------------

    def generate_all_certs(
        self,
        services: dict[str, Any],
        zones: dict[str, Any],
    ) -> dict[str, CertificateBundle]:
        """Generate certificates for all mTLS-enabled services.

        Parameters
        ----------
        services:
            Mapping of service names to service config dicts (from topology
            or the rendered Helm values).
        zones:
            Mapping of zone names to lists of hosts in that zone.

        Returns a dict mapping service names to their :class:`CertificateBundle`.
        """
        if not self.config.enabled:
            return {}

        # Ensure CA
        if self._ca_cert is None:
            self.generate_ca()

        # Build reverse map: host -> zone
        host_to_zone: dict[str, str] = {}
        for zone_name, zone_hosts in zones.items():
            if isinstance(zone_hosts, list):
                for h in zone_hosts:
                    host_name = h if isinstance(h, str) else str(h)
                    host_to_zone[host_name] = zone_name

        bundles: dict[str, CertificateBundle] = {}
        mtls_set = set(self.config.mtls_services)

        for svc_name in services:
            if mtls_set and svc_name not in mtls_set:
                continue

            zone = host_to_zone.get(svc_name, "default")
            weaknesses = self.config.weaknesses.get(svc_name, [])
            # Apply the first configured weakness (one per cert).
            weakness = weaknesses[0] if weaknesses else None

            bundles[svc_name] = self.generate_service_cert(
                service_name=svc_name,
                zone=zone,
                weakness=weakness,
            )

        return bundles

    # ------------------------------------------------------------------
    # Payload integration
    # ------------------------------------------------------------------

    @staticmethod
    def get_payload_files(bundle: CertificateBundle) -> list[dict[str, str]]:
        """Convert a :class:`CertificateBundle` into payload file entries.

        Returns entries compatible with the Helm chart payload format used
        by :meth:`KindRenderer._service_payloads`:

        .. code-block:: python

            [
                {"key": "ca.pem",   "mountPath": "/etc/mtls/ca.pem",   "content": ...},
                {"key": "cert.pem", "mountPath": "/etc/mtls/cert.pem", "content": ...},
                {"key": "key.pem",  "mountPath": "/etc/mtls/key.pem",  "content": ...},
            ]
        """
        return [
            {
                "key": "ca.pem",
                "mountPath": "/etc/mtls/ca.pem",
                "content": bundle.ca_cert_pem,
            },
            {
                "key": "cert.pem",
                "mountPath": "/etc/mtls/cert.pem",
                "content": bundle.cert_pem,
            },
            {
                "key": "key.pem",
                "mountPath": "/etc/mtls/key.pem",
                "content": bundle.key_pem,
            },
        ]

    @staticmethod
    def get_service_tls_env(service_name: str) -> dict[str, str]:
        """Return environment variables to enable TLS for a service.

        Supported services and their env vars:

        - **MySQL / db** : ``SSL_CERT``, ``SSL_KEY``, ``SSL_CA``, ``require_secure_transport``
        - **nginx / web** : ``ssl_certificate``, ``ssl_certificate_key``, ``ssl_client_certificate``
        - **LDAP / openldap** : image-native TLS filenames such as
          ``LDAP_TLS_CRT_FILENAME`` and ``LDAP_TLS_CA_CRT_FILENAME``

        Returns an empty dict for unknown services.
        """
        return dict(_SERVICE_TLS_ENV.get(service_name, {}))
