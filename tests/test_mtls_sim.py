"""Tests for mTLS simulation — CA generation, service certs, weaknesses, and payloads."""

from __future__ import annotations

import datetime

import pytest

pytest.importorskip("cryptography", reason="cryptography not installed")

from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import rsa  # noqa: E402
from cryptography.hazmat.primitives.serialization import load_pem_private_key  # noqa: E402
from cryptography.x509.oid import ExtendedKeyUsageOID  # noqa: E402

from open_range.mtls_sim import (  # noqa: E402
    SUPPORTED_WEAKNESSES,
    CertificateBundle,
    MTLSConfig,
    MTLSSimulator,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _parse_cert(pem: str) -> x509.Certificate:
    """Parse a PEM-encoded certificate string."""
    return x509.load_pem_x509_certificate(pem.encode())


def _parse_key(pem: str) -> rsa.RSAPrivateKey:
    """Parse a PEM-encoded RSA private key string."""
    return load_pem_private_key(pem.encode(), password=None)


# ---------------------------------------------------------------------------
# MTLSConfig model validation
# ---------------------------------------------------------------------------


class TestMTLSConfig:
    def test_defaults(self):
        config = MTLSConfig()
        assert config.enabled is False
        assert config.ca_common_name == "OpenRange Internal CA"
        assert config.cert_validity_days == 365
        assert config.key_size == 2048
        assert config.mtls_services == []
        assert config.weaknesses == {}

    def test_custom_values(self):
        config = MTLSConfig(
            enabled=True,
            ca_common_name="Test CA",
            cert_validity_days=30,
            key_size=4096,
            mtls_services=["db", "ldap"],
            weaknesses={"db": ["expired_cert"], "ldap": ["no_client_verify"]},
        )
        assert config.enabled is True
        assert config.ca_common_name == "Test CA"
        assert config.key_size == 4096
        assert "db" in config.mtls_services
        assert config.weaknesses["db"] == ["expired_cert"]

    def test_model_serialization_roundtrip(self):
        config = MTLSConfig(
            enabled=True,
            mtls_services=["web"],
            weaknesses={"web": ["wrong_san"]},
        )
        data = config.model_dump()
        restored = MTLSConfig(**data)
        assert restored == config


# ---------------------------------------------------------------------------
# CA generation
# ---------------------------------------------------------------------------


class TestCAGeneration:
    def test_generates_valid_x509_ca(self):
        sim = MTLSSimulator(MTLSConfig())
        ca_cert_pem, ca_key_pem = sim.generate_ca()

        assert b"BEGIN CERTIFICATE" in ca_cert_pem
        assert b"BEGIN RSA PRIVATE KEY" in ca_key_pem

        cert = x509.load_pem_x509_certificate(ca_cert_pem)
        assert cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[
            0
        ].value == ("OpenRange Internal CA")

    def test_ca_has_basic_constraints(self):
        sim = MTLSSimulator(MTLSConfig())
        ca_cert_pem, _ = sim.generate_ca()
        cert = x509.load_pem_x509_certificate(ca_cert_pem)

        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints)
        assert bc.value.ca is True

    def test_ca_uses_configured_common_name(self):
        config = MTLSConfig(ca_common_name="My Custom CA")
        sim = MTLSSimulator(config)
        ca_cert_pem, _ = sim.generate_ca()
        cert = x509.load_pem_x509_certificate(ca_cert_pem)

        cn = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value
        assert cn == "My Custom CA"

    def test_ca_key_size_matches_config(self):
        config = MTLSConfig(key_size=4096)
        sim = MTLSSimulator(config)
        _, ca_key_pem = sim.generate_ca()
        key = load_pem_private_key(ca_key_pem, password=None)
        assert key.key_size == 4096

    def test_ca_is_cached_on_instance(self):
        sim = MTLSSimulator(MTLSConfig())
        ca_cert_pem_1, _ = sim.generate_ca()
        # After first call, internal state is set.
        assert sim._ca_cert is not None
        assert sim._ca_key is not None


# ---------------------------------------------------------------------------
# Service certificate generation
# ---------------------------------------------------------------------------


class TestServiceCert:
    def test_basic_service_cert_has_correct_sans(self):
        sim = MTLSSimulator(MTLSConfig())
        sim.generate_ca()

        bundle = sim.generate_service_cert("db", zone="internal")

        cert = _parse_cert(bundle.cert_pem)
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        dns_names = san.value.get_values_for_type(x509.DNSName)

        assert "db.internal.svc.cluster.local" in dns_names
        assert "db.internal" in dns_names

    def test_service_cert_has_server_and_client_auth(self):
        sim = MTLSSimulator(MTLSConfig())
        sim.generate_ca()
        bundle = sim.generate_service_cert("web", zone="dmz")

        cert = _parse_cert(bundle.cert_pem)
        eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
        oid_list = list(eku.value)

        assert ExtendedKeyUsageOID.SERVER_AUTH in oid_list
        assert ExtendedKeyUsageOID.CLIENT_AUTH in oid_list

    def test_service_cert_common_name(self):
        sim = MTLSSimulator(MTLSConfig())
        sim.generate_ca()
        bundle = sim.generate_service_cert(
            "ldap", zone="management", domain="acme.local"
        )

        cert = _parse_cert(bundle.cert_pem)
        cn = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value
        assert cn == "ldap.acme.local"

    def test_service_cert_not_ca(self):
        sim = MTLSSimulator(MTLSConfig())
        sim.generate_ca()
        bundle = sim.generate_service_cert("web", zone="dmz")

        cert = _parse_cert(bundle.cert_pem)
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints)
        assert bc.value.ca is False

    def test_service_cert_auto_generates_ca(self):
        """If generate_ca() was not called, generate_service_cert() does it."""
        sim = MTLSSimulator(MTLSConfig())
        bundle = sim.generate_service_cert("db", zone="internal")
        assert bundle.ca_cert_pem
        assert bundle.cert_pem
        assert sim._ca_cert is not None

    def test_bundle_fields(self):
        sim = MTLSSimulator(MTLSConfig())
        bundle = sim.generate_service_cert("db", zone="internal")
        assert bundle.service_name == "db"
        assert bundle.weakness is None
        assert isinstance(bundle, CertificateBundle)


# ---------------------------------------------------------------------------
# Weakness: expired_cert
# ---------------------------------------------------------------------------


class TestWeaknessExpiredCert:
    def test_expired_cert_has_past_not_after(self):
        sim = MTLSSimulator(MTLSConfig())
        sim.generate_ca()
        bundle = sim.generate_service_cert(
            "db", zone="internal", weakness="expired_cert"
        )

        cert = _parse_cert(bundle.cert_pem)
        now = datetime.datetime.now(datetime.timezone.utc)
        assert cert.not_valid_after_utc < now

    def test_expired_cert_recorded_in_bundle(self):
        sim = MTLSSimulator(MTLSConfig())
        bundle = sim.generate_service_cert(
            "db", zone="internal", weakness="expired_cert"
        )
        assert bundle.weakness == "expired_cert"


# ---------------------------------------------------------------------------
# Weakness: weak_key_1024
# ---------------------------------------------------------------------------


class TestWeaknessWeakKey:
    def test_weak_key_1024_produces_1024_bit_key(self):
        sim = MTLSSimulator(MTLSConfig())
        sim.generate_ca()
        bundle = sim.generate_service_cert(
            "files", zone="internal", weakness="weak_key_1024"
        )

        key = _parse_key(bundle.key_pem)
        assert key.key_size == 1024

    def test_weak_key_1024_cert_still_valid_x509(self):
        sim = MTLSSimulator(MTLSConfig())
        sim.generate_ca()
        bundle = sim.generate_service_cert(
            "files", zone="internal", weakness="weak_key_1024"
        )

        # Should still parse as valid X.509
        cert = _parse_cert(bundle.cert_pem)
        assert cert.subject is not None


# ---------------------------------------------------------------------------
# Weakness: no_client_verify
# ---------------------------------------------------------------------------


class TestWeaknessNoClientVerify:
    def test_no_client_verify_omits_client_auth_eku(self):
        sim = MTLSSimulator(MTLSConfig())
        sim.generate_ca()
        bundle = sim.generate_service_cert(
            "ldap", zone="management", weakness="no_client_verify"
        )

        cert = _parse_cert(bundle.cert_pem)
        eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
        oid_list = list(eku.value)

        assert ExtendedKeyUsageOID.SERVER_AUTH in oid_list
        assert ExtendedKeyUsageOID.CLIENT_AUTH not in oid_list


# ---------------------------------------------------------------------------
# Weakness: wrong_san
# ---------------------------------------------------------------------------


class TestWeaknessWrongSAN:
    def test_wrong_san_does_not_match_service_name(self):
        sim = MTLSSimulator(MTLSConfig())
        sim.generate_ca()
        bundle = sim.generate_service_cert("web", zone="dmz", weakness="wrong_san")

        cert = _parse_cert(bundle.cert_pem)
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        dns_names = san.value.get_values_for_type(x509.DNSName)

        assert "web.dmz.svc.cluster.local" not in dns_names
        assert "web.dmz" not in dns_names
        # Should contain the "wrong" service name instead
        assert any("wrong-service" in n for n in dns_names)


# ---------------------------------------------------------------------------
# Weakness: self_signed
# ---------------------------------------------------------------------------


class TestWeaknessSelfSigned:
    def test_self_signed_uses_different_ca(self):
        sim = MTLSSimulator(MTLSConfig())
        sim.generate_ca()

        normal_bundle = sim.generate_service_cert("db", zone="internal")
        rogue_bundle = sim.generate_service_cert(
            "files", zone="internal", weakness="self_signed"
        )

        # The CA certs should differ
        assert normal_bundle.ca_cert_pem != rogue_bundle.ca_cert_pem

        # The rogue cert should be signed by a "Rogue CA"
        rogue_ca = _parse_cert(rogue_bundle.ca_cert_pem)
        cn = rogue_ca.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[
            0
        ].value
        assert cn == "Rogue CA"


# ---------------------------------------------------------------------------
# Weakness: unknown weakness raises
# ---------------------------------------------------------------------------


class TestWeaknessValidation:
    def test_unknown_weakness_raises_value_error(self):
        sim = MTLSSimulator(MTLSConfig())
        sim.generate_ca()
        with pytest.raises(ValueError, match="Unknown weakness"):
            sim.generate_service_cert("db", zone="internal", weakness="totally_fake")

    def test_supported_weaknesses_constant(self):
        assert "expired_cert" in SUPPORTED_WEAKNESSES
        assert "weak_key_1024" in SUPPORTED_WEAKNESSES
        assert "no_client_verify" in SUPPORTED_WEAKNESSES
        assert "wrong_san" in SUPPORTED_WEAKNESSES
        assert "self_signed" in SUPPORTED_WEAKNESSES
        assert len(SUPPORTED_WEAKNESSES) == 5


# ---------------------------------------------------------------------------
# Payload file generation
# ---------------------------------------------------------------------------


class TestPayloadFiles:
    def test_payload_files_structure(self):
        sim = MTLSSimulator(MTLSConfig())
        bundle = sim.generate_service_cert("db", zone="internal")

        payloads = MTLSSimulator.get_payload_files(bundle)

        assert len(payloads) == 3
        keys = {p["key"] for p in payloads}
        assert keys == {"ca.pem", "cert.pem", "key.pem"}

        mount_paths = {p["mountPath"] for p in payloads}
        assert mount_paths == {
            "/etc/mtls/ca.pem",
            "/etc/mtls/cert.pem",
            "/etc/mtls/key.pem",
        }

    def test_payload_content_matches_bundle(self):
        sim = MTLSSimulator(MTLSConfig())
        bundle = sim.generate_service_cert("web", zone="dmz")

        payloads = MTLSSimulator.get_payload_files(bundle)
        by_key = {p["key"]: p["content"] for p in payloads}

        assert by_key["ca.pem"] == bundle.ca_cert_pem
        assert by_key["cert.pem"] == bundle.cert_pem
        assert by_key["key.pem"] == bundle.key_pem

    def test_payload_files_contain_pem_markers(self):
        sim = MTLSSimulator(MTLSConfig())
        bundle = sim.generate_service_cert("db", zone="internal")

        payloads = MTLSSimulator.get_payload_files(bundle)
        by_key = {p["key"]: p["content"] for p in payloads}

        assert "BEGIN CERTIFICATE" in by_key["ca.pem"]
        assert "BEGIN CERTIFICATE" in by_key["cert.pem"]
        assert "BEGIN RSA PRIVATE KEY" in by_key["key.pem"]


# ---------------------------------------------------------------------------
# TLS environment variables
# ---------------------------------------------------------------------------


class TestServiceTLSEnv:
    def test_mysql_env(self):
        env = MTLSSimulator.get_service_tls_env("db")
        assert env["SSL_CERT"] == "/etc/mtls/cert.pem"
        assert env["SSL_KEY"] == "/etc/mtls/key.pem"
        assert env["SSL_CA"] == "/etc/mtls/ca.pem"
        assert env["require_secure_transport"] == "ON"

    def test_nginx_env(self):
        env = MTLSSimulator.get_service_tls_env("web")
        assert "ssl_certificate" in env
        assert "ssl_certificate_key" in env
        assert "ssl_client_certificate" in env

    def test_ldap_env(self):
        env = MTLSSimulator.get_service_tls_env("ldap")
        assert env["LDAP_TLS_CRT_FILENAME"] == "/etc/mtls/cert.pem"
        assert env["LDAP_TLS_VERIFY_CLIENT"] == "demand"

    def test_unknown_service_returns_empty(self):
        env = MTLSSimulator.get_service_tls_env("unknown_service")
        assert env == {}

    def test_returns_copy_not_reference(self):
        env1 = MTLSSimulator.get_service_tls_env("db")
        env2 = MTLSSimulator.get_service_tls_env("db")
        assert env1 == env2
        env1["extra"] = "mutated"
        assert "extra" not in env2


# ---------------------------------------------------------------------------
# Bulk generation (generate_all_certs)
# ---------------------------------------------------------------------------


class TestGenerateAllCerts:
    def test_disabled_returns_empty(self):
        config = MTLSConfig(enabled=False, mtls_services=["db"])
        sim = MTLSSimulator(config)
        result = sim.generate_all_certs(
            services={"db": {}, "web": {}},
            zones={"internal": ["db"], "dmz": ["web"]},
        )
        assert result == {}

    def test_generates_for_mtls_services_only(self):
        config = MTLSConfig(enabled=True, mtls_services=["db", "ldap"])
        sim = MTLSSimulator(config)
        result = sim.generate_all_certs(
            services={"db": {}, "web": {}, "ldap": {}},
            zones={"internal": ["db"], "dmz": ["web"], "management": ["ldap"]},
        )
        assert "db" in result
        assert "ldap" in result
        assert "web" not in result

    def test_applies_configured_weaknesses(self):
        config = MTLSConfig(
            enabled=True,
            mtls_services=["db", "ldap"],
            weaknesses={"db": ["expired_cert"], "ldap": ["weak_key_1024"]},
        )
        sim = MTLSSimulator(config)
        result = sim.generate_all_certs(
            services={"db": {}, "ldap": {}},
            zones={"internal": ["db"], "management": ["ldap"]},
        )
        assert result["db"].weakness == "expired_cert"
        assert result["ldap"].weakness == "weak_key_1024"

    def test_no_weakness_when_not_configured(self):
        config = MTLSConfig(enabled=True, mtls_services=["web"])
        sim = MTLSSimulator(config)
        result = sim.generate_all_certs(
            services={"web": {}},
            zones={"dmz": ["web"]},
        )
        assert result["web"].weakness is None

    def test_all_services_when_mtls_services_empty(self):
        config = MTLSConfig(enabled=True, mtls_services=[])
        sim = MTLSSimulator(config)
        result = sim.generate_all_certs(
            services={"db": {}, "web": {}},
            zones={"internal": ["db"], "dmz": ["web"]},
        )
        # When mtls_services is empty, all services in the services dict get certs.
        assert "db" in result
        assert "web" in result


# ---------------------------------------------------------------------------
# CertificateBundle model
# ---------------------------------------------------------------------------


class TestCertificateBundle:
    def test_bundle_model_fields(self):
        bundle = CertificateBundle(
            service_name="test",
            ca_cert_pem="ca",
            cert_pem="cert",
            key_pem="key",
            weakness="expired_cert",
        )
        assert bundle.service_name == "test"
        assert bundle.weakness == "expired_cert"

    def test_bundle_weakness_optional(self):
        bundle = CertificateBundle(
            service_name="test",
            ca_cert_pem="ca",
            cert_pem="cert",
            key_pem="key",
        )
        assert bundle.weakness is None

    def test_bundle_serialization_roundtrip(self):
        sim = MTLSSimulator(MTLSConfig())
        bundle = sim.generate_service_cert("db", zone="internal")
        data = bundle.model_dump()
        restored = CertificateBundle(**data)
        assert restored.cert_pem == bundle.cert_pem
        assert restored.service_name == bundle.service_name


# ---------------------------------------------------------------------------
# Validator check (v1 CheckFunc pattern)
# ---------------------------------------------------------------------------


def test_mtls_enforcement_passes_when_disabled(tmp_path):

    from open_range.mtls_enforcement import check_mtls_enforcement
    from open_range.snapshot import KindArtifacts

    # No security/mtls dir → passes immediately
    artifacts = KindArtifacts(
        render_dir=str(tmp_path),
        chart_dir=str(tmp_path / "chart"),
        values_path=str(tmp_path / "values.yaml"),
        kind_config_path=str(tmp_path / "kind-config.yaml"),
        manifest_summary_path=str(tmp_path / "summary.json"),
    )
    result = check_mtls_enforcement(None, artifacts)  # type: ignore[arg-type]
    assert result.passed is True


def test_mtls_enforcement_fails_missing_files(tmp_path):
    import json

    from open_range.mtls_enforcement import check_mtls_enforcement
    from open_range.snapshot import KindArtifacts

    mtls_dir = tmp_path / "security" / "mtls"
    mtls_dir.mkdir(parents=True)
    (mtls_dir / "config.json").write_text(
        json.dumps(
            {
                "enabled": True,
                "mtls_services": ["db"],
                "weaknesses": {"db": ["expired_cert"]},
            }
        )
    )
    # No cert files for db → should fail

    artifacts = KindArtifacts(
        render_dir=str(tmp_path),
        chart_dir=str(tmp_path / "chart"),
        values_path=str(tmp_path / "values.yaml"),
        kind_config_path=str(tmp_path / "kind-config.yaml"),
        manifest_summary_path=str(tmp_path / "summary.json"),
    )
    result = check_mtls_enforcement(None, artifacts)  # type: ignore[arg-type]
    assert result.passed is False


def test_mtls_enforcement_fails_no_weaknesses(tmp_path):
    import json

    from open_range.mtls_enforcement import check_mtls_enforcement
    from open_range.snapshot import KindArtifacts

    sim = MTLSSimulator(MTLSConfig())
    bundle = sim.generate_service_cert("db", zone="internal")

    mtls_dir = tmp_path / "security" / "mtls"
    mtls_dir.mkdir(parents=True)
    (mtls_dir / "config.json").write_text(
        json.dumps(
            {
                "enabled": True,
                "mtls_services": ["db"],
                "weaknesses": {},
            }
        )
    )
    svc_dir = mtls_dir / "db"
    svc_dir.mkdir()
    (svc_dir / "ca.pem").write_text(bundle.ca_cert_pem)
    (svc_dir / "cert.pem").write_text(bundle.cert_pem)
    (svc_dir / "key.pem").write_text(bundle.key_pem)

    artifacts = KindArtifacts(
        render_dir=str(tmp_path),
        chart_dir=str(tmp_path / "chart"),
        values_path=str(tmp_path / "values.yaml"),
        kind_config_path=str(tmp_path / "kind-config.yaml"),
        manifest_summary_path=str(tmp_path / "summary.json"),
    )
    result = check_mtls_enforcement(None, artifacts)  # type: ignore[arg-type]
    assert result.passed is False


def test_mtls_enforcement_passes_with_valid_config(tmp_path):
    import json

    from open_range.mtls_enforcement import check_mtls_enforcement
    from open_range.snapshot import KindArtifacts

    sim = MTLSSimulator(MTLSConfig())
    bundle = sim.generate_service_cert("db", zone="internal", weakness="expired_cert")

    mtls_dir = tmp_path / "security" / "mtls"
    mtls_dir.mkdir(parents=True)
    (mtls_dir / "config.json").write_text(
        json.dumps(
            {
                "enabled": True,
                "mtls_services": ["db"],
                "weaknesses": {"db": ["expired_cert"]},
            }
        )
    )
    svc_dir = mtls_dir / "db"
    svc_dir.mkdir()
    (svc_dir / "ca.pem").write_text(bundle.ca_cert_pem)
    (svc_dir / "cert.pem").write_text(bundle.cert_pem)
    (svc_dir / "key.pem").write_text(bundle.key_pem)

    artifacts = KindArtifacts(
        render_dir=str(tmp_path),
        chart_dir=str(tmp_path / "chart"),
        values_path=str(tmp_path / "values.yaml"),
        kind_config_path=str(tmp_path / "kind-config.yaml"),
        manifest_summary_path=str(tmp_path / "summary.json"),
    )
    result = check_mtls_enforcement(None, artifacts)  # type: ignore[arg-type]
    assert result.passed is True
