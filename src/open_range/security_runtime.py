"""Canonical security runtime plan stored on ``WorldIR``."""

from __future__ import annotations

import base64
import datetime
import hashlib
import json
from importlib.resources import files
from pathlib import Path
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel, ConfigDict, Field

from open_range.runtime_extensions import (
    RenderExtensions,
    RuntimePayload,
    RuntimePort,
    RuntimeSidecar,
    ServiceRuntimeExtension,
)

if TYPE_CHECKING:
    from open_range.world_ir import WorldIR


_DETERMINISTIC_CERT_EPOCH = datetime.datetime(2024, 1, 1, tzinfo=datetime.timezone.utc)
_MIN_RENDER_CERT_VALIDITY_DAYS = 3650


_STATIC_CA_PRIVATE_KEY_PEM = """-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAuhvpIJGaPyUf0YjDUbgPX9tj6kBbvQDuDZ7JbVOoV2/8haNi
gdZCKTLZWDkeCtXKFDitAW4LTSy0kNfQOEMyfG6O1fcDI2+D7GjHtG5EVg+yxGFl
nZq2+IZ0fcrLDdUEfGaQRzUACmqfd+fddYsGfNjP8PHtc8EwUgzlCUn6uXOiJ7mp
Iy+A6pnY4ANL01AmFVXVYA8KR1YGNJew9eDvwFiImnRILTqcnoHew9i9YRnsL2jf
9kSD8Aka0K+9CR3NrGAQvmFoM58uXtYcAcOr8rR/qO5cUuu0QXHYmqJWbp2y83M3
zrPWNeFGbxsiabKxD7vjZGPlofUyZV5Tctk7cQIDAQABAoIBAA8T4su6MBpsigri
Pxy4QjqcXhhk1WnXEPI2ipAaZnmK/5TeG0V0k9Cdp4Efw4DSODhyLQYAIddDR2+y
pFJik00EcfsAs5bj2nbFOGS0SEIGrI9/aomdtrQkxHxKeS/qMZ5YetjiANpXMAs5
VDZJKKHluNcG6ptlq+IB3G5nuXHbumocUypsiuUfxrZ6z+vJPJd/G4oIYMdxcbru
oigNv/3Aje53aY686GKX1IuP6QdMbwnDwoRrtEL/KsIxawDCAN2+e52Zl2XfafQU
hEI30HNQgNN8X/EZ2m3CRMY0RHU7Lw61KtDqTiYlBxrjuf72sq73BBggS5xoHVsD
Xa+5S6kCgYEA7U5UwInUCKtg/q9+Sv5AEpNT0b5CX0qRcspApvh6V2uzbVdxpS0B
lwPQ6Y9ZxSIqH+XbCpqjMfL5iTftQHTtyowZyKicrO4pdCbD3VPV/BI0A7rXhD/D
AdJTXMmFyCLA87Ike/+SQ2CvyyPA1eNAFgd6BnONk/sWdpfc0cLC1SUCgYEAyMUb
p+4cK+nx3Oa/qYJjyL0P7DFK7d7vk1+FrubdUs3Iupa4SY3PIoJnhN5Dx+ZXtc8x
ZAr6p5wH14o9BEwCOcQwtkDc9bv7iKE03w6Mef1u83TqAdSiJnu3yHsRrOnJA1cv
wQlYcI3TbOHE3FGR8ETzcBA7E+0iGiFRWpStiV0CgYEAuw7f59W9egf9sUUMvHim
cP4JOHBNSWgyNtYPGI8NgRO4oBwpzRYpBq1PZIxHKwm/Qt2hSD6VHa513SBkuEZz
mxHM0Ut4FSi3LIPSKQkIyGZg8f+6GtlYEnuEksOX3SboCjEGaWgQF2SDrhFE1FUK
E1NZcPRtSZTHJDyZKA/qHLECgYEAvixm+/TB3p7lKPexyODnn/fmIza14QfxK0mq
GXg5YPvoDUZDHfkjoW6gm+zli26W2nJ+OGNl9moHy5T4Ix/UY9+AvMJICsSbiFoa
+MaRLeRvulCecEl3prg957sbjQyOCYoGg/VUPpk5EcPxczgY4tyNMzNMop1WViYF
J6X5k0kCgYBy3WJ8MqAWlPoNsCdO0/cQQfNT081tnsQJ0K+8aheQ9qFuaWBKrMjE
eQiXyT00vpKnD8rLgUEanB+Eqh5k6vu6CmLii+fXKYIdvV9gSjmxzXKZG5nW5YE7
CbgHRVlOObXl83/998EyIUDoyYHIzDpVEvzNek7CUCLH7uRHMsMDpA==
-----END RSA PRIVATE KEY-----
"""

_STATIC_SERVICE_PRIVATE_KEY_PEM = """-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEA3SOUMMd9y7fvn2anLAVq8k0sl36PJhLqv9X9bDvZ3zMRFvxJ
81Urvb2vVENsV3Wl8Stx/q4N+02hgTmbkmgH/B291Hj9KH1PcekIljHnWPY9nzTt
VLyMQk9vNkxoPuhhJ95FQDQjYGjVkijlen9utuhdnv2OchtkrMW6d04Za/Em1TRF
eSr6U+0zQEqRbKvlpGuLVQHgeylZ1zjShefqZSWYe50M+OBkS7GRMf06LQjMAfVL
ifJIzk8JI/HJhEWbnvC9nR6tmw55IpGvUxnj4GIi1jG7vtWVvIG0Mf1RuAqKBxAA
tb4Wdmoy10lHhzWZp7gCuiLqG/QVNGh2hpW0SQIDAQABAoIBAA9dJbJW5ddFxfzv
45z0GmhPstGqrhTh2xPtcOA4b0xpzp3ndNbWW8XgvCHxVkFkT91n3JFqc9e6Hsas
4zFij211focYydPqkt6x51ISEQX2A7WANp38xIzl2m7uE48NU5SyxWJuzOdpmS8A
ruLaIC3OipSdfqxQWWgEi842q577XtEmp7Wi/n/Xa+q2dyWNPQUi/54zjH3BxIik
x4q/6IV/gvcqRo912/p06X0RqIvsZx3EHtxm0H4p6RqLE2s+wtl0J1/jrzvGE05z
EMglicmY2xZ7j20qDAuoesVbGprFXvwQ16VaTPGkmTiNfqLIlDUzpaASN5iJuzxs
Q2l7c1UCgYEA+r2z42aMMdUIGYLIekOBp+c93vPGedkevKVUYtSPnxjEj1qxf8c5
FODVISyo9Z5+hfZATtwapYgTcvQZUUKOIbBALYaxAWmsHWzXnomuygnj/g/9RwVU
s4Vu+h4SWR5eVwB0Iv5nbD4By+VL3hWN5m/8sZYJVKSgeiC25NDSIV0CgYEA4cbv
RyOomcFJDTHiLzk5KhwjlLn/62p2xZi1J+hcynQHY6N8Xuw40f4zfSLTANhO7Wnw
PVIlWD7GRnNNxLBMYQ4wU5avZB3bdZXa8YAggo+LaoO9hSSx+Bav3Jgid0sIAxlI
6Qxdmx0J4kb5SGzSY2gXlu4pir2+BYcQf3c5E90CgYEA5SewmtgisnxGbcI35H2D
pmbRBcz3DG8hBzl2GOi45acmJPm3FNeHVIxyXGJLfEbAzT+T4D6KX9QwKjPqW3if
GyzQSos5g9gGw9GwcaTVSLKnWo9UY678jSEanp4TGL2HbK3udfjZnnRBAg5qOuqq
B/s7DzXXCzN1sofpfs9V68UCgYEA3XzvF3bf25ZGN++L2I/miGz6atjdOvFCey4H
6ZKGFQYmiZTEWcqbI0ag9E3Jeba6FyYqS73ebOeIU2yiCiZ5h20H87iLb0frFztf
gjMTsYFoX6HFtmv9O0fmVh3ZEfZFceTIJfe/jH+8RoMh4e7/pg1jtukFT9o8I+gQ
QzuOfvECgYEA5c7pHZpLwjwlmOkjtXBCnw9U12COr0YRwrckB+H0ZScoyS7/qt2m
HqyEnhav+a2Otlaxf8ndXWRiB0jGf8409vDz7X/aNoDYO2K3PWs92JalQQVmVW9X
LCdu8t3Lwq9yUmUyC7o3oLt5nLeUnalktCI9QJiktIFr/ZEElb9ByDM=
-----END RSA PRIVATE KEY-----
"""

_STATIC_WEAK_SERVICE_PRIVATE_KEY_PEM = """-----BEGIN RSA PRIVATE KEY-----
MIICXgIBAAKBgQDWfURggCroy92zjPDiPb1teW7DXB38A06J1l4gzpcNU3tbXX8K
mFXL23ZzxJvZPGur7A/j3lSOS1q8qahIBPKeoe8KZs7QAvOlcaOJ/q+Wg7x8Z5TF
Co5IlfWobhnYRUxd2J9Er8VMsphb9+JQQyg0imsMQc2NfUkalBl5YM8IrwIDAQAB
AoGAcXl0Y1lrWh4A/KzkA82GGhTUdKaXdmyJcILo6ZJid7pi2MNuIrzVJzTERhsO
GK/OhvYssfE96soTBxz62p9De5EAmgJaZ2uDjkcy3nxoJtBQAkPnerMz4Wqiukxv
R1m7BAp6ggHiLv8dqzED9YjPFcNDgr3a+MF6Cz0kIj+xjgECQQD3dLZAFFdySR+S
wPKHunkXkwjV6aMFO0FgKngyybfhPfcz47LqDJ9VgSUj5bLncbZXjRcHV1PJdJwX
CJL2roKfAkEA3eUpAovadLR9/ol5syhcrkR8SDv6P5NgxJbRX/uDcK3miznh5R1S
gfk/7yoMbf1iiaDWYobVbna397IKp2lP8QJBAMFoqHXHMF30B0h1pFovhivF0VcY
aEFTghJ+vzm67gyPmSImaxWBzhtPeE7pXn6FIyak8QXc3HENwl5CZlOGLDMCQQDS
XrFrtZWuMXSGPmYAAdMkcM93WE2fuqTynJ3yJqztxiEdfAn7Qrp3eQwxPac9HA4w
tyipjnWI3cr6bXSGVWSxAkEAzXjLbr3niEjP/HydSjlPn2Jc2z8ngIO4l3hFueg1
8QkOdg7aSr+kVlma516waQDhVRpkQrZZV+5rbMqhkzgCUg==
-----END RSA PRIVATE KEY-----
"""

_STATIC_ROGUE_CA_PRIVATE_KEY_PEM = """-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAjFt8OCHngxHGq2+nW/i/Tmnw6XSYhvY/K74gwiiHs4CfX+1m
mhJ3rTuMMb6ttDp9b025fKor0XWda5R7CmGsALAEvDusL1mImhl+30g3+F7b+VqL
SNQyOvZSfEGa84ff7TeFdupvUr9ZzUhpTrF8L3EWiLX8T0qK3REH4oV8BAvhMSlC
VXZ2gT3dFcTwW/Cyziz6FCT1eUtwf0B5ustQa7WewDOtJPUaO2/eO7u2EZbF0aJn
4SmxwBIT9US4SEf3/XKqfUzDmZWzfBqC9LP0dfLQY/xARS7yFeolGEqVcFk2EHf5
cSkBYDPzHRGmsEAxM9p87po56LaiBmW4We0F8QIDAQABAoIBAAoZVQ1G5z0HjOdt
77lO4xj1x3dMw+LGGhKAKiQ+PVFdmloRH1ZLqN/GjpZPtXjn0nmtOoDtT5zRHSQN
+XJsR69++sA+fOulQg5wcjAHprtQu/wrlyUE255hddrp74fBSYvseEZvpNXr3b7H
DIi0fY5+URRCH+bmoqo4XPxgBWXXB7QvTD+8T5F47ELcXAMAcxAehXcROHVPnpKJ
LwFl1fjgnZKQv4nFKBrpJI2uPB4B0K3EGPgDhupf17Q6WtCxW4xTEoPYUWI00rn4
BhSe3SwCmUSBTF4kWq125KwiQ3mRRfw6lpNiM+HcPt/dGxfgDSj5Glr+nMZ+FT6u
2xwx3D8CgYEAvoY54ChfzWUOa6T5fwXh/Leyp30sN7TFhcNXIQpvs59nSeKeMBmZ
jUdQuPlsBi5gO/mzt1UFezqoSpaV0zbCAv0bVYkq+THdIPugiXH09j/pV0SF/4vj
A/orEbNC+21INGLEfct4kqllia8z131TcupiWY2KpL6mcRqRozG/hb8CgYEAvJe3
eClP60XoLRNGd/eK1vTCfs2oZGEIwoZJhGoP6dmMOUbjJLAdQryf8sCuNxvCPcDD
Wq7p8AFJbRMcEVatmiODjxoI6fIeo6siUoKBOS0CpRByinqNtgmjHAZvO8Z+V4Jm
z3GjVZobizfZk8Dh/f5tc9t8Aqjc7eoBGXhdQE8CgYAk372b0LSaABEGbGuNVgoi
6zq8h9FjBq2j8eaPEoID9bn75sxO6uV5HnBVHJD3sUoW0YEi3mWtL/EaXoKo2lQ6
V9pOd7nFeQ0fMRQlBdUvQ7dZmH2GtAA/6M8lIdi46LGs0eDNp++yEu7/8tTJxAu+
lfZq9qX6tJtqEIZXW22B6QKBgQCP3AuQFbNo/QKGn9V5XdMC9eIHaEmziHFuMZGS
+HT7JX/ZkUFjkxQ+/DPmsSQz1XDuOkTKv/Kjqdeg5JrcfwoeMkkAuBNkodTNdJXR
6ss4GiWSVGGLUMEYw3Ewx5fCOT/W8RoL09uMSOoJ4KiQFOpPHe3QGvUV8knVElOU
YkR/8QKBgE2cw9ydqMfD+dZhq5dWvrq511D6R/ZCE7dt/GGoXehfkdtSPLv3/Usd
l3epP2A/aRLuFFSp3bPwEDqxelrex4Z4VxOQYNxZH/llggt8ayjlsJnnYiQV19NV
HoPJtsmDPERc0rzWK2lXQLpw20VDrQR7H1Pux2HiFql/h6MJT1sm
-----END RSA PRIVATE KEY-----
"""


class SecurityPayloadSpec(BaseModel):
    """Declarative payload mount generated from a security artifact."""

    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    key: str
    mount_path: str = Field(alias="mountPath")
    source_path: str


class SecurityServiceRuntimeSpec(BaseModel):
    """Declarative runtime additions owned by the security plan."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    env: dict[str, str] = Field(default_factory=dict)
    payloads: tuple[SecurityPayloadSpec, ...] = Field(default_factory=tuple)
    ports: tuple[RuntimePort, ...] = Field(default_factory=tuple)
    sidecars: tuple[RuntimeSidecar, ...] = Field(default_factory=tuple)


class SecurityRuntimeSpec(BaseModel):
    """Security runtime intent for a world.

    Concrete files and payload contents are derived during render so the
    canonical world model only carries the declared security plan.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    tier: int = 1
    identity_provider: dict[str, Any] = Field(default_factory=dict)
    encryption: dict[str, Any] = Field(default_factory=dict)
    mtls: dict[str, Any] = Field(default_factory=dict)
    npc_credential_lifecycle: dict[str, Any] = Field(default_factory=dict)
    service_runtime: dict[str, SecurityServiceRuntimeSpec] = Field(default_factory=dict)

    @property
    def enabled(self) -> bool:
        return self.tier > 1

    def summary(self) -> dict[str, Any]:
        return self.model_dump(
            mode="json",
            exclude={"service_runtime"},
        )


def materialize_security_runtime(
    world: WorldIR,
    render_dir: Path,
) -> RenderExtensions:
    """Materialize the security plan into render-time files and extensions."""

    security_runtime = world.security_runtime
    if not security_runtime.enabled:
        return RenderExtensions()

    file_contents = _build_security_file_contents(world, security_runtime)
    written_paths: list[str] = []
    for relative_path, content in file_contents.items():
        path = render_dir / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        written_paths.append(str(path))

    services: dict[str, ServiceRuntimeExtension] = {}
    for service_id, extension in security_runtime.service_runtime.items():
        payloads = [
            RuntimePayload(
                key=payload.key,
                mountPath=payload.mount_path,
                content=_required_file_content(file_contents, payload.source_path),
            )
            for payload in extension.payloads
        ]
        services[service_id] = ServiceRuntimeExtension(
            env=dict(extension.env),
            payloads=payloads,
            ports=list(extension.ports),
            sidecars=list(extension.sidecars),
        )

    return RenderExtensions(
        services=services,
        values={"security": security_runtime.summary()},
        summary_updates={
            "security_tier": security_runtime.tier,
            "security_integration_enabled": True,
        },
        rendered_files=tuple(written_paths),
    )


def _required_file_content(
    file_contents: dict[str, str],
    relative_path: str,
) -> str:
    try:
        return file_contents[relative_path]
    except KeyError as exc:  # pragma: no cover - defensive, validated by tests
        raise ValueError(
            f"security runtime references missing artifact {relative_path!r}"
        ) from exc


def _build_security_file_contents(
    world: WorldIR,
    security_runtime: SecurityRuntimeSpec,
) -> dict[str, str]:
    file_contents: dict[str, str] = {}
    file_contents.update(_identity_provider_files(security_runtime))
    file_contents.update(_encryption_files(world, security_runtime))
    file_contents.update(_mtls_files(world, security_runtime))
    file_contents.update(_npc_files(security_runtime))
    file_contents["security/security-context.json"] = (
        json.dumps(security_runtime.summary(), indent=2, sort_keys=True) + "\n"
    )
    return file_contents


def _identity_provider_files(
    security_runtime: SecurityRuntimeSpec,
) -> dict[str, str]:
    if not security_runtime.identity_provider:
        return {}
    try:
        from open_range.identity_provider import (
            IdentityProviderConfig,
            SimulatedIdentityProvider,
        )
    except ImportError:  # pragma: no cover - optional dependency
        return {}

    idp_config = IdentityProviderConfig.model_validate(
        security_runtime.identity_provider
    )
    idp = SimulatedIdentityProvider(idp_config)
    server_template = (
        files("open_range")
        .joinpath("templates")
        .joinpath("identity_provider_server.py.tpl")
        .read_text(encoding="utf-8")
    )
    return {
        "security/idp/config.json": json.dumps(idp_config.model_dump(), indent=2)
        + "\n",
        "security/idp/startup.sh": idp.generate_startup_script(),
        "security/idp/identity_provider_server.py": server_template,
    }


def _encryption_files(
    world: WorldIR,
    security_runtime: SecurityRuntimeSpec,
) -> dict[str, str]:
    if not security_runtime.encryption:
        return {}
    try:
        from open_range.envelope_crypto import (
            EncryptedBundle,
            EncryptionConfig,
            _aes_gcm_encrypt,
        )
    except ImportError:  # pragma: no cover - optional dependency
        return {}

    config = EncryptionConfig.model_validate(security_runtime.encryption)
    if not config.enabled or not config.encrypted_paths:
        return {}

    credentials = {cred.id: cred for cred in world.credentials}
    master_key = _derive_bytes(
        world,
        security_runtime,
        label="encryption-master-key",
        length=32,
    )
    dek_metadata: dict[str, Any] = {}

    for credential_id in config.encrypted_paths:
        credential = credentials.get(credential_id)
        if credential is None:
            raise ValueError(
                f"security runtime references unknown credential {credential_id!r}"
            )
        aad = f"openrange:range:{credential.subject}:{credential.id}"
        dek = _derive_bytes(
            world,
            security_runtime,
            label="encryption-dek",
            item=credential.id,
            length=32,
        )
        nonce = _derive_bytes(
            world,
            security_runtime,
            label="encryption-nonce",
            item=credential.id,
            length=12,
        )
        wrap_nonce = _derive_bytes(
            world,
            security_runtime,
            label="encryption-wrap-nonce",
            item=credential.id,
            length=12,
        )
        ciphertext = _aes_gcm_encrypt(
            dek,
            nonce,
            credential.secret_ref.encode("utf-8"),
            aad.encode("utf-8"),
        )
        wrapped_ct = _aes_gcm_encrypt(master_key, wrap_nonce, dek, b"dek-wrap")
        bundle = EncryptedBundle(
            ciphertext=base64.b64encode(ciphertext).decode(),
            nonce=base64.b64encode(nonce).decode(),
            wrapped_dek=base64.b64encode(wrap_nonce + wrapped_ct).decode(),
            aad=aad,
            key_version=1,
        )
        dek_metadata[credential.id] = bundle.model_dump()

    return {
        "security/encryption/config.json": json.dumps(config.model_dump(), indent=2)
        + "\n",
        "security/encryption/wrapped_dek.json": json.dumps(dek_metadata, indent=2)
        + "\n",
    }


def _mtls_files(
    world: WorldIR,
    security_runtime: SecurityRuntimeSpec,
) -> dict[str, str]:
    if not security_runtime.mtls:
        return {}
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

        from open_range.mtls_sim import MTLSConfig
    except ImportError:  # pragma: no cover - optional dependency
        return {}

    config = MTLSConfig.model_validate(security_runtime.mtls)
    if not config.enabled or not config.mtls_services:
        return {}

    services, _ = _service_zone_layout(world)
    service_kinds = {service.id: service.kind for service in world.services}
    service_dependencies = {
        service.id: tuple(service.dependencies) for service in world.services
    }
    now = _DETERMINISTIC_CERT_EPOCH
    # Keep deterministic render-time certs valid across calendar time.
    # The explicit expired_cert weakness remains the supported way to
    # materialize an actually expired certificate.
    validity_days = max(config.cert_validity_days, _MIN_RENDER_CERT_VALIDITY_DAYS)

    def load_key(pem: str) -> rsa.RSAPrivateKey:
        return serialization.load_pem_private_key(pem.encode("utf-8"), password=None)

    ca_key = load_key(_STATIC_CA_PRIVATE_KEY_PEM)
    rogue_ca_key = load_key(_STATIC_ROGUE_CA_PRIVATE_KEY_PEM)
    strong_service_key = load_key(_STATIC_SERVICE_PRIVATE_KEY_PEM)
    weak_service_key = load_key(_STATIC_WEAK_SERVICE_PRIVATE_KEY_PEM)

    ca_subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, config.ca_common_name),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "OpenRange"),
        ]
    )
    rogue_subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, "Rogue CA"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Untrusted"),
        ]
    )

    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_subject)
        .issuer_name(ca_subject)
        .public_key(ca_key.public_key())
        .serial_number(_serial_number(world, security_runtime, "mtls-ca"))
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=validity_days * 2))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    rogue_ca_cert = (
        x509.CertificateBuilder()
        .subject_name(rogue_subject)
        .issuer_name(rogue_subject)
        .public_key(rogue_ca_key.public_key())
        .serial_number(_serial_number(world, security_runtime, "mtls-rogue-ca"))
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=validity_days))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(rogue_ca_key, hashes.SHA256())
    )

    rendered_config = config.model_copy(update={"cert_validity_days": validity_days})
    file_contents = {
        "security/mtls/config.json": json.dumps(rendered_config.model_dump(), indent=2)
        + "\n"
    }
    for service_id in config.mtls_services:
        weakness = next(iter(config.weaknesses.get(service_id, ())), None)
        zone = services.get(service_id, "default")
        fqdn = f"{service_id}.{zone}.svc.cluster.local"
        sans = [
            x509.DNSName(fqdn),
            x509.DNSName(f"{service_id}.{zone}"),
        ]
        if weakness == "wrong_san":
            sans = [x509.DNSName(f"wrong-{service_id}.{zone}.svc.cluster.local")]

        not_valid_before = now
        not_valid_after = now + datetime.timedelta(days=validity_days)
        if weakness == "expired_cert":
            not_valid_before = now - datetime.timedelta(days=validity_days + 30)
            not_valid_after = now - datetime.timedelta(days=1)

        signer_key = ca_key
        signer_subject = ca_subject
        ca_pem = ca_cert.public_bytes(serialization.Encoding.PEM).decode()
        if weakness == "self_signed":
            signer_key = rogue_ca_key
            signer_subject = rogue_subject
            ca_pem = rogue_ca_cert.public_bytes(serialization.Encoding.PEM).decode()

        service_key = (
            weak_service_key if weakness == "weak_key_1024" else strong_service_key
        )
        eku = [ExtendedKeyUsageOID.SERVER_AUTH]
        if weakness != "no_client_verify":
            eku.append(ExtendedKeyUsageOID.CLIENT_AUTH)

        cert = (
            x509.CertificateBuilder()
            .subject_name(
                x509.Name(
                    [
                        x509.NameAttribute(
                            NameOID.COMMON_NAME, f"{service_id}.range.local"
                        ),
                        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "OpenRange"),
                    ]
                )
            )
            .issuer_name(signer_subject)
            .public_key(service_key.public_key())
            .serial_number(
                _serial_number(world, security_runtime, "mtls-service", service_id)
            )
            .not_valid_before(not_valid_before)
            .not_valid_after(not_valid_after)
            .add_extension(x509.SubjectAlternativeName(sans), critical=False)
            .add_extension(x509.ExtendedKeyUsage(eku), critical=False)
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None), critical=True
            )
            .sign(signer_key, hashes.SHA256())
        )

        file_contents[f"security/mtls/{service_id}/ca.pem"] = ca_pem
        file_contents[f"security/mtls/{service_id}/cert.pem"] = cert.public_bytes(
            serialization.Encoding.PEM
        ).decode()
        file_contents[f"security/mtls/{service_id}/key.pem"] = (
            service_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            ).decode()
        )
        if service_kinds.get(service_id) == "db":
            file_contents[f"security/mtls/{service_id}/mysql.cnf"] = (
                "[mysqld]\n"
                "ssl-ca=/etc/mtls/ca.pem\n"
                "ssl-cert=/etc/mtls/cert.pem\n"
                "ssl-key=/etc/mtls/key.pem\n"
                "require_secure_transport=ON\n"
            )
            file_contents[f"security/mtls/{service_id}/mysql-init.sql"] = (
                "CREATE USER IF NOT EXISTS 'app'@'%' IDENTIFIED WITH mysql_native_password BY 'app-pass';\n"
                "CREATE USER IF NOT EXISTS 'app'@'localhost' IDENTIFIED WITH mysql_native_password BY 'app-pass';\n"
                "ALTER USER 'app'@'%' IDENTIFIED WITH mysql_native_password BY 'app-pass';\n"
                "ALTER USER 'app'@'localhost' IDENTIFIED WITH mysql_native_password BY 'app-pass';\n"
                "ALTER USER 'app'@'%' REQUIRE X509;\n"
                "ALTER USER 'app'@'localhost' REQUIRE X509;\n"
                "GRANT ALL PRIVILEGES ON app.* TO 'app'@'%';\n"
                "GRANT ALL PRIVILEGES ON app.* TO 'app'@'localhost';\n"
                "FLUSH PRIVILEGES;\n"
            )
        if "svc-db" in service_dependencies.get(service_id, ()):
            file_contents[f"security/mtls/{service_id}/mysql-client.cnf"] = (
                "[client]\n"
                "host=svc-db\n"
                "user=app\n"
                "password=app-pass\n"
                "database=app\n"
                "protocol=TCP\n"
                "connect-timeout=5\n"
                "ssl-ca=/etc/mtls/ca.pem\n"
                "ssl-cert=/etc/mtls/cert.pem\n"
                "ssl-key=/etc/mtls/key.pem\n"
            )
    return file_contents


def _npc_files(
    security_runtime: SecurityRuntimeSpec,
) -> dict[str, str]:
    if not security_runtime.npc_credential_lifecycle:
        return {}
    return {
        "security/npc/config.json": json.dumps(
            security_runtime.npc_credential_lifecycle,
            indent=2,
        )
        + "\n"
    }


def _service_zone_layout(
    world: WorldIR,
) -> tuple[dict[str, str], dict[str, list[str]]]:
    host_by_id = {host.id: host for host in world.hosts}
    services: dict[str, str] = {}
    zones_dict: dict[str, list[str]] = {}
    for service in world.services:
        zone = (
            host_by_id[service.host].zone if service.host in host_by_id else "default"
        )
        services[service.id] = zone
        zones_dict.setdefault(zone, []).append(service.id)
    return services, zones_dict


def _derive_bytes(
    world: WorldIR,
    security_runtime: SecurityRuntimeSpec,
    *,
    label: str,
    item: str = "",
    length: int,
) -> bytes:
    seed = json.dumps(
        {
            "world_id": world.world_id,
            "seed": world.seed,
            "label": label,
            "item": item,
            "summary": security_runtime.summary(),
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    output = bytearray()
    counter = 0
    while len(output) < length:
        counter_bytes = counter.to_bytes(4, byteorder="big")
        output.extend(hashlib.sha256(seed + counter_bytes).digest())
        counter += 1
    return bytes(output[:length])


def _serial_number(
    world: WorldIR,
    security_runtime: SecurityRuntimeSpec,
    label: str,
    item: str = "",
) -> int:
    raw = _derive_bytes(
        world,
        security_runtime,
        label=label,
        item=item,
        length=20,
    )
    serial = int.from_bytes(raw, byteorder="big") >> 1
    return serial or 1
