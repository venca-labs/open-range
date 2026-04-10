from __future__ import annotations

from open_range.identity_provider import (
    IdentityProviderConfig,
    ServiceIdentity,
    SimulatedIdentityProvider,
)


def _idp(*, weaknesses: list[str] | None = None) -> SimulatedIdentityProvider:
    return SimulatedIdentityProvider(
        IdentityProviderConfig(
            enabled=True,
            weaknesses=[] if weaknesses is None else weaknesses,
            service_identities={
                "svc-web": ServiceIdentity(
                    identity_uri="spiffe://range.local/ns/dmz/sa/svc-web",
                    allowed_scopes=["data:read:patients/*"],
                )
            },
        )
    )


def test_validate_token_accepts_required_scopes() -> None:
    idp = _idp()

    token = idp.issue_token(
        "spiffe://range.local/ns/dmz/sa/svc-web",
        ["data:read:patients/*"],
    )

    claims = idp.validate_token(
        token,
        required_scopes=["data:read:patients/42"],
    )

    assert claims is not None


def test_validate_token_rejects_missing_required_scopes() -> None:
    idp = _idp()

    token = idp.issue_token(
        "spiffe://range.local/ns/dmz/sa/svc-web",
        ["data:read:patients/*"],
    )

    claims = idp.validate_token(
        token,
        required_scopes=["admin:write:*"],
    )

    assert claims is None


def test_missing_scope_check_weakness_bypasses_scope_validation() -> None:
    idp = _idp(weaknesses=["missing_scope_check"])

    token = idp.issue_token(
        "spiffe://range.local/ns/dmz/sa/svc-web",
        ["data:read:patients/*"],
    )

    claims = idp.validate_token(
        token,
        required_scopes=["admin:write:*"],
    )

    assert claims is not None
