"""Catalog-backed role home and routine defaults for green personas."""

from __future__ import annotations

from open_range.catalog.contracts import PersonaDefaultsSpec

_DEFAULT_ROLE_DEFAULTS = PersonaDefaultsSpec(
    role="*",
    home_service="svc-web",
    routine=("check_mail", "browse_app", "access_fileshare"),
)

ROLE_DEFAULT_SPECS: tuple[PersonaDefaultsSpec, ...] = (
    PersonaDefaultsSpec(
        role="sales",
        home_service="svc-web",
        routine=_DEFAULT_ROLE_DEFAULTS.routine,
    ),
    PersonaDefaultsSpec(
        role="engineer",
        home_service="svc-web",
        routine=_DEFAULT_ROLE_DEFAULTS.routine,
    ),
    PersonaDefaultsSpec(
        role="executive",
        home_service="svc-web",
        routine=_DEFAULT_ROLE_DEFAULTS.routine,
    ),
    PersonaDefaultsSpec(
        role="finance",
        home_service="svc-fileshare",
        routine=("check_mail", "open_payroll_dashboard", "access_fileshare"),
    ),
    PersonaDefaultsSpec(
        role="it_admin",
        home_service="svc-idp",
        routine=("review_idp", "triage_alerts", "reset_password"),
    ),
    PersonaDefaultsSpec(
        role="security",
        home_service="svc-siem",
        routine=("triage_alerts", "browse_app", "query_db"),
    ),
)

_ROLE_DEFAULTS_BY_ROLE = {entry.role: entry for entry in ROLE_DEFAULT_SPECS}
ROLE_HOME_SERVICE_BY_ROLE: dict[str, str] = {
    entry.role: entry.home_service for entry in ROLE_DEFAULT_SPECS
}


def role_defaults_for_role(role: str) -> PersonaDefaultsSpec:
    return _ROLE_DEFAULTS_BY_ROLE.get(role, _DEFAULT_ROLE_DEFAULTS)


def home_service_for_role(role: str) -> str:
    return role_defaults_for_role(role).home_service


def routine_for_role(role: str) -> tuple[str, ...]:
    return role_defaults_for_role(role).routine
