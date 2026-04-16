from __future__ import annotations

from open_range.catalog.services import (
    ROLE_HOME_SERVICE_BY_ROLE,
    host_for_service,
    service_catalog_entry_for_kind,
    service_kind_names,
)


def test_service_catalog_exposes_fixed_enterprise_palette() -> None:
    assert set(service_kind_names()) == {
        "web_app",
        "email",
        "idp",
        "fileshare",
        "db",
        "siem",
    }


def test_service_catalog_keeps_known_service_defaults_stable() -> None:
    web = service_catalog_entry_for_kind("web_app")
    assert web is not None
    assert web.service_id == "svc-web"
    assert web.dependencies == ("svc-db", "svc-idp", "svc-fileshare")

    siem = service_catalog_entry_for_kind("siem")
    assert siem is not None
    assert siem.service_id == "svc-siem"
    assert siem.telemetry_surfaces == ("ingest", "alert")


def test_service_catalog_carries_role_homes_and_host_lookup() -> None:
    assert ROLE_HOME_SERVICE_BY_ROLE["finance"] == "svc-fileshare"
    assert host_for_service("svc-idp") == "idp-1"
