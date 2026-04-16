"""Catalog-backed enterprise service facts."""

from __future__ import annotations

from open_range.catalog.contracts import ServiceCatalogEntry

SERVICE_CATALOG: tuple[ServiceCatalogEntry, ...] = (
    ServiceCatalogEntry(
        kind="web_app",
        host_id="web-1",
        service_id="svc-web",
        zone="dmz",
        exposure="public",
        ports=(80, 443),
        dependencies=("svc-db", "svc-idp", "svc-fileshare"),
        telemetry_surfaces=("web_access", "web_error"),
    ),
    ServiceCatalogEntry(
        kind="email",
        host_id="mail-1",
        service_id="svc-email",
        zone="dmz",
        exposure="public",
        ports=(25, 587, 993),
        dependencies=("svc-idp",),
        telemetry_surfaces=("smtp", "imap"),
    ),
    ServiceCatalogEntry(
        kind="idp",
        host_id="idp-1",
        service_id="svc-idp",
        zone="management",
        exposure="management",
        ports=(389,),
        dependencies=(),
        telemetry_surfaces=("auth", "audit"),
    ),
    ServiceCatalogEntry(
        kind="fileshare",
        host_id="files-1",
        service_id="svc-fileshare",
        zone="corp",
        exposure="corp",
        ports=(445,),
        dependencies=("svc-idp",),
        telemetry_surfaces=("share_access",),
    ),
    ServiceCatalogEntry(
        kind="db",
        host_id="db-1",
        service_id="svc-db",
        zone="data",
        exposure="data",
        ports=(3306,),
        dependencies=(),
        telemetry_surfaces=("query", "slow_query"),
    ),
    ServiceCatalogEntry(
        kind="siem",
        host_id="siem-1",
        service_id="svc-siem",
        zone="management",
        exposure="management",
        ports=(514, 9200, 9201),
        dependencies=(),
        telemetry_surfaces=("ingest", "alert"),
    ),
)

ROLE_HOME_SERVICE_BY_ROLE: dict[str, str] = {
    "sales": "svc-web",
    "engineer": "svc-web",
    "finance": "svc-fileshare",
    "it_admin": "svc-idp",
}

_SERVICE_BY_KIND = {entry.kind: entry for entry in SERVICE_CATALOG}
_SERVICE_BY_ID = {entry.service_id: entry for entry in SERVICE_CATALOG}


def service_kind_names() -> tuple[str, ...]:
    return tuple(entry.kind for entry in SERVICE_CATALOG)


def service_catalog_entry_for_kind(kind: str) -> ServiceCatalogEntry | None:
    return _SERVICE_BY_KIND.get(kind)


def service_catalog_entry_for_id(service_id: str) -> ServiceCatalogEntry | None:
    return _SERVICE_BY_ID.get(service_id)


def host_for_service(service_id: str) -> str:
    entry = service_catalog_entry_for_id(service_id)
    if entry is None:
        return "web-1"
    return entry.host_id
