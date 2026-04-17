"""Service and edge compilation helpers."""

from __future__ import annotations

from open_range.catalog.services import service_catalog_entry_for_kind
from open_range.contracts.world import EdgeSpec, HostSpec, ServiceSpec


def compile_service_topology(
    *,
    service_names: tuple[str, ...],
    available_zones: tuple[str, ...],
    allowed_surfaces: set[str],
) -> tuple[tuple[HostSpec, ...], tuple[ServiceSpec, ...], tuple[EdgeSpec, ...]]:
    hosts: list[HostSpec] = []
    services: list[ServiceSpec] = []
    edges: list[EdgeSpec] = []
    service_ids = {
        entry.service_id
        for service_name in service_names
        for entry in (service_catalog_entry_for_kind(service_name),)
        if entry is not None
    }

    for service_name in service_names:
        layout = service_catalog_entry_for_kind(service_name)
        if layout is None:
            raise ValueError(f"unsupported enterprise_saas_v1 service: {service_name}")

        telemetry = layout.telemetry_surfaces
        if allowed_surfaces:
            telemetry = tuple(
                surface for surface in telemetry if surface in allowed_surfaces
            )
        dependencies = tuple(dep for dep in layout.dependencies if dep in service_ids)

        hosts.append(
            HostSpec(
                id=layout.host_id,
                zone=resolve_zone(available_zones, layout.zone),
                exposure=layout.exposure,
                services=(layout.service_id,),
            )
        )
        services.append(
            ServiceSpec(
                id=layout.service_id,
                kind=service_name,
                host=layout.host_id,
                ports=layout.ports,
                dependencies=dependencies,
                telemetry_surfaces=telemetry,
            )
        )

        for dep in dependencies:
            edges.append(
                EdgeSpec(
                    id=f"net-{layout.service_id}-to-{dep}",
                    kind="network",
                    source=layout.service_id,
                    target=dep,
                    label="service_dependency",
                )
            )
            edges.append(
                EdgeSpec(
                    id=f"trust-{layout.service_id}-to-{dep}",
                    kind="trust",
                    source=layout.service_id,
                    target=dep,
                    label="service_trust",
                )
            )

        if layout.kind != "siem" and (not allowed_surfaces or telemetry):
            edges.append(
                EdgeSpec(
                    id=f"telemetry-{layout.service_id}-to-siem",
                    kind="telemetry",
                    source=layout.service_id,
                    target="svc-siem",
                    label="log_ship",
                )
            )

    return tuple(hosts), tuple(services), tuple(edges)


def resolve_zone(available: tuple[str, ...], preferred: str) -> str:
    if preferred in available:
        return preferred
    if available:
        return available[0]
    raise ValueError("manifest must declare at least one topology zone")
