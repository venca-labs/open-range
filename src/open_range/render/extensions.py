"""Typed runtime extensions applied during render."""

from __future__ import annotations

from typing import Any

from open_range.contracts.render import (
    RenderExtensions,
    ServiceRuntimeExtension,
)


def merge_render_extensions(
    base: RenderExtensions | None,
    extra: RenderExtensions | None,
) -> RenderExtensions | None:
    """Merge two render extension bundles."""

    if base is None:
        return extra
    if extra is None:
        return base

    services: dict[str, ServiceRuntimeExtension] = {
        service_id: ServiceRuntimeExtension.model_validate(
            extension.model_dump(by_alias=True)
        )
        for service_id, extension in base.services.items()
    }
    for service_id, extension in extra.services.items():
        if service_id not in services:
            services[service_id] = ServiceRuntimeExtension.model_validate(
                extension.model_dump(by_alias=True)
            )
            continue
        merged = services[service_id]
        merged.env.update(extension.env)
        merged.payloads.extend(extension.payloads)
        merged.ports.extend(extension.ports)
        merged.sidecars.extend(extension.sidecars)

    values = dict(base.values)
    values.update(extra.values)
    summary_updates = dict(base.summary_updates)
    summary_updates.update(extra.summary_updates)
    rendered_files = tuple(dict.fromkeys((*base.rendered_files, *extra.rendered_files)))
    return RenderExtensions(
        services=services,
        values=values,
        summary_updates=summary_updates,
        rendered_files=rendered_files,
    )


def apply_service_runtime_extensions(
    services: dict[str, dict[str, Any]],
    extensions: dict[str, ServiceRuntimeExtension],
) -> dict[str, dict[str, Any]]:
    """Merge typed runtime extensions into rendered service values."""

    next_services = {name: dict(spec) for name, spec in services.items()}
    for service_id, extension in extensions.items():
        service = next_services.get(service_id)
        if not isinstance(service, dict):
            continue
        if extension.env:
            merged_env = dict(service.get("env", {}))
            merged_env.update(extension.env)
            service["env"] = merged_env
        if extension.payloads:
            service["payloads"] = list(service.get("payloads", [])) + [
                payload.as_chart_value() for payload in extension.payloads
            ]
        if extension.ports:
            existing = list(service.get("ports", []))
            for port in extension.ports:
                rendered = port.as_chart_value()
                if any(item.get("port") == rendered["port"] for item in existing):
                    continue
                existing.append(rendered)
            service["ports"] = existing
        if extension.sidecars:
            existing_sidecars = list(service.get("sidecars", []))
            existing_sidecars.extend(
                sidecar.as_chart_value(service, service_id=service_id)
                for sidecar in extension.sidecars
            )
            service["sidecars"] = existing_sidecars
    return next_services
