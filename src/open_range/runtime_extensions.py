"""Typed runtime extensions applied during render."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class RuntimePayload(BaseModel):
    """Mountable content added to a rendered service."""

    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    key: str
    mount_path: str = Field(alias="mountPath")
    content: str

    def as_chart_value(self) -> dict[str, str]:
        return {
            "key": self.key,
            "mountPath": self.mount_path,
            "content": self.content,
        }


class RuntimePort(BaseModel):
    """Port exposed by a rendered service or sidecar."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str
    port: int
    protocol: str = "TCP"

    def as_chart_value(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "port": self.port,
            "protocol": self.protocol,
        }


class RuntimeSidecar(BaseModel):
    """Sidecar attached to a rendered service."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str
    image: str | None = None
    image_source: Literal["explicit", "service"] = "explicit"
    command: tuple[str, ...] = Field(default_factory=tuple)
    args: tuple[str, ...] = Field(default_factory=tuple)
    ports: tuple[RuntimePort, ...] = Field(default_factory=tuple)
    env: dict[str, str] = Field(default_factory=dict)
    payloads: tuple[RuntimePayload, ...] = Field(default_factory=tuple)
    include_service_payloads: bool = False

    def as_chart_value(
        self,
        service: dict[str, Any],
        *,
        service_id: str,
    ) -> dict[str, Any]:
        if self.image_source == "service":
            image = str(service.get("image", "")).strip()
        else:
            image = (self.image or "").strip()
        if not image:
            raise ValueError(
                f"sidecar {self.name!r} for service {service_id!r} has no image"
            )

        payloads: list[dict[str, str]] = []
        if self.include_service_payloads:
            payloads.extend(list(service.get("payloads", [])))
        payloads.extend(payload.as_chart_value() for payload in self.payloads)

        resolved: dict[str, Any] = {"name": self.name, "image": image}
        if self.command:
            resolved["command"] = list(self.command)
        if self.args:
            resolved["args"] = list(self.args)
        if self.ports:
            resolved["ports"] = [port.as_chart_value() for port in self.ports]
        if self.env:
            resolved["env"] = dict(self.env)
        if payloads:
            resolved["payloads"] = payloads
        return resolved


class ServiceRuntimeExtension(BaseModel):
    """Runtime additions attached to a rendered service."""

    model_config = ConfigDict(extra="forbid")

    env: dict[str, str] = Field(default_factory=dict)
    payloads: list[RuntimePayload] = Field(default_factory=list)
    ports: list[RuntimePort] = Field(default_factory=list)
    sidecars: list[RuntimeSidecar] = Field(default_factory=list)


class RenderExtensions(BaseModel):
    """Additional render-time inputs layered onto the base world render."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    services: dict[str, ServiceRuntimeExtension] = Field(default_factory=dict)
    values: dict[str, Any] = Field(default_factory=dict)
    summary_updates: dict[str, Any] = Field(default_factory=dict)
    rendered_files: tuple[str, ...] = Field(default_factory=tuple)


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
