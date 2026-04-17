"""Neutral render/runtime contract models."""

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


class KindArtifacts(BaseModel):
    """Rendered artifact bundle stored on snapshots."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    render_dir: str
    chart_dir: str
    values_path: str
    kind_config_path: str
    manifest_summary_path: str
    rendered_files: tuple[str, ...] = Field(default_factory=tuple)
    chart_values: dict[str, Any] = Field(default_factory=dict)
    pinned_image_digests: dict[str, str] = Field(default_factory=dict)


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
    """Security runtime intent stored on ``WorldIR``."""

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
