"""Public render package surface."""

from __future__ import annotations

from importlib import import_module
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .extensions import (
        RenderExtensions,
        RuntimePayload,
        RuntimePort,
        RuntimeSidecar,
        ServiceRuntimeExtension,
        apply_service_runtime_extensions,
        merge_render_extensions,
    )
    from .images import (
        DB_MTLS_HELPER_IMAGE,
        DEFAULT_SERVICE_IMAGE,
        SANDBOX_IMAGE_BY_ROLE,
        SANDBOX_MULTITOOL_IMAGE,
        SERVICE_IMAGE_BY_KIND,
        sandbox_image_for_role,
        service_image_for_kind,
    )
    from .k3d import K3dRenderer
    from .kind import EnterpriseSaaSKindRenderer, KindRenderer
    from .security import (
        SecurityPayloadSpec,
        SecurityRuntimeSpec,
        SecurityServiceRuntimeSpec,
        materialize_security_runtime,
    )

__all__ = [
    "DB_MTLS_HELPER_IMAGE",
    "DEFAULT_SERVICE_IMAGE",
    "EnterpriseSaaSKindRenderer",
    "K3dRenderer",
    "KindRenderer",
    "RenderExtensions",
    "RuntimePayload",
    "RuntimePort",
    "RuntimeSidecar",
    "SANDBOX_IMAGE_BY_ROLE",
    "SANDBOX_MULTITOOL_IMAGE",
    "SERVICE_IMAGE_BY_KIND",
    "SecurityPayloadSpec",
    "SecurityRuntimeSpec",
    "SecurityServiceRuntimeSpec",
    "ServiceRuntimeExtension",
    "apply_service_runtime_extensions",
    "materialize_security_runtime",
    "merge_render_extensions",
    "sandbox_image_for_role",
    "service_image_for_kind",
]

_EXPORT_MODULES = {
    "DB_MTLS_HELPER_IMAGE": "images",
    "DEFAULT_SERVICE_IMAGE": "images",
    "EnterpriseSaaSKindRenderer": "kind",
    "K3dRenderer": "k3d",
    "KindRenderer": "kind",
    "RenderExtensions": "extensions",
    "RuntimePayload": "extensions",
    "RuntimePort": "extensions",
    "RuntimeSidecar": "extensions",
    "SANDBOX_IMAGE_BY_ROLE": "images",
    "SANDBOX_MULTITOOL_IMAGE": "images",
    "SERVICE_IMAGE_BY_KIND": "images",
    "SecurityPayloadSpec": "security",
    "SecurityRuntimeSpec": "security",
    "SecurityServiceRuntimeSpec": "security",
    "ServiceRuntimeExtension": "extensions",
    "apply_service_runtime_extensions": "extensions",
    "materialize_security_runtime": "security",
    "merge_render_extensions": "extensions",
    "sandbox_image_for_role": "images",
    "service_image_for_kind": "images",
}


def __getattr__(name: str):
    module_name = _EXPORT_MODULES.get(name)
    if module_name is None:
        raise AttributeError(name)
    module = import_module(f"open_range.render.{module_name}")
    return getattr(module, name)


def __dir__() -> list[str]:
    return sorted(__all__)
