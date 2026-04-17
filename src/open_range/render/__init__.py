"""Public render package surface."""

from open_range.contracts.render import (
    RenderExtensions,
    RuntimePayload,
    RuntimePort,
    RuntimeSidecar,
    SecurityPayloadSpec,
    SecurityRuntimeSpec,
    SecurityServiceRuntimeSpec,
    ServiceRuntimeExtension,
)

from .cilium import CiliumPolicyConfig, CiliumPolicyGenerator
from .extensions import apply_service_runtime_extensions, merge_render_extensions
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
from .security.integrator import (
    DEFAULT_TIER_MAP,
    SecurityIntegrator,
    SecurityIntegratorConfig,
    SecurityTierConfig,
)
from .security.runtime import materialize_security_runtime

__all__ = [
    "CiliumPolicyConfig",
    "CiliumPolicyGenerator",
    "DB_MTLS_HELPER_IMAGE",
    "DEFAULT_TIER_MAP",
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
    "SecurityIntegrator",
    "SecurityIntegratorConfig",
    "SecurityRuntimeSpec",
    "SecurityServiceRuntimeSpec",
    "SecurityTierConfig",
    "ServiceRuntimeExtension",
    "apply_service_runtime_extensions",
    "materialize_security_runtime",
    "merge_render_extensions",
    "sandbox_image_for_role",
    "service_image_for_kind",
]
