"""Security render subsystem."""

from __future__ import annotations

from importlib import import_module
from typing import TYPE_CHECKING

from .runtime import (
    SecurityPayloadSpec,
    SecurityRuntimeSpec,
    SecurityServiceRuntimeSpec,
    materialize_security_runtime,
)

if TYPE_CHECKING:
    from .integrator import (
        DEFAULT_TIER_MAP,
        SecurityIntegrator,
        SecurityIntegratorConfig,
        SecurityTierConfig,
    )

__all__ = [
    "DEFAULT_TIER_MAP",
    "SecurityIntegrator",
    "SecurityIntegratorConfig",
    "SecurityPayloadSpec",
    "SecurityRuntimeSpec",
    "SecurityServiceRuntimeSpec",
    "SecurityTierConfig",
    "materialize_security_runtime",
]

_EXPORT_MODULES = {
    "DEFAULT_TIER_MAP": "integrator",
    "SecurityIntegrator": "integrator",
    "SecurityIntegratorConfig": "integrator",
    "SecurityTierConfig": "integrator",
}


def __getattr__(name: str):
    module_name = _EXPORT_MODULES.get(name)
    if module_name is None:
        raise AttributeError(name)
    module = import_module(f"open_range.render.security.{module_name}")
    return getattr(module, name)


def __dir__() -> list[str]:
    return sorted(__all__)
