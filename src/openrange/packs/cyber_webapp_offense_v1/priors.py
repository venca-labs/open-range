"""Default generation priors for the v1 cyber procedural builder.

A ``Mapping[str, object]`` shaped to be ergonomic for samplers, not for
documentation. ``ProceduralBuilder`` reads these to decide service
counts, kind weights, vuln weights, and chain depth. Tests can
substitute their own priors via ``ProceduralBuilder(priors=...)`` to
make sampling deterministic / focused.

Shape:

    service_count: {min, max}              — discrete uniform sample
    service_kinds: {kind: weight}          — weighted pick (web is forced)
    endpoints_per_service: {min, max}      — discrete uniform sample
    vuln_count: {min, max}                 — discrete uniform sample
    vuln_kinds: {kind: weight}             — weighted pick (catalog id)
    account_count: {min, max}              — discrete uniform sample

The values are deliberately small for v1 — "business scale" is 3-5
services, not 50. The MCTS layer (C7) will scale these intelligently;
the procedural builder is the floor.
"""

from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType

PRIORS: Mapping[str, object] = MappingProxyType(
    {
        "service_count": MappingProxyType({"min": 2, "max": 5}),
        "service_kinds": MappingProxyType(
            {
                "web": 0,  # always one web service; weight ignored
                "api": 3,
                "auth": 2,
                "db": 4,
            },
        ),
        "endpoints_per_service": MappingProxyType({"min": 1, "max": 3}),
        "vuln_count": MappingProxyType({"min": 1, "max": 3}),
        "vuln_kinds": MappingProxyType(
            {
                "sql_injection": 3,
                "ssrf": 2,
                "broken_authz": 2,
            },
        ),
        "account_count": MappingProxyType({"min": 1, "max": 3}),
    },
)


__all__ = ["PRIORS"]
