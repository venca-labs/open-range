"""Compiler package contracts."""

from __future__ import annotations

from typing import Protocol

from open_range.config import DEFAULT_BUILD_CONFIG, BuildConfig
from open_range.manifest import EnterpriseSaaSManifest
from open_range.world_ir import WorldIR


class ManifestCompiler(Protocol):
    def compile(
        self,
        manifest: dict | EnterpriseSaaSManifest,
        build_config: BuildConfig = DEFAULT_BUILD_CONFIG,
    ) -> WorldIR: ...
