"""Compiler package contracts."""

from __future__ import annotations

from typing import Protocol

from open_range.config import DEFAULT_BUILD_CONFIG, BuildConfig
from open_range.contracts.world import WorldIR
from open_range.manifest import EnterpriseSaaSManifest


class ManifestCompiler(Protocol):
    def compile(
        self,
        manifest: dict | EnterpriseSaaSManifest,
        build_config: BuildConfig = DEFAULT_BUILD_CONFIG,
    ) -> WorldIR: ...
