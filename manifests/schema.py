"""Helpers for working with the checked-in strict manifest examples."""

from __future__ import annotations

from pathlib import Path

import yaml

from open_range.manifest import (
    EnterpriseSaaSManifest,
    manifest_schema,
    validate_manifest,
)


def load_manifest(path: str | Path) -> EnterpriseSaaSManifest:
    """Load one checked-in manifest example and validate it."""
    manifest_path = Path(path)
    payload = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"expected a YAML mapping in {manifest_path}")
    return validate_manifest(payload)


__all__ = [
    "EnterpriseSaaSManifest",
    "load_manifest",
    "manifest_schema",
    "validate_manifest",
]
