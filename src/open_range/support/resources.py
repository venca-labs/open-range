"""Access bundled manifests, schemas, and other installable assets."""

from __future__ import annotations

import json
from importlib.resources import files
from pathlib import Path
from typing import Any

import yaml


def resource_root() -> Path:
    """Return the installed resource root for the package."""
    return Path(str(files("open_range").joinpath("_resources")))


def bundled_manifest_dir() -> Path:
    return resource_root() / "manifests"


def bundled_schema_dir() -> Path:
    return resource_root() / "schemas"


def bundled_manifest_names() -> tuple[str, ...]:
    manifest_dir = bundled_manifest_dir()
    return tuple(sorted(path.name for path in manifest_dir.glob("tier*.yaml")))


def bundled_manifest_path(name: str) -> Path:
    return bundled_manifest_dir() / name


def load_bundled_manifest(name: str) -> dict[str, Any]:
    payload = yaml.safe_load(bundled_manifest_path(name).read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"expected a YAML mapping in bundled manifest {name}")
    return payload


def load_bundled_manifest_registry() -> dict[str, Any]:
    payload = yaml.safe_load(
        (bundled_manifest_dir() / "registry.yaml").read_text(encoding="utf-8")
    )
    if not isinstance(payload, dict):
        raise ValueError("expected a YAML mapping in bundled registry")
    return payload


def load_bundled_schema(name: str) -> dict[str, Any]:
    payload = json.loads((bundled_schema_dir() / name).read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"expected a JSON object in bundled schema {name}")
    return payload


__all__ = [
    "bundled_manifest_dir",
    "bundled_manifest_names",
    "bundled_manifest_path",
    "bundled_schema_dir",
    "load_bundled_manifest",
    "load_bundled_manifest_registry",
    "load_bundled_schema",
    "resource_root",
]
