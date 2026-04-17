"""Validation helpers for the strict public manifest."""

from __future__ import annotations

from .models import EnterpriseSaaSManifest


def validate_manifest(payload: dict) -> EnterpriseSaaSManifest:
    """Validate raw public manifest payload into the strict model."""
    return EnterpriseSaaSManifest.model_validate(payload)


def manifest_schema() -> dict:
    """Return the JSON schema for the strict public manifest."""
    return EnterpriseSaaSManifest.model_json_schema()
