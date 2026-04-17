"""Asset compilation helpers."""

from __future__ import annotations

from open_range.catalog.assets import (
    asset_confidentiality_for_class,
    asset_placement_rule_for_id,
)
from open_range.contracts.world import AssetSpec
from open_range.manifest import ManifestAsset


def place_assets(
    assets: tuple[ManifestAsset, ...],
    *,
    available_service_ids: frozenset[str] = frozenset(),
) -> tuple[AssetSpec, ...]:
    return tuple(
        place_asset(asset, available_service_ids=available_service_ids)
        for asset in assets
    )


def place_asset(
    asset: ManifestAsset,
    *,
    available_service_ids: frozenset[str] = frozenset(),
) -> AssetSpec:
    rule = asset_placement_rule_for_id(asset.id)
    owner_service = rule.owner_service
    if available_service_ids and owner_service not in available_service_ids:
        owner_service = _fallback_owner_service(available_service_ids)
    location = rule.location_template.format(asset_id=asset.id)
    if owner_service != rule.owner_service:
        location = _rebased_asset_location(owner_service, asset.id)
    return AssetSpec(
        id=asset.id,
        asset_class=asset.asset_class,
        location=location,
        owner_service=owner_service,
        confidentiality=asset_confidentiality_for_class(asset.asset_class),
    )


def _fallback_owner_service(available_service_ids: frozenset[str]) -> str:
    for service_id in ("svc-web", "svc-idp", "svc-email", "svc-fileshare", "svc-db"):
        if service_id in available_service_ids:
            return service_id
    return sorted(available_service_ids)[0]


def _rebased_asset_location(owner_service: str, asset_id: str) -> str:
    if owner_service == "svc-db":
        return f"svc-db://main/{asset_id}"
    if owner_service == "svc-idp":
        return f"svc-idp://secrets/{asset_id}"
    if owner_service == "svc-fileshare":
        return f"svc-fileshare:/srv/shared/{asset_id}.txt"
    return f"{owner_service}:/var/{owner_service}/{asset_id}.txt"
