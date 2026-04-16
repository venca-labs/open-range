"""Asset compilation helpers."""

from __future__ import annotations

from open_range.catalog.assets import (
    asset_confidentiality_for_class,
    asset_placement_rule_for_id,
)
from open_range.manifest import ManifestAsset
from open_range.world_ir import AssetSpec


def place_assets(assets: tuple[ManifestAsset, ...]) -> tuple[AssetSpec, ...]:
    return tuple(place_asset(asset) for asset in assets)


def place_asset(asset: ManifestAsset) -> AssetSpec:
    rule = asset_placement_rule_for_id(asset.id)
    return AssetSpec(
        id=asset.id,
        asset_class=asset.asset_class,
        location=rule.location_template.format(asset_id=asset.id),
        owner_service=rule.owner_service,
        confidentiality=asset_confidentiality_for_class(asset.asset_class),
    )
