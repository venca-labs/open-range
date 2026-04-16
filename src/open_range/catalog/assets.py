"""Catalog-backed asset placement rules for compiled world assets."""

from __future__ import annotations

from open_range.catalog.contracts import (
    AssetConfidentialitySpec,
    AssetPlacementRuleSpec,
)

ASSET_PLACEMENT_RULE_SPECS: tuple[AssetPlacementRuleSpec, ...] = (
    AssetPlacementRuleSpec(
        match_tokens=("db",),
        owner_service="svc-db",
        location_template="svc-db://main/{asset_id}",
    ),
    AssetPlacementRuleSpec(
        match_tokens=("doc", "file", "share"),
        owner_service="svc-fileshare",
        location_template="svc-fileshare:/srv/shared/{asset_id}.txt",
    ),
    AssetPlacementRuleSpec(
        match_tokens=("cred", "password", "token", "key"),
        owner_service="svc-idp",
        location_template="svc-idp://secrets/{asset_id}",
    ),
)

ASSET_CONFIDENTIALITY_SPECS: tuple[AssetConfidentialitySpec, ...] = (
    AssetConfidentialitySpec(
        asset_class="crown_jewel",
        confidentiality="critical",
    ),
    AssetConfidentialitySpec(
        asset_class="sensitive",
        confidentiality="high",
    ),
    AssetConfidentialitySpec(
        asset_class="operational",
        confidentiality="medium",
    ),
)

_DEFAULT_ASSET_PLACEMENT_RULE = AssetPlacementRuleSpec(
    match_tokens=(),
    owner_service="svc-web",
    location_template="svc-web:/var/www/html/content/{asset_id}.txt",
)

_CONFIDENTIALITY_BY_CLASS = {
    entry.asset_class: entry.confidentiality for entry in ASSET_CONFIDENTIALITY_SPECS
}


def asset_placement_rule_for_id(asset_id: str) -> AssetPlacementRuleSpec:
    normalized = asset_id.lower()
    for rule in ASSET_PLACEMENT_RULE_SPECS:
        if any(token in normalized for token in rule.match_tokens):
            return rule
    return _DEFAULT_ASSET_PLACEMENT_RULE


def asset_confidentiality_for_class(asset_class: str) -> str:
    return _CONFIDENTIALITY_BY_CLASS[asset_class]
