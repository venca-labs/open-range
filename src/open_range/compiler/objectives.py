"""Objective compilation helpers."""

from __future__ import annotations

from open_range.objectives import objective_tags_for_predicate
from open_range.objectives.expr import predicate_inner
from open_range.world_ir import AssetSpec, ObjectiveSpec


def compile_objectives(
    *,
    owner: str,
    predicates: tuple[str, ...],
    assets: tuple[AssetSpec, ...],
) -> tuple[ObjectiveSpec, ...]:
    return tuple(
        compile_objective(
            owner=owner,
            index=index,
            predicate=predicate,
            assets=assets,
        )
        for index, predicate in enumerate(predicates, start=1)
    )


def compile_objective(
    *,
    owner: str,
    index: int,
    predicate: str,
    assets: tuple[AssetSpec, ...],
) -> ObjectiveSpec:
    target = predicate_inner(predicate)
    asset = next((item for item in assets if item.id == target), None)
    objective_tags = objective_tags_for_predicate(
        predicate,
        asset_location=asset.location if asset is not None else "",
        owner_service=asset.owner_service if asset is not None else "",
        target_id=target,
    )
    return ObjectiveSpec(
        id=f"{owner}-{index}",
        owner=owner,
        predicate=predicate,
        objective_tags=objective_tags,
    )
