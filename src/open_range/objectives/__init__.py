"""Benchmark-aligned offensive objective helpers."""

from open_range.catalog.contracts import StandardAttackObjective
from open_range.objectives.evaluation import (
    evaluate_objective_grader,
    evaluate_red_objectives,
)
from open_range.objectives.live import evaluate_objective_grader_live
from open_range.objectives.models import ObjectiveGraderSpec, ResolvedObjectiveSpec
from open_range.objectives.resolution import (
    PUBLIC_OBJECTIVE_PREDICATE_NAMES,
    objective_event_for_predicate,
    objective_grader_for_predicate,
    objective_tags_for_predicate,
    resolve_objective,
    weakness_objective_tags,
)

__all__ = [
    "ObjectiveGraderSpec",
    "PUBLIC_OBJECTIVE_PREDICATE_NAMES",
    "ResolvedObjectiveSpec",
    "StandardAttackObjective",
    "evaluate_objective_grader",
    "evaluate_objective_grader_live",
    "evaluate_red_objectives",
    "objective_event_for_predicate",
    "objective_grader_for_predicate",
    "objective_tags_for_predicate",
    "resolve_objective",
    "weakness_objective_tags",
]
