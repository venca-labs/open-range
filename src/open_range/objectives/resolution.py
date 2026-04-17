"""Objective resolution and grader construction."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from open_range.catalog.contracts import (
    ObjectiveRuleSpec,
    StandardAttackObjective,
)
from open_range.catalog.objectives import (
    objective_rule_for_predicate_name,
    public_objective_predicate_names,
    weakness_objective_tags_for_kind,
)

from .expr import PredicateExpr, parse_predicate
from .models import ObjectiveGraderSpec, ResolvedObjectiveSpec


@dataclass(frozen=True, slots=True)
class _ObjectiveContext:
    predicate: str
    owner_service: str = ""
    asset_location: str = ""
    target_id: str = ""
    default_service: str = ""
    service_ids: frozenset[str] = frozenset()

    def resolved_target(self, expr: PredicateExpr) -> str:
        return self.target_id or expr.inner

    def is_db_target(self, target_id: str) -> bool:
        return (
            self.owner_service == "svc-db"
            or "db" in target_id.lower()
            or "mysql" in self.asset_location.lower()
        )


TagGraderBuilder = Callable[[str, _ObjectiveContext], ObjectiveGraderSpec]
ObjectiveResolver = Callable[
    [ObjectiveRuleSpec, PredicateExpr, _ObjectiveContext], ResolvedObjectiveSpec
]


def _service_health_grader(
    resolved_target: str,
    ctx: _ObjectiveContext,
) -> ObjectiveGraderSpec:
    service_id = ctx.owner_service or ctx.default_service
    return ObjectiveGraderSpec(
        objective_tag="dos",
        grader_kind="service_health",
        service_id=service_id or resolved_target,
        target_id=resolved_target,
    )


def _file_grader(
    resolved_target: str,
    ctx: _ObjectiveContext,
    *,
    objective_tag: StandardAttackObjective,
) -> ObjectiveGraderSpec:
    return ObjectiveGraderSpec(
        objective_tag=objective_tag,
        grader_kind="file_exists",
        service_id=ctx.owner_service or ctx.default_service,
        target_id=resolved_target,
        path=_live_asset_probe_path(ctx.asset_location),
        expected_ref=resolved_target,
    )


def _db_grader(
    resolved_target: str,
    ctx: _ObjectiveContext,
    *,
    objective_tag: StandardAttackObjective,
    grader_kind: str,
) -> ObjectiveGraderSpec:
    return ObjectiveGraderSpec(
        objective_tag=objective_tag,
        grader_kind=grader_kind,
        service_id=ctx.owner_service or "svc-db",
        target_id=resolved_target,
        expected_ref=resolved_target,
    )


def _outbound_request_grader(
    resolved_target: str,
    ctx: _ObjectiveContext,
) -> ObjectiveGraderSpec:
    return ObjectiveGraderSpec(
        objective_tag="outbound_service",
        grader_kind="outbound_request",
        service_id=ctx.owner_service or ctx.default_service,
        target_id=resolved_target,
        expected_ref=resolved_target,
    )


def _event_present_grader(
    resolved_target: str,
    ctx: _ObjectiveContext,
    *,
    objective_tag: StandardAttackObjective,
    event_type: str,
) -> ObjectiveGraderSpec:
    return ObjectiveGraderSpec(
        objective_tag=objective_tag,
        grader_kind="event_present",
        service_id=ctx.owner_service or ctx.default_service or "svc-idp",
        target_id=resolved_target,
        event_type=event_type,
        expected_ref=resolved_target,
    )


def _build_grader_for_tag(
    tag: StandardAttackObjective,
    resolved_target: str,
    ctx: _ObjectiveContext,
) -> ObjectiveGraderSpec:
    return _TAG_GRADER_BUILDERS[tag](resolved_target, ctx)


def _resolved_target_service(
    rule: ObjectiveRuleSpec,
    resolved_target: str,
    ctx: _ObjectiveContext,
) -> str:
    def existing_or_fallback(*candidates: str) -> str:
        for candidate in candidates:
            if candidate and (not ctx.service_ids or candidate in ctx.service_ids):
                return candidate
        return sorted(ctx.service_ids)[0] if ctx.service_ids else ""

    if rule.target_kind == "asset":
        return existing_or_fallback(
            ctx.owner_service, ctx.default_service, rule.default_service or ""
        )
    if rule.target_kind == "service":
        if resolved_target and resolved_target in ctx.service_ids:
            return resolved_target
        return existing_or_fallback(
            ctx.default_service, rule.default_service or "", resolved_target
        )
    return existing_or_fallback(ctx.default_service, rule.default_service or "")


def _build_resolution_for_tag(
    rule: ObjectiveRuleSpec,
    tag: StandardAttackObjective,
    resolved_target: str,
    ctx: _ObjectiveContext,
) -> ResolvedObjectiveSpec:
    return ResolvedObjectiveSpec(
        predicate=ctx.predicate,
        objective_tags=(tag,),
        grader=_build_grader_for_tag(tag, resolved_target, ctx),
        target_kind=rule.target_kind,
        target_id=resolved_target,
        target_service=_resolved_target_service(rule, resolved_target, ctx),
        event_type=rule.event_type,
    )


def _resolve_observation_only(
    rule: ObjectiveRuleSpec,
    expr: PredicateExpr,
    ctx: _ObjectiveContext,
) -> ResolvedObjectiveSpec:
    resolved_target = ctx.resolved_target(expr)
    return ResolvedObjectiveSpec(
        predicate=ctx.predicate,
        target_kind=rule.target_kind,
        target_id=resolved_target,
        target_service=_resolved_target_service(rule, resolved_target, ctx),
        event_type=rule.event_type,
    )


def _resolve_direct_objective(
    rule: ObjectiveRuleSpec,
    expr: PredicateExpr,
    ctx: _ObjectiveContext,
) -> ResolvedObjectiveSpec:
    if rule.objective_tag is None:
        return ResolvedObjectiveSpec(predicate=ctx.predicate)
    return _build_resolution_for_tag(
        rule,
        rule.objective_tag,
        ctx.resolved_target(expr),
        ctx,
    )


def _resolve_asset_read(
    _rule: ObjectiveRuleSpec,
    expr: PredicateExpr,
    ctx: _ObjectiveContext,
) -> ResolvedObjectiveSpec:
    resolved_target = ctx.resolved_target(expr)
    tag: StandardAttackObjective = (
        "db_access" if ctx.is_db_target(resolved_target) else "file_access"
    )
    rule = objective_rule_for_predicate_name("asset_read")
    if rule is None:
        return ResolvedObjectiveSpec(predicate=ctx.predicate)
    return _build_resolution_for_tag(rule, tag, resolved_target, ctx)


def _resolve_credential_obtained(
    rule: ObjectiveRuleSpec,
    expr: PredicateExpr,
    ctx: _ObjectiveContext,
) -> ResolvedObjectiveSpec:
    resolved_target = ctx.resolved_target(expr)
    service_id = _resolved_target_service(rule, resolved_target, ctx) or "svc-idp"
    return ResolvedObjectiveSpec(
        predicate=ctx.predicate,
        objective_tags=("privilege_escalation",),
        grader=ObjectiveGraderSpec(
            objective_tag="privilege_escalation",
            grader_kind="event_present",
            service_id=service_id,
            target_id=resolved_target,
            event_type=rule.event_type,
            expected_ref=resolved_target,
        ),
        target_kind=rule.target_kind,
        target_id=resolved_target,
        target_service=service_id,
        event_type=rule.event_type,
    )


_TAG_GRADER_BUILDERS: dict[StandardAttackObjective, TagGraderBuilder] = {
    "dos": _service_health_grader,
    "file_access": lambda resolved_target, ctx: _file_grader(
        resolved_target,
        ctx,
        objective_tag="file_access",
    ),
    "file_creation": lambda resolved_target, ctx: _file_grader(
        resolved_target,
        ctx,
        objective_tag="file_creation",
    ),
    "db_access": lambda resolved_target, ctx: _db_grader(
        resolved_target,
        ctx,
        objective_tag="db_access",
        grader_kind="db_row_read",
    ),
    "db_modification": lambda resolved_target, ctx: _db_grader(
        resolved_target,
        ctx,
        objective_tag="db_modification",
        grader_kind="db_row_write",
    ),
    "outbound_service": _outbound_request_grader,
    "unauthorized_admin_login": lambda resolved_target, ctx: _event_present_grader(
        resolved_target,
        ctx,
        objective_tag="unauthorized_admin_login",
        event_type="UnauthorizedCredentialUse",
    ),
    "privilege_escalation": lambda resolved_target, ctx: _event_present_grader(
        resolved_target,
        ctx,
        objective_tag="privilege_escalation",
        event_type="PrivilegeEscalation",
    ),
}

_OBJECTIVE_RESOLVERS: dict[str, ObjectiveResolver] = {
    "observation_only": _resolve_observation_only,
    "direct_objective": _resolve_direct_objective,
    "asset_read": _resolve_asset_read,
    "credential_obtained": _resolve_credential_obtained,
}


def resolve_objective(
    predicate: str,
    *,
    owner_service: str = "",
    asset_location: str = "",
    target_id: str = "",
    default_service: str = "",
    service_ids: frozenset[str] | set[str] = frozenset(),
) -> ResolvedObjectiveSpec:
    expr = parse_predicate(predicate)
    rule = objective_rule_for_predicate_name(expr.name)
    if rule is None:
        return ResolvedObjectiveSpec(predicate=predicate)
    if "(" in expr.raw and not (target_id or expr.inner):
        return ResolvedObjectiveSpec(predicate=predicate)
    resolver = _OBJECTIVE_RESOLVERS.get(rule.resolution_kind)
    if resolver is None:
        return ResolvedObjectiveSpec(predicate=predicate)
    return resolver(
        rule,
        expr,
        _ObjectiveContext(
            predicate=predicate,
            owner_service=owner_service,
            asset_location=asset_location,
            target_id=target_id,
            default_service=default_service,
            service_ids=frozenset(service_ids),
        ),
    )


PUBLIC_OBJECTIVE_PREDICATE_NAMES: tuple[str, ...] = public_objective_predicate_names()


def weakness_objective_tags(
    family: str, kind: str
) -> tuple[StandardAttackObjective, ...]:
    return weakness_objective_tags_for_kind(family, kind)


def objective_tags_for_predicate(
    predicate: str,
    *,
    asset_location: str = "",
    owner_service: str = "",
    target_id: str = "",
) -> tuple[StandardAttackObjective, ...]:
    return resolve_objective(
        predicate,
        asset_location=asset_location,
        owner_service=owner_service,
        target_id=target_id,
    ).objective_tags


def objective_grader_for_predicate(
    predicate: str,
    *,
    owner_service: str = "",
    asset_location: str = "",
    target_id: str = "",
    default_service: str = "",
) -> ObjectiveGraderSpec | None:
    return resolve_objective(
        predicate,
        owner_service=owner_service,
        asset_location=asset_location,
        target_id=target_id,
        default_service=default_service,
    ).grader


def objective_event_for_predicate(
    predicate: str,
    *,
    owner_service: str = "",
    asset_location: str = "",
    target_id: str = "",
    default_service: str = "",
    service_ids: frozenset[str] | set[str] = frozenset(),
) -> tuple[str, str]:
    resolved = resolve_objective(
        predicate,
        owner_service=owner_service,
        asset_location=asset_location,
        target_id=target_id,
        default_service=default_service,
        service_ids=service_ids,
    )
    return (
        resolved.event_type,
        resolved.target_id or resolved.target_service,
    )


def _live_asset_probe_path(asset_location: str) -> str:
    if not asset_location:
        return ""
    if asset_location.startswith("/") or "://" in asset_location:
        return asset_location if asset_location.startswith("/") else ""
    prefix, sep, suffix = asset_location.partition(":")
    if prefix and sep and suffix.startswith("/"):
        return suffix
    return asset_location
