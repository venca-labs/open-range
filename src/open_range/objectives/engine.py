"""Shared predicate and graph reasoning for admission and runtime."""

from __future__ import annotations

from collections import deque
from collections.abc import Mapping
from dataclasses import dataclass

from open_range.contracts.world import AssetSpec, ServiceSpec, WeaknessSpec, WorldIR

from .evaluation import evaluate_red_objectives
from .expr import parse_predicate, predicate_inner
from .models import ObjectiveGraderSpec
from .resolution import resolve_objective


@dataclass(frozen=True, slots=True)
class PredicateEngine:
    """Shared objective, graph, and weakness reasoning over one immutable world."""

    world: WorldIR

    def resolve_objective(self, predicate: str):
        target_id = predicate_inner(predicate)
        asset = next(
            (item for item in self.world.assets if item.id == target_id),
            None,
        )
        return resolve_objective(
            predicate,
            owner_service=asset.owner_service if asset is not None else "",
            asset_location=asset.location if asset is not None else "",
            target_id=target_id,
            service_ids=frozenset(service.id for service in self.world.services),
        )

    def active_weaknesses(self) -> tuple[WeaknessSpec, ...]:
        return tuple(
            weakness
            for weakness in self.world.weaknesses
            if weakness.status == "seeded"
        )

    def objective_target_asset(self, predicate: str) -> AssetSpec | None:
        resolved = self.resolve_objective(predicate)
        if resolved.target_kind != "asset" or not resolved.target_id:
            return None
        for asset in self.world.assets:
            if asset.id == resolved.target_id:
                return asset
        return None

    def objective_target_service(self, predicate: str) -> str | None:
        resolved = self.resolve_objective(predicate)
        return resolved.target_service or None

    def objective_tags(self, predicate: str) -> tuple[str, ...]:
        return self.resolve_objective(predicate).objective_tags

    def objective_grader(self, predicate: str) -> ObjectiveGraderSpec | None:
        return self.resolve_objective(predicate).grader

    def is_groundable(self, predicate: str) -> bool:
        return self.resolve_objective(predicate).groundable

    def service_graph(self) -> dict[str, set[str]]:
        adjacency: dict[str, set[str]] = {
            service.id: set() for service in self.world.services
        }
        for service in self.world.services:
            for dep in service.dependencies:
                adjacency.setdefault(service.id, set()).add(dep)
                adjacency.setdefault(dep, set()).add(service.id)
        for edge in self.world.edges:
            if edge.kind not in {"network", "trust", "data"}:
                continue
            if edge.source in adjacency and edge.target in adjacency:
                adjacency[edge.source].add(edge.target)
                adjacency[edge.target].add(edge.source)
        return adjacency

    def shortest_path(self, start: str, target: str) -> tuple[str, ...]:
        if start == target:
            return (start,)
        adjacency = self.service_graph()
        queue: deque[tuple[str, tuple[str, ...]]] = deque([(start, (start,))])
        seen = {start}
        while queue:
            current, path = queue.popleft()
            for neighbor in sorted(adjacency.get(current, set())):
                if neighbor == target:
                    return path + (neighbor,)
                if neighbor in seen:
                    continue
                seen.add(neighbor)
                queue.append((neighbor, path + (neighbor,)))
        return (start, target)

    def reachable_from_any(self, starts: set[str], target: str) -> bool:
        if not starts:
            return False
        for start in starts:
            if target in self.shortest_path(start, target):
                return True
        return False

    def is_public_service(self, service: ServiceSpec) -> bool:
        return service.kind in {"web_app", "email"}

    def red_path_depth(self) -> int:
        start = next(
            (
                service.id
                for service in self.world.services
                if self.is_public_service(service)
            ),
            self.world.services[0].id,
        )
        target = (
            self.objective_target_service(self.world.red_objectives[0].predicate)
            or self.world.services[-1].id
        )
        return len(self.shortest_path(start, target))

    def red_alt_path_count(self) -> int:
        start_services = [
            service.id
            for service in self.world.services
            if self.is_public_service(service)
        ]
        target_services = {
            self.objective_target_service(objective.predicate)
            for objective in self.world.red_objectives
        }
        target_services.discard(None)
        adjacency = self.service_graph()
        reachable_starts = sum(
            1
            for start in start_services
            if any(
                target in _shortest_path(start, target, adjacency)
                for target in target_services
            )
        )
        return max(0, reachable_starts - 1)

    def benchmark_tags_covered(self) -> tuple[str, ...]:
        return tuple(
            sorted(
                {
                    tag
                    for weak in self.active_weaknesses()
                    for tag in weak.benchmark_tags
                }
            )
        )

    def objective_graders(self) -> tuple[ObjectiveGraderSpec, ...]:
        graders = []
        for objective in self.world.red_objectives:
            grader = self.objective_grader(objective.predicate)
            if grader is not None:
                graders.append(grader)
        return tuple(graders)

    def evaluate_red_objectives(
        self,
        *,
        snapshot: object,
        events: tuple[object, ...],
        service_health: Mapping[str, float],
    ) -> set[str]:
        graders = {
            objective.predicate: self.objective_grader(objective.predicate)
            for objective in self.world.red_objectives
        }
        return evaluate_red_objectives(
            snapshot=snapshot,
            objective_specs=self.world.red_objectives,
            graders=graders,
            events=events,
            service_health=service_health,
        )

    def red_terminal_satisfied(self, satisfied_predicates: set[str]) -> bool:
        required = {
            objective.predicate
            for objective in self.world.red_objectives
            if objective.terminal
        }
        return bool(required) and required <= satisfied_predicates

    def blue_terminal_satisfied(
        self,
        *,
        satisfied_predicates: set[str] | frozenset[str],
    ) -> bool:
        required = {
            objective.predicate
            for objective in self.world.blue_objectives
            if objective.terminal
        }
        return bool(required) and required <= set(satisfied_predicates)

    def supports_blue_objective(self, predicate: str) -> bool:
        expr = parse_predicate(predicate)
        if expr.name == "intrusion_detected":
            return expr.inner == "initial_access"
        if expr.name == "intrusion_contained":
            return expr.inner == "before_asset_read"
        if expr.name != "service_health_above":
            return False
        try:
            threshold = float(expr.inner)
        except ValueError:
            return False
        return 0.0 <= threshold <= 1.0

    def evaluate_blue_objectives(
        self,
        *,
        initial_access_detected: bool,
        contained_before_asset_read: bool,
        continuity: float,
    ) -> set[str]:
        satisfied: set[str] = set()
        for objective in self.world.blue_objectives:
            expr = parse_predicate(objective.predicate)
            if expr.name == "intrusion_detected":
                if expr.inner == "initial_access" and initial_access_detected:
                    satisfied.add(objective.predicate)
                continue
            if expr.name == "intrusion_contained":
                if expr.inner == "before_asset_read" and contained_before_asset_read:
                    satisfied.add(objective.predicate)
                continue
            if expr.name != "service_health_above":
                continue
            try:
                threshold = float(expr.inner)
            except ValueError:
                continue
            if continuity >= threshold:
                satisfied.add(objective.predicate)
        return satisfied


def predicate_engine(world: WorldIR) -> PredicateEngine:
    return PredicateEngine(world=world)


def _shortest_path(
    start: str, target: str, adjacency: dict[str, set[str]]
) -> tuple[str, ...]:
    if start == target:
        return (start,)
    queue: deque[tuple[str, tuple[str, ...]]] = deque([(start, (start,))])
    seen = {start}
    while queue:
        current, path = queue.popleft()
        for neighbor in sorted(adjacency.get(current, set())):
            if neighbor == target:
                return path + (neighbor,)
            if neighbor in seen:
                continue
            seen.add(neighbor)
            queue.append((neighbor, path + (neighbor,)))
    return (start, target)
