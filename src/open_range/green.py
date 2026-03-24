"""Scripted green scheduler for runtime-owned enterprise activity."""

from __future__ import annotations

import random
from collections import defaultdict, deque
from math import floor
from typing import Any, Protocol

from open_range.episode_config import EpisodeConfig
from open_range.runtime_types import Action, RuntimeEvent
from open_range.snapshot import RuntimeSnapshot
from open_range.world_ir import GreenPersona


class GreenScheduler(Protocol):
    def reset(
        self, snapshot: RuntimeSnapshot, episode_config: EpisodeConfig
    ) -> None: ...
    def advance_until(self, sim_time: float) -> None: ...
    def pop_ready_actions(self) -> tuple[Action, ...]: ...
    def record_event(self, event: RuntimeEvent) -> None: ...


class ScriptedGreenScheduler:
    """Deterministic routine and branch scheduling owned by the runtime."""

    def __init__(self) -> None:
        self._snapshot: RuntimeSnapshot | None = None
        self._episode_config = EpisodeConfig()
        self._seed = 0
        self._last_advanced_slot = -1
        self._reactive_queue: dict[int, deque[Action]] = defaultdict(deque)
        self._scheduled_reactions: set[tuple[int, str, str]] = set()
        self._ready_actions: deque[Action] = deque()

    def reset(self, snapshot: RuntimeSnapshot, episode_config: EpisodeConfig) -> None:
        self._snapshot = snapshot
        self._episode_config = episode_config
        self._seed = snapshot.world.seed
        self._last_advanced_slot = -1
        self._reactive_queue = defaultdict(deque)
        self._scheduled_reactions = set()
        self._ready_actions = deque()

    def advance_until(self, sim_time: float) -> None:
        if self._snapshot is None or not self._episode_config.green_enabled:
            return
        goal_slot = max(0, floor(sim_time))
        for slot in range(self._last_advanced_slot + 1, goal_slot + 1):
            self._ready_actions.extend(self._routine_actions(slot))
            self._ready_actions.extend(self._reactive_actions(slot))
            self._last_advanced_slot = slot

    def pop_ready_actions(self) -> tuple[Action, ...]:
        actions = tuple(self._ready_actions)
        self._ready_actions.clear()
        return actions

    def record_event(self, event: RuntimeEvent) -> None:
        if (
            self._snapshot is None
            or not self._episode_config.green_enabled
            or not self._episode_config.green_branch_enabled
            or self._episode_config.green_branch_backend == "none"
            or not event.malicious
        ):
            return
        personas = sorted(
            self._snapshot.world.green_personas,
            key=lambda persona: (-persona.awareness, persona.id),
        )
        if not personas:
            return
        backend = self._episode_config.green_branch_backend
        slot = floor(event.time) + 1
        target = event.target_entity
        reaction_key = (slot, event.event_type, target)
        if reaction_key in self._scheduled_reactions:
            return
        self._scheduled_reactions.add(reaction_key)
        if backend == "scripted":
            self._schedule_scripted_reaction(event, personas, slot)
            return
        if backend == "small_llm":
            self._schedule_small_llm_reaction(event, personas, slot)
            return
        self._schedule_workflow_orchestrator_reaction(event, personas, slot)

    def _routine_actions(self, slot: int) -> tuple[Action, ...]:
        assert self._snapshot is not None
        if not self._episode_config.green_routine_enabled:
            return ()
        if self._episode_config.green_profile == "off":
            return ()
        personas = list(self._snapshot.world.green_personas)
        if not personas:
            return ()
        workload = self._snapshot.world.green_workload
        interval = max(1, workload.routine_interval_ticks)
        if slot % interval != 0:
            return ()

        rng = random.Random(self._seed + slot)
        personas.sort(key=lambda persona: persona.id)
        max_parallel = min(
            self._parallel_budget(workload.max_parallel_actions), len(personas)
        )
        chosen = (
            personas
            if max_parallel == len(personas)
            else rng.sample(personas, k=max_parallel)
        )
        chosen.sort(key=lambda persona: persona.id)

        actions = []
        for persona in chosen:
            routine = (
                persona.routine[slot % len(persona.routine)]
                if persona.routine
                else "browse_app"
            )
            service = _routine_service(routine)
            kind = "mail" if "mail" in routine else "api"
            actions.append(
                Action(
                    actor_id=persona.id,
                    role="green",
                    kind=kind,
                    payload={
                        "routine": routine,
                        "service": service,
                        "host": persona.home_host,
                        "mailbox": persona.mailbox,
                    },
                )
            )
        return tuple(actions)

    def _reactive_actions(self, slot: int) -> tuple[Action, ...]:
        if not self._episode_config.green_branch_enabled:
            self._reactive_queue.pop(slot, None)
            return ()
        actions: list[Action] = []
        budget = self._reactive_budget()
        while self._reactive_queue[slot] and len(actions) < budget:
            actions.append(self._reactive_queue[slot].popleft())
        if self._reactive_queue[slot]:
            self._reactive_queue[slot + 1].extend(self._reactive_queue[slot])
        self._reactive_queue.pop(slot, None)
        return tuple(actions)

    def _parallel_budget(self, base_budget: int) -> int:
        if self._episode_config.green_profile == "off":
            return 0
        if self._episode_config.green_profile == "low":
            return max(1, base_budget // 2)
        if self._episode_config.green_profile == "high":
            return base_budget + 1
        return base_budget

    def _reactive_budget(self) -> int:
        assert self._snapshot is not None
        base_budget = self._snapshot.world.green_workload.reactive_branch_budget
        if self._episode_config.green_branch_backend == "workflow_orchestrator":
            base_budget += 2
        elif self._episode_config.green_branch_backend == "small_llm":
            base_budget += 1
        if self._episode_config.green_profile == "off":
            return 0
        if self._episode_config.green_profile == "low":
            return max(0, base_budget - 1)
        if self._episode_config.green_profile == "high":
            return base_budget + 1
        return base_budget

    def _schedule_scripted_reaction(
        self, event: RuntimeEvent, personas: list[Any], slot: int
    ) -> None:
        reporter = personas[0]
        self._reactive_queue[slot].append(
            self._report_action(reporter.id, event.target_entity, event.event_type)
        )
        if event.event_type in {"CredentialObtained", "UnauthorizedCredentialUse"}:
            self._reactive_queue[slot].append(
                self._recover_action(reporter.id, event.target_entity)
            )

    def _schedule_small_llm_reaction(
        self, event: RuntimeEvent, personas: list[Any], slot: int
    ) -> None:
        reporter = max(
            personas,
            key=lambda persona: (
                round(
                    persona.awareness
                    - (self._susceptibility_score(persona, event) * 0.4),
                    4,
                ),
                persona.id,
            ),
        )
        delay = 2 if event.event_type == "InitialAccess" else 1
        llm_slot = slot + delay - 1
        self._reactive_queue[llm_slot].append(
            self._report_action(
                reporter.id, event.target_entity, event.event_type, depth=40
            )
        )
        if event.event_type in {
            "CredentialObtained",
            "UnauthorizedCredentialUse",
        } and reporter.awareness >= (self._susceptibility_score(reporter, event) * 0.8):
            self._reactive_queue[llm_slot].append(
                self._recover_action(reporter.id, event.target_entity)
            )

    @staticmethod
    def _susceptibility_score(persona: GreenPersona, event: RuntimeEvent) -> float:
        if not persona.susceptibility:
            return 0.0
        event_key = _event_susceptibility_key(event.event_type)
        if event_key in persona.susceptibility:
            return persona.susceptibility[event_key]
        return max(persona.susceptibility.values())

    def _schedule_workflow_orchestrator_reaction(
        self, event: RuntimeEvent, personas: list[Any], slot: int
    ) -> None:
        reporter = personas[0]
        self._reactive_queue[slot].append(
            self._report_action(reporter.id, event.target_entity, event.event_type)
        )
        self._reactive_queue[slot].append(
            Action(
                actor_id=reporter.id,
                role="green",
                kind="shell",
                payload={
                    "target": "svc-siem",
                    "command": "printf '%s\n' openrange-ticket >> /tmp/openrange-green-ticket",
                    "branch": "open_it_ticket",
                    "reported_target": event.target_entity,
                    "reported_event_type": event.event_type,
                },
            )
        )
        if event.event_type in {
            "CredentialObtained",
            "UnauthorizedCredentialUse",
            "InitialAccess",
        }:
            self._reactive_queue[slot].append(
                self._recover_action(reporter.id, event.target_entity)
            )

    @staticmethod
    def _report_action(
        actor_id: str, target: str, event_type: str, *, depth: int = 20
    ) -> Action:
        return Action(
            actor_id=actor_id,
            role="green",
            kind="shell",
            payload={
                "target": "svc-siem",
                "command": f"wget -qO- http://svc-siem:9200/all.log | tail -n {depth}",
                "branch": "report_suspicious_activity",
                "reported_target": target,
                "reported_event_type": event_type,
            },
        )

    @staticmethod
    def _recover_action(actor_id: str, target: str) -> Action:
        return Action(
            actor_id=actor_id,
            role="green",
            kind="control",
            payload={
                "target": "svc-idp",
                "action": "recover",
                "branch": "reset_password",
                "reported_target": target,
            },
        )


def _routine_service(routine: str) -> str:
    lowered = routine.lower()
    if "mail" in lowered:
        return "svc-email"
    if "file" in lowered or "share" in lowered:
        return "svc-fileshare"
    if "idp" in lowered or "password" in lowered:
        return "svc-idp"
    if "alert" in lowered or "triage" in lowered:
        return "svc-siem"
    if "payroll" in lowered:
        return "svc-db"
    return "svc-web"


def _event_susceptibility_key(event_type: str) -> str:
    chunks: list[str] = []
    token: list[str] = []
    for char in event_type:
        if char.isupper() and token:
            chunks.append("".join(token).lower())
            token = [char]
            continue
        token.append(char)
    if token:
        chunks.append("".join(token).lower())
    return "_".join(chunks)
