"""Decision-loop runtime with simulated time and internal green progression."""

from __future__ import annotations

from math import inf
from typing import Literal
from uuid import uuid4

from open_range.audit import ActionAuditor, command_text_for_action
from open_range.episode_config import DEFAULT_EPISODE_CONFIG, EpisodeConfig
from open_range.execution import ActionBackend, ActionExecution
from open_range.green import GreenScheduler, ScriptedGreenScheduler
from open_range.predicates import PredicateEngine
from open_range.probe_planner import runtime_action as reference_runtime_action
from open_range.rewards import RewardEngine
from open_range.runtime_events import (
    action_target,
    green_events_for_action,
    red_events_for_step,
)
from open_range.runtime_types import (
    Action,
    ActionResult,
    ActorSessionState,
    Decision,
    EpisodeScore,
    EpisodeState,
    ExternalRole,
    Observation,
    RuntimeEvent,
    ServiceHealth,
)
from open_range.snapshot import RuntimeSnapshot


class OpenRangeRuntime:
    """Decision-loop runtime for admitted snapshots with actor-specific decisions."""

    def __init__(
        self,
        *,
        green_scheduler: GreenScheduler | None = None,
        action_backend: ActionBackend | None = None,
    ) -> None:
        self.green_scheduler = green_scheduler or ScriptedGreenScheduler()
        self.action_backend = action_backend
        self.reward_engine = RewardEngine()
        self._snapshot: RuntimeSnapshot | None = None
        self._predicates: PredicateEngine | None = None
        self._episode_config = DEFAULT_EPISODE_CONFIG
        self._state = EpisodeState(snapshot_id="", episode_id="")
        self._events: list[RuntimeEvent] = []
        self._event_visibility: dict[str, dict[str, float]] = {}
        self._observed_event_ids = {"red": set(), "blue": set()}
        self._last_reward_delta = {"red": 0.0, "blue": 0.0}
        self._red_reward_shaping = 0.0
        self._blue_reward_shaping = 0.0
        self._red_progress = 0
        self._blue_progress = 0
        self._blue_detected = False
        self._blue_contained = False
        self._contained_targets: set[str] = set()
        self._patched_targets: set[str] = set()
        self._red_objectives_satisfied: set[str] = set()
        self._blue_objectives_satisfied: set[str] = set()
        self._detected_event_ids: set[str] = set()
        self._red_footholds: set[str] = set()
        self._last_red_target = ""
        self._event_seq = 0
        self._decision_seq = 0
        self._reset_seq = 0
        self._pending_actor: ExternalRole | Literal[""] = ""
        self._next_due_time = {"red": 0.0, "blue": 0.0}
        self._reference_attack_index = 0
        self._reference_defense_index = 0
        self._auditor: ActionAuditor | None = None

    def reset(
        self,
        snapshot: RuntimeSnapshot,
        episode_config: EpisodeConfig = DEFAULT_EPISODE_CONFIG,
        *,
        reference_attack_index: int | None = None,
        reference_defense_index: int | None = None,
    ) -> EpisodeState:
        self._snapshot = snapshot
        self._predicates = PredicateEngine(snapshot.world)
        self._episode_config = episode_config
        self._reset_seq += 1
        self.reward_engine.reset()
        self._events = []
        self._event_visibility = {}
        self._observed_event_ids = {"red": set(), "blue": set()}
        self._last_reward_delta = {"red": 0.0, "blue": 0.0}
        self._red_reward_shaping = 0.0
        self._blue_reward_shaping = 0.0
        self._red_progress = 0
        self._blue_progress = 0
        self._blue_detected = False
        self._blue_contained = False
        self._contained_targets = set()
        self._patched_targets = set()
        self._red_objectives_satisfied = set()
        self._blue_objectives_satisfied = set()
        self._detected_event_ids = set()
        self._red_footholds = set()
        self._last_red_target = ""
        self._event_seq = 0
        self._decision_seq = 0
        self._pending_actor = ""
        self._next_due_time = _initial_due_times(episode_config)
        self._reference_attack_index = self._resolve_reference_index(
            reference_attack_index,
            len(snapshot.reference_bundle.reference_attack_traces),
        )
        self._reference_defense_index = self._resolve_reference_index(
            reference_defense_index,
            len(snapshot.reference_bundle.reference_defense_traces),
            fallback=self._reference_attack_index,
        )
        self._auditor = ActionAuditor(episode_config.audit)
        self._auditor.bind_snapshot(snapshot)
        self._auditor.capture_baseline(self._capture_integrity)

        service_health = {service.id: 1.0 for service in snapshot.world.services}
        if self.action_backend is not None:
            live_health = self.action_backend.service_health()
            if live_health:
                service_health.update(live_health)
        continuity = (
            sum(service_health.values()) / len(service_health)
            if service_health
            else 1.0
        )
        self._state = EpisodeState(
            snapshot_id=snapshot.snapshot_id,
            episode_id=f"ep-{uuid4()}",
            sim_time=0.0,
            done=False,
            winner="",
            terminal_reason="",
            continuity=continuity,
            service_health=service_health,
            controls_red=episode_config.controls_red,
            controls_blue=episode_config.controls_blue,
            next_actor="",
            decision_count=0,
            red_session=ActorSessionState(
                session_id=f"red-{uuid4()}", actor_id="red", role="red"
            ),
            blue_session=ActorSessionState(
                session_id=f"blue-{uuid4()}", actor_id="blue", role="blue"
            ),
        )
        self.green_scheduler.reset(snapshot, episode_config)
        self._apply_prefix_start()
        self._advance_until_external_decision()
        return self.state()

    def set_action_backend(self, action_backend: ActionBackend | None) -> None:
        self.action_backend = action_backend

    def next_decision(self) -> Decision:
        if self._snapshot is None:
            raise RuntimeError("runtime must be reset before next_decision()")
        if self._state.done:
            raise RuntimeError(
                "episode is done; reset() is required before more decisions"
            )
        if not self._pending_actor:
            self._advance_until_external_decision()
        if self._state.done:
            raise RuntimeError(
                "episode is done; reset() is required before more decisions"
            )
        if not self._pending_actor:
            raise RuntimeError("no external decision is available")

        actor = self._pending_actor
        obs = self._build_observation(actor)
        self._decision_seq += 1
        self._state.decision_count += 1
        self._state.next_actor = actor
        return Decision(decision_id=f"dec-{self._decision_seq}", actor=actor, obs=obs)

    def act(self, actor: str, action: Action) -> ActionResult:
        if self._snapshot is None:
            raise RuntimeError("runtime must be reset before act()")
        if self._state.done:
            raise RuntimeError(
                "episode is done; reset() is required before more actions"
            )
        if actor not in {"red", "blue"}:
            raise ValueError("public act() only supports red and blue")
        if self._pending_actor != actor:
            raise RuntimeError(
                f"cannot act as {actor!r}; next actor is {self._pending_actor!r}"
            )
        if action.role != actor:
            raise ValueError("action.role must match the acting external role")

        result = self._act_red(action) if actor == "red" else self._act_blue(action)
        self._pending_actor = ""
        self._state.next_actor = ""
        self._advance_due_time(actor)
        self._check_terminal_conditions()
        return result.model_copy(
            update={
                "done": self._state.done,
                "sim_time": round(self._state.sim_time, 4),
            }
        )

    def score(self) -> EpisodeScore:
        red_terminal, blue_terminal = self.reward_engine.terminal_rewards(
            winner=self._state.winner,
            done=self._state.done,
        )
        audit = (
            self._auditor.build_summary(self._capture_integrity)
            if self._auditor is not None
            else None
        )
        return EpisodeScore(
            snapshot_id=self._state.snapshot_id,
            episode_id=self._state.episode_id,
            done=self._state.done,
            winner=self._state.winner,
            terminal_reason=self._state.terminal_reason,
            sim_time=round(self._state.sim_time, 4),
            continuity=self._state.continuity,
            red_reward=round(self._red_reward_shaping + red_terminal, 4),
            blue_reward=round(self._blue_reward_shaping + blue_terminal, 4),
            red_objectives_satisfied=tuple(sorted(self._red_objectives_satisfied)),
            blue_objectives_satisfied=tuple(sorted(self._blue_objectives_satisfied)),
            event_count=len(self._events),
            audit=audit,
        )

    def state(self) -> EpisodeState:
        self._state.red_objectives_satisfied = tuple(
            sorted(self._red_objectives_satisfied)
        )
        self._state.blue_objectives_satisfied = tuple(
            sorted(self._blue_objectives_satisfied)
        )
        self._state.next_actor = self._pending_actor
        return self._state.model_copy(deep=True)

    def close(self) -> None:
        self._snapshot = None
        self._predicates = None
        self._auditor = None
        self._pending_actor = ""
        self._state.done = True
        self._state.next_actor = ""

    def export_events(self) -> tuple[RuntimeEvent, ...]:
        return tuple(self._events)

    def reference_step(self, actor: ExternalRole):
        if actor == "red":
            return self._next_red_step()
        return self._next_blue_step()

    def remaining_red_targets(self) -> set[str]:
        return set(self._remaining_red_targets())

    @staticmethod
    def matches_reference_step(action: Action, expected, live_stdout: str) -> bool:
        return OpenRangeRuntime._matches_step(action, expected, live_stdout)

    def _apply_prefix_start(self) -> None:
        if self._snapshot is None:
            return
        if (
            self._episode_config.mode != "blue_only_from_prefix"
            or self._episode_config.start_state == "clean"
        ):
            return
        attack_trace = self._reference_attack_trace()
        if self._episode_config.start_state == "prefix_delivery":
            if not any(
                step.payload.get("action") in {"deliver_phish", "deliver_lure"}
                for step in attack_trace.steps
            ):
                return
        if self._episode_config.start_state == "prefix_click":
            if not any(
                step.payload.get("action") == "click_lure"
                for step in attack_trace.steps
            ):
                return
        for _ in range(len(attack_trace.steps)):
            step = self._next_red_step()
            if step is None or self._state.done:
                break
            due = max(self._state.sim_time, self._next_due_time["red"])
            self._advance_time(due)
            emitted = self._act_red(
                reference_runtime_action("red", step), internal=True
            ).emitted_events
            self._advance_due_time("red")
            self._check_terminal_conditions()
            if self._prefix_satisfied(
                self._episode_config.start_state,
                step_action=str(step.payload.get("action", "")),
                emitted=emitted,
            ):
                break

    def _prefix_satisfied(
        self,
        start_state: str,
        *,
        step_action: str,
        emitted: tuple[RuntimeEvent, ...],
    ) -> bool:
        event_types = {event.event_type for event in emitted}
        if start_state == "prefix_delivery":
            return step_action in {"deliver_phish", "deliver_lure"}
        if start_state == "prefix_click":
            return step_action == "click_lure" or "InitialAccess" in event_types
        if start_state == "prefix_foothold":
            return "InitialAccess" in event_types
        if start_state == "prefix_credential_theft":
            return "CredentialObtained" in event_types
        if start_state == "prefix_lateral_movement":
            return "CrossZoneTraversal" in event_types or self._red_progress >= 2
        return False

    def _advance_until_external_decision(self) -> None:
        while not self._state.done and not self._pending_actor:
            actor, due_time = self._next_scheduled_actor()
            if actor is None:
                self._state.done = True
                self._state.winner = "failure"
                self._state.terminal_reason = "scheduler_exhausted"
                return
            if due_time > self._state.sim_time:
                self._advance_time(due_time)
                continue
            if self._is_controlled(actor):
                self._pending_actor = actor
                self._state.next_actor = actor
                return
            internal_action = self._internal_action(actor)
            if actor == "red":
                self._act_red(internal_action, internal=True)
            else:
                self._act_blue(internal_action, internal=True)
            self._advance_due_time(actor)
            self._check_terminal_conditions()

    def _next_scheduled_actor(self) -> tuple[ExternalRole | None, float]:
        candidates = sorted(
            (
                (role, due_time)
                for role, due_time in self._next_due_time.items()
                if not (
                    self._episode_config.mode == "blue_only_from_prefix"
                    and role == "red"
                )
            ),
            key=lambda item: (item[1], 0 if item[0] == "red" else 1),
        )
        if not candidates:
            return None, inf
        return candidates[0]

    def _advance_time(self, target_time: float) -> None:
        if self._state.done:
            return
        self._state.sim_time = round(target_time, 4)
        if self._state.sim_time >= self._episode_config.episode_horizon:
            self._state.done = True
            self._state.winner = "timeout"
            self._state.terminal_reason = "timeout"
            return
        self.green_scheduler.advance_until(self._state.sim_time)
        self._drain_green()

    def _drain_green(self) -> None:
        while not self._state.done:
            ready = self.green_scheduler.pop_ready_actions()
            if not ready:
                break
            for action in ready:
                self._act_green(action)
                if self._state.done:
                    return

    def _build_observation(self, actor: ExternalRole) -> Observation:
        visible = self._visible_events(actor)
        alerts = tuple(
            event
            for event in visible
            if event.malicious
            or event.event_type
            in {
                "DetectionAlertRaised",
                "ContainmentApplied",
                "PatchApplied",
                "ServiceDegraded",
            }
        )
        reward_delta = self._last_reward_delta[actor]
        self._last_reward_delta[actor] = 0.0
        self._observed_event_ids[actor].update(event.id for event in visible)
        session = (
            self._state.red_session if actor == "red" else self._state.blue_session
        )
        first_observation = session is not None and session.observation_count == 0
        if session is not None:
            session.observation_count += 1
        stdout = self._observation_stdout(actor, first_observation=first_observation)
        return Observation(
            actor_id=actor,
            sim_time=round(self._state.sim_time, 4),
            stdout=stdout,
            visible_events=visible,
            alerts_delta=alerts,
            service_health=self._service_health_tuple(),
            reward_delta=reward_delta,
            done=self._state.done,
        )

    def _act_green(self, action: Action) -> ActionResult:
        target = action_target(action)
        live = self._execute_live_action(action)
        emitted = (
            green_events_for_action(
                action,
                live_recovery_applied=live.recovery_applied,
                target=target,
                emit_event=self._emit_event,
                service_surfaces=self._service_surfaces,
            )
            if live.ok
            else ()
        )
        self._state.sim_time = round(
            min(self._state.sim_time + 0.01, self._episode_config.episode_horizon), 4
        )
        return ActionResult(
            action=action,
            sim_time=self._state.sim_time,
            stdout=live.stdout or f"green routine executed on {target}",
            stderr=live.stderr,
            emitted_events=emitted,
            reward_delta=0.0,
            done=self._state.done,
        )

    def _act_red(self, action: Action, *, internal: bool = False) -> ActionResult:
        if self._state.red_session is not None:
            self._state.red_session.action_count += 1

        emitted: list[RuntimeEvent] = []
        target = action_target(action)
        exec_action = action
        if self.action_backend is not None:
            payload = dict(action.payload)
            payload.setdefault("origin", self._live_red_origin(target))
            if target:
                payload.setdefault("target", target)
            exec_action = action.model_copy(update={"payload": payload})
        live = self._execute_live_action(exec_action)
        audit = self._observe_action(
            exec_action,
            live,
            controlled=not internal,
        )
        emit_event = self._audit_emit_event(audit)
        stdout = live.stdout or "red action had no strategic effect"
        stderr = live.stderr

        expected = self._next_red_step()
        blocked_reason = self._path_block_reason(target)
        if blocked_reason:
            blocked_msg = f"target {target} is {blocked_reason}"
            if blocked_msg not in {
                line.strip() for line in stderr.splitlines() if line.strip()
            }:
                stderr = "\n".join(filter(None, [stderr, blocked_msg])).strip()
        elif (
            expected is not None
            and live.ok
            and self._matches_step(action, expected, live.stdout)
        ):
            self._red_progress += 1
            stdout = f"red advanced on {target}"
            batch = red_events_for_step(
                expected,
                action,
                last_red_target=self._last_red_target,
                emit_event=emit_event,
                service_surfaces=self._service_surfaces,
            )
            emitted = list(batch.events)
            self._red_objectives_satisfied.update(batch.satisfied_objectives)
            self._last_red_target = batch.last_red_target
            if batch.last_red_target:
                self._red_footholds.add(batch.last_red_target)
        else:
            stdout = live.stdout or f"red executed on {target or 'unknown target'}"

        reward_delta = self.reward_engine.on_red_action(
            action,
            tuple(emitted),
            shaping_enabled=self._episode_config.red_shaping_enabled,
            hallucination_penalty_enabled=self._episode_config.hallucination_penalty_enabled,
        )
        self._red_reward_shaping += reward_delta
        if not internal:
            self._last_reward_delta["red"] += reward_delta
        self._append_suspicious_audit_event(exec_action, audit, emitted)
        self._record_action_audit(audit, emitted)

        return ActionResult(
            action=action,
            sim_time=round(self._state.sim_time, 4),
            stdout=stdout,
            stderr=stderr,
            emitted_events=tuple(emitted),
            reward_delta=reward_delta,
            done=self._state.done,
        )

    def _act_blue(self, action: Action, *, internal: bool = False) -> ActionResult:
        if self._state.blue_session is not None:
            self._state.blue_session.action_count += 1

        emitted: list[RuntimeEvent] = []
        reward_delta = 0.0
        expected_reference = self._next_blue_step()
        live = self._execute_live_action(action)
        audit = self._observe_action(action, live, controlled=not internal)
        emit_event = self._audit_emit_event(audit)
        stdout = live.stdout or "blue action applied"
        stderr = live.stderr

        if action.kind == "submit_finding":
            event_type = str(
                action.payload.get("event_type", action.payload.get("event", ""))
            )
            target = str(action.payload.get("target", ""))
            matched = self._find_detectable_event(event_type, target, visible_only=True)
            if matched is not None:
                emitted.append(
                    emit_event(
                        event_type="DetectionAlertRaised",
                        actor="blue",
                        source_entity="blue",
                        target_entity=matched.target_entity,
                        malicious=False,
                        observability_surfaces=("svc-siem",),
                        linked_objective_predicates=(
                            "intrusion_detected(initial_access)",
                        ),
                    )
                )
                self._blue_detected = True
                self._blue_objectives_satisfied.add(
                    "intrusion_detected(initial_access)"
                )
                self._detected_event_ids.add(matched.id)
                reward_delta += self.reward_engine.on_blue_detection(
                    matched,
                    shaping_enabled=self._episode_config.blue_detection_shaping,
                    false_positive_penalty_enabled=self._episode_config.false_positive_penalty_enabled,
                )
                stdout = f"validated finding for {matched.event_type}"
            else:
                reward_delta += self.reward_engine.on_blue_detection(
                    None,
                    shaping_enabled=self._episode_config.blue_detection_shaping,
                    false_positive_penalty_enabled=self._episode_config.false_positive_penalty_enabled,
                )
                stdout = "finding rejected as false positive"
        elif action.kind == "control":
            target = action_target(action)
            directive = str(action.payload.get("action", "contain")).lower()
            remaining_targets = self._remaining_red_targets()
            continuity_before = self._state.continuity
            path_broken = bool(
                target
                and target in remaining_targets
                and (live.containment_applied or live.patch_applied)
            )
            if target and live.containment_applied:
                self._contained_targets.add(target)
                self._patched_targets.discard(target)
                emitted.append(
                    emit_event(
                        event_type="ContainmentApplied",
                        actor="blue",
                        source_entity="blue",
                        target_entity=target,
                        malicious=False,
                        observability_surfaces=("svc-siem",),
                        linked_objective_predicates=(
                            "intrusion_contained(before_asset_read)",
                        )
                        if path_broken
                        else (),
                    )
                )
            elif target and live.patch_applied:
                self._patched_targets.add(target)
                self._contained_targets.discard(target)
                emitted.append(
                    emit_event(
                        event_type="PatchApplied",
                        actor="blue",
                        source_entity="blue",
                        target_entity=target,
                        malicious=False,
                        observability_surfaces=("svc-siem",),
                        linked_objective_predicates=(
                            "intrusion_contained(before_asset_read)",
                        )
                        if path_broken
                        else (),
                    )
                )
            elif target and live.recovery_applied:
                self._contained_targets.discard(target)
                self._patched_targets.discard(target)
                emitted.append(
                    emit_event(
                        event_type="RecoveryCompleted",
                        actor="blue",
                        source_entity="blue",
                        target_entity=target,
                        malicious=False,
                        observability_surfaces=("svc-siem",),
                    )
                )

            if path_broken:
                self._blue_contained = True
                self._blue_objectives_satisfied.add(
                    "intrusion_contained(before_asset_read)"
                )
                if live.patch_applied:
                    if directive == "mitigate":
                        stdout = f"mitigation applied to {target}"
                    else:
                        stdout = f"patch applied to {target}"
                else:
                    stdout = f"containment applied to {target}"
                self._update_continuity()
                reward_delta += self.reward_engine.on_blue_containment(
                    target=target,
                    path_broken=True,
                    continuity_before=continuity_before,
                    continuity_after=self._state.continuity,
                    shaping_enabled=self._episode_config.blue_containment_shaping,
                )
            else:
                if live.recovery_applied:
                    stdout = (
                        live.stdout
                        or f"recovery applied to {target or 'unknown target'}"
                    )
                elif live.patch_applied:
                    noun = "mitigation" if directive == "mitigate" else "patch"
                    stdout = (
                        live.stdout
                        or f"{noun} on {target or 'unknown target'} did not break the remaining path"
                    )
                elif directive == "contain":
                    stdout = (
                        live.stdout
                        or f"control action on {target or 'unknown target'} had no path-breaking effect"
                    )
                else:
                    stdout = (
                        live.stdout
                        or f"{directive} on {target or 'unknown target'} had no path-breaking effect"
                    )
                self._update_continuity()
                reward_delta += self.reward_engine.on_blue_containment(
                    target=target,
                    path_broken=False,
                    continuity_before=continuity_before,
                    continuity_after=self._state.continuity,
                    shaping_enabled=self._episode_config.blue_containment_shaping,
                )
        elif action.kind == "sleep":
            stdout = "blue slept"
        else:
            stdout = live.stdout or f"blue executed {action.kind}"

        self._blue_reward_shaping += reward_delta
        if not internal:
            self._last_reward_delta["blue"] += reward_delta
        if expected_reference is not None and self._matches_step(
            action, expected_reference, live.stdout
        ):
            self._blue_progress += 1
        self._append_suspicious_audit_event(action, audit, emitted)
        self._record_action_audit(audit, emitted)

        return ActionResult(
            action=action,
            sim_time=round(self._state.sim_time, 4),
            stdout=stdout,
            stderr=stderr,
            emitted_events=tuple(emitted),
            reward_delta=reward_delta,
            done=self._state.done,
        )

    def _next_red_step(self):
        if self._snapshot is None:
            return None
        trace = self._reference_attack_trace()
        if self._red_progress >= len(trace.steps):
            return None
        return trace.steps[self._red_progress]

    def _live_red_origin(self, target: str) -> str:
        if not target or self._snapshot is None or self._predicates is None:
            return self._last_red_target or "sandbox-red"
        service_ids = {service.id for service in self._snapshot.world.services}
        candidate_ids = service_ids & self._red_footholds
        if self._last_red_target in service_ids:
            candidate_ids.add(self._last_red_target)
        reachable = {
            origin
            for origin in candidate_ids
            if self._foothold_can_reach_target(origin, target)
        }
        if not reachable:
            return self._last_red_target or "sandbox-red"
        return min(
            reachable,
            key=lambda origin: (
                len(self._predicates.shortest_path(origin, target)),
                origin,
            ),
        )

    def _foothold_can_reach_target(self, origin: str, target: str) -> bool:
        if self._snapshot is None:
            return False
        origin_zone = self._service_zone(origin)
        target_zone = self._service_zone(target)
        if not origin_zone or not target_zone:
            return False
        return self._zone_can_reach(origin_zone, target_zone)

    def _service_zone(self, service_id: str) -> str:
        snapshot = self._require_snapshot()
        host_zone_by_id = {host.id: host.zone for host in snapshot.world.hosts}
        service = next(
            (item for item in snapshot.world.services if item.id == service_id), None
        )
        if service is None:
            return ""
        return host_zone_by_id.get(service.host, "")

    def _zone_can_reach(self, from_zone: str, to_zone: str) -> bool:
        if from_zone == to_zone:
            return True
        snapshot = self._require_snapshot()
        rules = snapshot.artifacts.chart_values.get("firewallRules", ())
        return any(
            rule.get("action") == "allow"
            and rule.get("fromZone") == from_zone
            and rule.get("toZone") == to_zone
            for rule in rules
            if isinstance(rule, dict)
        )

    def _next_blue_step(self):
        if self._snapshot is None:
            return None
        trace = self._reference_defense_trace()
        if self._blue_progress >= len(trace.steps):
            return None
        return trace.steps[self._blue_progress]

    @staticmethod
    def _matches_step(action: Action, expected, live_stdout: str) -> bool:
        if action.kind != expected.kind or action_target(action) != expected.target:
            return False
        if action.kind == "api":
            expected_path = expected.payload.get("path")
            actual_path = action.payload.get("path")
            if (expected_path or actual_path) and actual_path != expected_path:
                return False
            expected_query = expected.payload.get("query")
            actual_query = action.payload.get("query")
            if (expected_query or actual_query) and actual_query != expected_query:
                return False
            expected_contains = str(expected.payload.get("expect_contains", "")).strip()
            if expected_contains and expected_contains not in live_stdout:
                return False
        if action.kind in {"shell", "mail"}:
            expected_path = expected.payload.get("path")
            actual_path = action.payload.get("path")
            if (expected_path or actual_path) and actual_path != expected_path:
                return False
            expected_contains = str(expected.payload.get("expect_contains", "")).strip()
            if expected_contains and expected_contains not in live_stdout:
                return False
        if action.kind == "control":
            expected_directive = expected.payload.get("action")
            if (
                expected_directive
                and action.payload.get("action") != expected_directive
            ):
                return False
        if action.kind == "submit_finding":
            expected_event = expected.payload.get(
                "event_type", expected.payload.get("event")
            )
            actual_event = action.payload.get("event_type", action.payload.get("event"))
            if expected_event and actual_event != expected_event:
                return False
        return True

    def _find_detectable_event(
        self,
        event_type: str,
        target: str,
        *,
        visible_only: bool,
    ) -> RuntimeEvent | None:
        for event in self._events:
            if not event.malicious:
                continue
            if event.event_type != event_type:
                continue
            if target and event.target_entity != target:
                continue
            if visible_only and not self._is_visible_to("blue", event):
                continue
            return event
        return None

    def _remaining_red_targets(self) -> set[str]:
        if self._snapshot is None:
            return set()
        trace = self._reference_attack_trace()
        return {step.target for step in trace.steps[self._red_progress :]}

    def _path_block_reason(self, target: str) -> str:
        if not target:
            return ""
        if target in self._patched_targets:
            return "patched"
        if target in self._contained_targets:
            return "contained"
        return ""

    def _check_terminal_conditions(self) -> None:
        self._refresh_red_objective_state()
        red_terminal = self._red_terminal_satisfied()
        blue_terminal = self._blue_terminal_satisfied(red_terminal)
        if red_terminal:
            self._state.done = True
            self._state.winner = "red"
            self._state.terminal_reason = "red_terminal"
            self._pending_actor = ""
            return
        if blue_terminal:
            self._state.done = True
            self._state.winner = "blue"
            self._state.terminal_reason = "blue_terminal"
            self._pending_actor = ""
            return
        if self._state.sim_time >= self._episode_config.episode_horizon:
            self._state.done = True
            self._state.winner = "timeout"
            self._state.terminal_reason = "timeout"
            self._pending_actor = ""

    def _red_terminal_satisfied(self) -> bool:
        if self._predicates is None:
            return False
        return self._predicates.red_terminal_satisfied(self._red_objectives_satisfied)

    def _blue_terminal_satisfied(self, red_terminal: bool) -> bool:
        if self._predicates is None:
            return False
        return self._predicates.blue_terminal_satisfied(
            red_terminal=red_terminal,
            blue_detected=self._blue_detected,
            blue_contained=self._blue_contained,
            continuity=self._state.continuity,
            continuity_threshold=self._episode_config.continuity_threshold,
            continuity_enforced=self._episode_config.continuity_enforced,
        )

    def _update_continuity(self) -> None:
        if not self._state.service_health:
            self._state.continuity = 1.0
            return
        self._state.continuity = sum(self._state.service_health.values()) / len(
            self._state.service_health
        )
        if (
            self._episode_config.continuity_enforced
            and self._state.continuity < self._episode_config.continuity_threshold
        ):
            self._blue_objectives_satisfied.discard("service_health_above(0.9)")
        elif self._episode_config.continuity_enforced:
            self._blue_objectives_satisfied.add("service_health_above(0.9)")

    def _service_health_tuple(self) -> tuple[ServiceHealth, ...]:
        return tuple(
            ServiceHealth(service_id=service_id, health=health)
            for service_id, health in sorted(self._state.service_health.items())
        )

    def _visible_events(self, actor: ExternalRole) -> tuple[RuntimeEvent, ...]:
        visible: list[RuntimeEvent] = []
        for event in self._events:
            if event.id in self._observed_event_ids[actor]:
                continue
            if not self._is_visible_to(actor, event):
                continue
            if event.event_type == "SuspiciousActionObserved":
                continue
            if actor == "blue":
                if event.observability_surfaces:
                    visible.append(event)
                continue
            if event.actor in {"green", "red"} or event.event_type in {
                "ContainmentApplied",
                "PatchApplied",
                "RecoveryCompleted",
                "ServiceDegraded",
            }:
                visible.append(event)
        return tuple(visible)

    def _is_visible_to(self, actor: ExternalRole, event: RuntimeEvent) -> bool:
        visible_at = self._event_visibility.get(event.id, {}).get(actor, inf)
        return visible_at <= self._state.sim_time

    def _emit_event(
        self,
        *,
        event_type: str,
        actor: Literal["red", "blue", "green"],
        source_entity: str,
        target_entity: str,
        malicious: bool,
        observability_surfaces: tuple[str, ...],
        linked_objective_predicates: tuple[str, ...] = (),
        suspicious: bool = False,
        suspicious_reasons: tuple[str, ...] = (),
        green_reactive: bool = True,
    ) -> RuntimeEvent:
        self._event_seq += 1
        event = RuntimeEvent(
            id=f"evt-{self._event_seq}",
            event_type=event_type,
            actor=actor,
            time=round(self._state.sim_time, 4),
            source_entity=source_entity,
            target_entity=target_entity,
            malicious=malicious,
            observability_surfaces=observability_surfaces,
            linked_objective_predicates=linked_objective_predicates,
            suspicious=suspicious,
            suspicious_reasons=suspicious_reasons,
        )
        self._events.append(event)
        blue_delay = self._blue_visibility_time(event, observability_surfaces)
        self._event_visibility[event.id] = {
            "red": self._state.sim_time,
            "blue": blue_delay,
        }
        if green_reactive:
            self.green_scheduler.record_event(event)
        if self.action_backend is not None:
            self.action_backend.record_event(event)
        return event

    def _blue_visibility_time(
        self,
        event: RuntimeEvent,
        observability_surfaces: tuple[str, ...],
    ) -> float:
        if not observability_surfaces:
            return inf
        blindspots = self._active_telemetry_blindspots()
        if event.malicious and {event.source_entity, event.target_entity} & blindspots:
            return inf
        delay = _telemetry_delay(self._episode_config)
        return self._state.sim_time + delay

    def _active_telemetry_blindspots(self) -> set[str]:
        if self._predicates is None:
            return set()
        return {
            weakness.target
            for weakness in self._predicates.active_weaknesses()
            if weakness.family == "telemetry_blindspot"
            and weakness.target not in self._patched_targets
        }

    def _service_surfaces(self, target: str) -> tuple[str, ...]:
        if self._snapshot is None:
            return ()
        for service in self._snapshot.world.services:
            if service.id == target:
                return tuple(service.telemetry_surfaces) + ("svc-siem",)
        return ("svc-siem",)

    def _refresh_red_objective_state(self) -> None:
        if self._snapshot is None or self._predicates is None:
            return
        self._red_objectives_satisfied = self._predicates.evaluate_red_objectives(
            snapshot=self._snapshot,
            events=tuple(self._events),
            service_health=self._state.service_health,
        )

    def _observation_stdout(
        self, actor: ExternalRole, *, first_observation: bool
    ) -> str:
        base = f"sim_time={self._state.sim_time:.2f}"
        if not first_observation or self._snapshot is None:
            return base
        return f"{self._briefing_text(actor)}\n{base}"

    def _briefing_text(self, actor: ExternalRole) -> str:
        world = self._require_snapshot().world
        objectives = world.red_objectives if actor == "red" else world.blue_objectives
        public_services = ",".join(
            service.id
            for service in world.services
            if self._predicates and self._predicates.is_public_service(service)
        )
        lines = [
            f"briefing_mode={self._episode_config.prompt_mode}",
            f"business={world.business_archetype}",
            f"public_services={public_services or 'none'}",
            f"objectives={'; '.join(objective.predicate for objective in objectives) or 'none'}",
        ]
        if self._episode_config.prompt_mode == "one_day":
            surfaces = ", ".join(
                self._briefing_surface_summary(world, weak)
                for weak in world.weaknesses
                if weak.family != "telemetry_blindspot" or actor == "blue"
            )
            lines.append(f"known_risky_surfaces={surfaces or 'none'}")
        return "\n".join(lines)

    @staticmethod
    def _briefing_surface_summary(world, weak) -> str:
        service = next(
            (service for service in world.services if service.id == weak.target), None
        )
        service_label = service.kind if service is not None else weak.target_kind
        family_label = {
            "code_web": "web surface",
            "config_identity": "identity surface",
            "secret_exposure": "secret surface",
            "workflow_abuse": "workflow surface",
            "telemetry_blindspot": "telemetry gap",
        }.get(weak.family, weak.family)
        return f"{service_label} {family_label}"

    def _execute_live_action(self, action: Action) -> ActionExecution:
        if self.action_backend is None:
            directive = str(action.payload.get("action", "contain")).lower()
            weakness_id = str(
                action.payload.get("weakness_id", action.payload.get("weakness", ""))
            ).strip()
            if action.kind in {"api", "shell", "mail"} and weakness_id:
                weakness = self._active_weakness(weakness_id)
                if weakness is None:
                    return ActionExecution(
                        stderr=f"weakness {weakness_id} unavailable", ok=False
                    )
                return ActionExecution(
                    stdout=str(action.payload.get("expect_contains", ""))
                    or f"exercised {weakness.kind}",
                )
            return ActionExecution(
                stdout=str(action.payload.get("expect_contains", ""))
                if action.kind in {"api", "shell", "mail"}
                else "",
                containment_applied=action.kind == "control" and directive == "contain",
                patch_applied=action.kind == "control"
                and directive in {"patch", "mitigate"},
                recovery_applied=action.kind == "control"
                and directive in {"recover", "restore"},
                executed_command=command_text_for_action(action),
                runner_service=action.payload.get("origin", action.actor_id),
                target_service=action_target(action),
            )
        result = self.action_backend.execute(action)
        if result.service_health:
            self._state.service_health.update(result.service_health)
            self._update_continuity()
        return result

    def _observe_action(
        self,
        action: Action,
        live: ActionExecution,
        *,
        controlled: bool,
    ):
        if self._auditor is None:
            return None
        return self._auditor.observe(
            action=action,
            executed_command=live.executed_command,
            audit_command=command_text_for_action(action),
            sim_time=self._state.sim_time,
            controlled=controlled,
        )

    def _audit_emit_event(self, audit):
        if audit is None or not audit.suspicious:
            return self._emit_event

        def emit_event(**kwargs):
            return self._emit_event(
                **kwargs,
                suspicious=True,
                suspicious_reasons=audit.matched_patterns,
            )

        return emit_event

    def _record_action_audit(self, audit, emitted: list[RuntimeEvent]) -> None:
        if self._auditor is None:
            return
        self._auditor.record(
            audit,
            emitted_event_ids=tuple(event.id for event in emitted),
        )

    def _append_suspicious_audit_event(
        self, action: Action, audit, emitted: list[RuntimeEvent]
    ) -> None:
        if audit is None or not audit.suspicious or emitted:
            return
        emitted.append(
            self._emit_event(
                event_type="SuspiciousActionObserved",
                actor=action.role,
                source_entity=action.actor_id,
                target_entity=action_target(action) or action.kind,
                malicious=action.role == "red",
                observability_surfaces=(),
                suspicious=True,
                suspicious_reasons=audit.matched_patterns,
                green_reactive=False,
            )
        )

    def _capture_integrity(self, service_paths):
        if self.action_backend is None:
            return ()
        capture_integrity = getattr(self.action_backend, "capture_integrity", None)
        if not callable(capture_integrity):
            return ()
        return capture_integrity(service_paths)

    def _advance_due_time(self, actor: ExternalRole) -> None:
        cadence = 1.0 if self._is_controlled(actor) else self._opponent_cadence(actor)
        self._next_due_time[actor] = round(
            max(self._next_due_time[actor], self._state.sim_time) + cadence, 4
        )

    def _is_controlled(self, actor: ExternalRole) -> bool:
        return self._state.controls_red if actor == "red" else self._state.controls_blue

    def _internal_action(self, actor: ExternalRole) -> Action:
        if actor == "red":
            return self._internal_red_action()
        return self._internal_blue_action()

    def _internal_red_action(self) -> Action:
        if self._resolved_opponent_mode("red") == "none":
            return Action(actor_id="red", role="red", kind="sleep", payload={})
        step = self._next_red_step()
        if step is None:
            return Action(actor_id="red", role="red", kind="sleep", payload={})
        return reference_runtime_action("red", step)

    def _internal_blue_action(self) -> Action:
        mode = self._resolved_opponent_mode("blue")
        if mode == "none":
            return Action(actor_id="blue", role="blue", kind="sleep", payload={})
        if mode in {"reference", "replay"}:
            step = self._next_blue_step()
            if step is None:
                return Action(actor_id="blue", role="blue", kind="sleep", payload={})
            return reference_runtime_action("blue", step)
        for event in self._visible_events("blue"):
            if event.malicious and event.id not in self._detected_event_ids:
                return Action(
                    actor_id="blue",
                    role="blue",
                    kind="submit_finding",
                    payload={
                        "event_type": event.event_type,
                        "target": event.target_entity,
                    },
                )
        remaining = sorted(self._remaining_red_targets() - self._contained_targets)
        if remaining and self._blue_detected:
            return Action(
                actor_id="blue",
                role="blue",
                kind="control",
                payload={"target": remaining[0], "action": "contain"},
            )
        return Action(actor_id="blue", role="blue", kind="sleep", payload={})

    def _resolved_opponent_mode(self, actor: ExternalRole) -> str:
        mode = (
            self._episode_config.opponent_red
            if actor == "red"
            else self._episode_config.opponent_blue
        )
        if mode != "checkpoint_pool":
            return mode
        if self._snapshot is None:
            return "scripted"
        if actor == "red":
            return "reference" if self._snapshot.seed % 2 == 0 else "frozen_policy"
        return "reference" if self._snapshot.seed % 2 == 0 else "scripted"

    def _opponent_cadence(self, actor: ExternalRole) -> float:
        mode = self._resolved_opponent_mode(actor)
        if actor == "red":
            if mode == "replay":
                return 0.75
            if mode == "frozen_policy":
                return 1.5
            if mode == "scripted":
                return 1.25
            return 1.0
        if mode == "replay":
            return 0.5
        if mode == "reference":
            return 0.75
        if mode == "frozen_policy":
            return 1.25
        return 1.0

    def _active_weakness(self, weakness_id: str):
        if self._predicates is None:
            return None
        return next(
            (
                weakness
                for weakness in self._predicates.active_weaknesses()
                if weakness.id == weakness_id
            ),
            None,
        )

    def _reference_attack_trace(self):
        traces = self._require_snapshot().reference_bundle.reference_attack_traces
        return traces[self._reference_attack_index % len(traces)]

    def _reference_defense_trace(self):
        traces = self._require_snapshot().reference_bundle.reference_defense_traces
        return traces[self._reference_defense_index % len(traces)]

    def _require_snapshot(self) -> RuntimeSnapshot:
        if self._snapshot is None:
            raise RuntimeError("runtime has no active snapshot")
        return self._snapshot

    def _resolve_reference_index(
        self,
        requested: int | None,
        count: int,
        *,
        fallback: int = 0,
    ) -> int:
        if count < 1:
            return 0
        if requested is not None:
            return requested % count
        return (fallback + self._reset_seq - 1) % count


def _initial_due_times(config: EpisodeConfig) -> dict[str, float]:
    if config.scheduler_mode == "strict_turns":
        return {"red": 0.0, "blue": 0.0}
    return {"red": 0.0, "blue": _telemetry_delay(config)}


def _telemetry_delay(config: EpisodeConfig) -> float:
    if not config.telemetry_delay_enabled:
        return 0.0
    if config.telemetry_delay_profile == "none":
        return 0.0
    if config.telemetry_delay_profile == "low":
        return 0.25
    if config.telemetry_delay_profile == "high":
        return 1.0
    return 0.5
