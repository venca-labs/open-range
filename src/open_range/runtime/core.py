"""Decision-loop runtime with simulated time and internal green progression."""

from __future__ import annotations

import os
from collections.abc import Callable
from math import inf
from typing import Literal
from uuid import uuid4

from open_range.agents.npc_scheduler import NPCGreenScheduler
from open_range.config import DEFAULT_EPISODE_CONFIG, EpisodeConfig
from open_range.contracts.runtime import (
    Action,
    ActionResult,
    ActorSessionState,
    Decision,
    EpisodeScore,
    EpisodeState,
    ExternalRole,
    Observation,
    RuntimeEvent,
    action_target,
    control_directive,
    finding_event_type,
)
from open_range.contracts.snapshot import RuntimeSnapshot
from open_range.objectives.engine import PredicateEngine
from open_range.runtime.briefing import observation_stdout, service_health_tuple
from open_range.runtime.events import (
    RuntimeEventLog,
    green_events_for_action,
    service_observability_surfaces,
    telemetry_blindspots,
)
from open_range.runtime.execution import (
    ActionBackend,
    ActionExecution,
    execute_runtime_action,
    prepare_red_execution,
)
from open_range.runtime.green import GreenScheduler, ScriptedGreenScheduler
from open_range.runtime.hooks import RuntimeHooks
from open_range.runtime.reducers import (
    continuity_for_service_health,
    emit_blue_action_event,
    evaluate_terminal_state,
    opponent_cadence,
    reduce_blue_control,
    reduce_blue_finding,
    reduce_observation_state,
    reduce_red_action,
    resolved_opponent_mode,
    select_internal_opponent_action,
    update_continuity_state,
)
from open_range.runtime.replay import (
    ReferencePlayback,
    action_for_reference_step,
    matches_reference_step,
    prefix_satisfied,
)
from open_range.runtime.rewards import RewardEngine


def _npc_credentials_present() -> bool:
    return bool(os.environ.get("NVIDIA_API_KEY") or os.environ.get("OPENAI_API_KEY"))


class OpenRangeRuntime:
    """Decision-loop runtime for admitted snapshots with actor-specific decisions."""

    def __init__(
        self,
        *,
        green_scheduler: GreenScheduler | None = None,
        action_backend: ActionBackend | None = None,
        event_sink: Callable[[RuntimeEvent], None] | None = None,
    ) -> None:
        self.green_scheduler = green_scheduler or ScriptedGreenScheduler()
        self.action_backend = action_backend
        self.reward_engine = RewardEngine()
        self._snapshot: RuntimeSnapshot | None = None
        self._predicates: PredicateEngine | None = None
        self._episode_config = DEFAULT_EPISODE_CONFIG
        self._state = EpisodeState(snapshot_id="", episode_id="")
        self._event_log = RuntimeEventLog()
        self._observed_event_ids = {"red": set(), "blue": set()}
        self._last_reward_delta = {"red": 0.0, "blue": 0.0}
        self._red_reward_shaping = 0.0
        self._blue_reward_shaping = 0.0
        self._red_progress = 0
        self._blue_progress = 0
        self._blue_detected = False
        self._blue_detected_initial_access = False
        self._blue_contained = False
        self._contained_targets: set[str] = set()
        self._patched_targets: set[str] = set()
        self._red_objectives_satisfied: set[str] = set()
        self._blue_objectives_satisfied: set[str] = set()
        self._detected_event_ids: set[str] = set()
        self._red_footholds: set[str] = set()
        self._last_red_target = ""
        self._decision_seq = 0
        self._reset_seq = 0
        self._pending_actor: ExternalRole | Literal[""] = ""
        self._next_due_time = {"red": 0.0, "blue": 0.0}
        self._reference_playback: ReferencePlayback | None = None
        self._hooks = RuntimeHooks(
            green_scheduler=self.green_scheduler,
            action_backend=action_backend,
            event_sink=event_sink,
        )

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
        self._event_log.reset()
        self._observed_event_ids = {"red": set(), "blue": set()}
        self._last_reward_delta = {"red": 0.0, "blue": 0.0}
        self._red_reward_shaping = 0.0
        self._blue_reward_shaping = 0.0
        self._red_progress = 0
        self._blue_progress = 0
        self._blue_detected = False
        self._blue_detected_initial_access = False
        self._blue_contained = False
        self._contained_targets = set()
        self._patched_targets = set()
        self._red_objectives_satisfied = set()
        self._blue_objectives_satisfied = set()
        self._detected_event_ids = set()
        self._red_footholds = set()
        self._last_red_target = ""
        self._decision_seq = 0
        self._pending_actor = ""
        self._next_due_time = _initial_due_times(episode_config)
        self._reference_playback = ReferencePlayback.resolve(
            snapshot,
            reset_seq=self._reset_seq,
            requested_attack_index=reference_attack_index,
            requested_defense_index=reference_defense_index,
        )
        if episode_config.green_branch_backend == "npc":
            if episode_config.npc_mode == "online":
                if not _npc_credentials_present():
                    raise RuntimeError(
                        "green_branch_backend='npc' with npc_mode='online' "
                        "requires NVIDIA_API_KEY or OPENAI_API_KEY"
                    )
                if not isinstance(self.green_scheduler, NPCGreenScheduler):
                    self.green_scheduler = NPCGreenScheduler(
                        model=episode_config.llm_model,
                        base_url=episode_config.llm_endpoint,
                    )
                    self._hooks.set_green_scheduler(self.green_scheduler)
            elif not isinstance(self.green_scheduler, ScriptedGreenScheduler):
                self.green_scheduler = ScriptedGreenScheduler()
                self._hooks.set_green_scheduler(self.green_scheduler)
        elif not isinstance(self.green_scheduler, ScriptedGreenScheduler):
            self.green_scheduler = ScriptedGreenScheduler()
            self._hooks.set_green_scheduler(self.green_scheduler)
        self._hooks.reset(snapshot, episode_config.audit)

        service_health = {service.id: 1.0 for service in snapshot.world.services}
        if self.action_backend is not None:
            live_health = self.action_backend.service_health()
            if live_health:
                service_health.update(live_health)
        continuity = continuity_for_service_health(service_health)
        self._state = EpisodeState(
            snapshot_id=snapshot.snapshot_id,
            episode_id=f"ep-{uuid4()}",
            sim_time=0.0,
            done=False,
            winner="",
            terminal_reason="",
            execution_mode="live" if self.action_backend is not None else "offline",
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
        self._refresh_blue_objectives()
        self._advance_until_external_decision()
        return self.state()

    def set_action_backend(self, action_backend: ActionBackend | None) -> None:
        self.action_backend = action_backend
        self._hooks.set_action_backend(action_backend)

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
            event_count=len(self._event_log),
            audit=self._hooks.build_audit_summary(),
        )

    def state(self) -> EpisodeState:
        self._state.execution_mode = (
            "live" if self.action_backend is not None else "offline"
        )
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
        self._reference_playback = None
        self._hooks.close()
        self._pending_actor = ""
        self._state.done = True
        self._state.next_actor = ""

    def export_events(self) -> tuple[RuntimeEvent, ...]:
        return self._event_log.export()

    def reference_step(self, actor: ExternalRole):
        if self._reference_playback is None:
            return None
        return self._reference_playback.next_step(
            actor,
            self._red_progress if actor == "red" else self._blue_progress,
        )

    def remaining_red_targets(self) -> set[str]:
        if self._snapshot is None or self._reference_playback is None:
            return set()
        trace = self._reference_playback.attack_trace()
        return {step.target for step in trace.steps[self._red_progress :]}

    def _apply_prefix_start(self) -> None:
        if self._snapshot is None or self._reference_playback is None:
            return
        if (
            self._episode_config.mode != "blue_only_from_prefix"
            or self._episode_config.start_state == "clean"
        ):
            return
        attack_trace = self._reference_playback.attack_trace()
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
            step = self.reference_step("red")
            if step is None or self._state.done:
                break
            due = max(self._state.sim_time, self._next_due_time["red"])
            self._advance_time(due)
            emitted = self._act_red(
                action_for_reference_step(self._snapshot, "red", step),
                internal=True,
            ).emitted_events
            self._advance_due_time("red")
            self._check_terminal_conditions()
            if prefix_satisfied(
                self._episode_config.start_state,
                step_action=str(step.payload.get("action", "")),
                emitted=emitted,
                red_progress=self._red_progress,
            ):
                break

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
            if (
                self._state.controls_red
                if actor == "red"
                else self._state.controls_blue
            ):
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
        bounded_time = min(target_time, self._episode_config.episode_horizon)
        self._state.sim_time = round(bounded_time, 4)
        if target_time >= self._episode_config.episode_horizon:
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
        visible = self._event_log.visible_events(
            actor,
            observed_event_ids=self._observed_event_ids[actor],
            sim_time=self._state.sim_time,
        )
        session = (
            self._state.red_session if actor == "red" else self._state.blue_session
        )
        transition = reduce_observation_state(
            visible_events=visible,
            previous_reward_delta=self._last_reward_delta[actor],
            observed_event_ids=self._observed_event_ids[actor],
            observation_count=(
                session.observation_count if session is not None else None
            ),
        )
        self._last_reward_delta[actor] = 0.0
        self._observed_event_ids[actor] = transition.observed_event_ids
        if session is not None and transition.next_observation_count is not None:
            session.observation_count = transition.next_observation_count
        stdout = observation_stdout(
            sim_time=self._state.sim_time,
            world=self._snapshot.world if self._snapshot is not None else None,
            actor=actor,
            first_observation=transition.first_observation,
            prompt_mode=self._episode_config.prompt_mode,
            predicates=self._predicates,
        )
        return Observation(
            actor_id=actor,
            sim_time=round(self._state.sim_time, 4),
            stdout=stdout,
            visible_events=visible,
            alerts_delta=transition.alerts,
            service_health=service_health_tuple(self._state.service_health),
            reward_delta=transition.reward_delta,
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

        target = action_target(action)
        exec_action, blocked_reason = prepare_red_execution(
            action,
            target=target,
            action_backend=self.action_backend,
            snapshot=self._snapshot,
            predicates=self._predicates,
            red_footholds=self._red_footholds,
            last_red_target=self._last_red_target,
            patched_targets=self._patched_targets,
            contained_targets=self._contained_targets,
        )
        live = self._execute_live_action(exec_action)
        audit = self._hooks.observe_action(
            exec_action,
            live,
            sim_time=self._state.sim_time,
            controlled=not internal,
        )
        emit_event = self._hooks.emit_event(audit, self._emit_event)
        expected = self.reference_step("red")
        reduction = reduce_red_action(
            action=action,
            target=target,
            live=live,
            blocked_reason=blocked_reason,
            matched_reference_step=(
                expected is not None
                and live.ok
                and matches_reference_step(action, expected, live.stdout)
            ),
            expected_reference_step=expected,
            last_red_target=self._last_red_target,
            emit_event=emit_event,
            service_surfaces=self._service_surfaces,
        )
        emitted = list(reduction.emitted_events)
        self._red_objectives_satisfied.update(reduction.satisfied_objectives)
        if reduction.progress_advanced:
            self._red_progress += 1
            self._last_red_target = reduction.advanced_target
            if reduction.advanced_target:
                self._red_footholds.add(reduction.advanced_target)

        reward_delta = self.reward_engine.on_red_action(
            action,
            reduction.emitted_events,
            shaping_enabled=self._episode_config.red_shaping_enabled,
            hallucination_penalty_enabled=self._episode_config.hallucination_penalty_enabled,
        )
        self._red_reward_shaping += reward_delta
        if not internal:
            self._last_reward_delta["red"] += reward_delta
        self._hooks.finalize_action(
            audit,
            action=exec_action,
            emitted=emitted,
            emit_event=self._emit_event,
        )

        return ActionResult(
            action=action,
            sim_time=round(self._state.sim_time, 4),
            stdout=reduction.stdout,
            stderr=reduction.stderr,
            emitted_events=tuple(emitted),
            reward_delta=reward_delta,
            done=self._state.done,
        )

    def _act_blue(self, action: Action, *, internal: bool = False) -> ActionResult:
        if self._state.blue_session is not None:
            self._state.blue_session.action_count += 1

        emitted: list[RuntimeEvent] = []
        reward_delta = 0.0
        expected_reference = self.reference_step("blue")
        live = self._execute_live_action(action)
        audit = self._hooks.observe_action(
            action,
            live,
            sim_time=self._state.sim_time,
            controlled=not internal,
        )
        emit_event = self._hooks.emit_event(audit, self._emit_event)
        stdout = live.stdout or "blue action applied"
        stderr = live.stderr

        if action.kind == "submit_finding":
            event_type = finding_event_type(action)
            target = str(action.payload.get("target", ""))
            matched = self._event_log.find_detectable_event(
                event_type,
                target,
                sim_time=self._state.sim_time,
                visible_only=True,
            )
            transition = reduce_blue_finding(
                matched_event=matched,
                detected_event_ids=self._detected_event_ids,
                blue_detected=self._blue_detected,
            )
            self._blue_detected = transition.blue_detected
            self._blue_detected_initial_access = (
                self._blue_detected_initial_access or transition.initial_access_detected
            )
            self._detected_event_ids = transition.detected_event_ids
            event = emit_blue_action_event(transition.event_spec, emit_event=emit_event)
            if event is not None:
                emitted.append(event)
            self._refresh_blue_objectives()
            reward_delta += self.reward_engine.on_blue_detection(
                matched,
                shaping_enabled=self._episode_config.blue_detection_shaping,
                false_positive_penalty_enabled=self._episode_config.false_positive_penalty_enabled,
            )
            stdout = transition.stdout
        elif action.kind == "control":
            target = action_target(action)
            directive = control_directive(action, default="contain")
            continuity_before = self._state.continuity
            transition = reduce_blue_control(
                target=target,
                directive=directive,
                live=live,
                remaining_red_targets=self.remaining_red_targets(),
                contained_targets=self._contained_targets,
                patched_targets=self._patched_targets,
                blue_contained=self._blue_contained,
            )
            self._contained_targets = transition.contained_targets
            self._patched_targets = transition.patched_targets
            self._blue_contained = transition.blue_contained
            event = emit_blue_action_event(transition.event_spec, emit_event=emit_event)
            if event is not None:
                emitted.append(event)

            stdout = transition.stdout
            self._state.continuity = update_continuity_state(self._state.service_health)
            self._refresh_blue_objectives()
            reward_delta += self.reward_engine.on_blue_containment(
                target=target,
                path_broken=transition.path_broken,
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
        if expected_reference is not None and matches_reference_step(
            action, expected_reference, live.stdout
        ):
            self._blue_progress += 1
        self._hooks.finalize_action(
            audit,
            action=action,
            emitted=emitted,
            emit_event=self._emit_event,
        )

        return ActionResult(
            action=action,
            sim_time=round(self._state.sim_time, 4),
            stdout=stdout,
            stderr=stderr,
            emitted_events=tuple(emitted),
            reward_delta=reward_delta,
            done=self._state.done,
        )

    def _check_terminal_conditions(self) -> None:
        (
            self._red_objectives_satisfied,
            winner,
            reason,
        ) = evaluate_terminal_state(
            self._predicates,
            snapshot=self._snapshot,
            events=self._event_log.export(),
            service_health=self._state.service_health,
            red_objectives_satisfied=self._red_objectives_satisfied,
            blue_objectives_satisfied=self._blue_objectives_satisfied,
            sim_time=self._state.sim_time,
            episode_horizon=self._episode_config.episode_horizon,
        )
        if winner:
            self._state.done = True
            self._state.winner = winner
            self._state.terminal_reason = reason
            self._pending_actor = ""

    def _emit_event(
        self,
        *,
        event_type: str,
        actor: Literal["red", "blue", "green"],
        source_entity: str,
        target_entity: str,
        malicious: bool,
        observability_surfaces: tuple[str, ...],
        detail: str | None = None,
        suspicious: bool = False,
        suspicious_reasons: tuple[str, ...] = (),
        green_reactive: bool = True,
    ) -> RuntimeEvent:
        active_weaknesses = (
            self._predicates.active_weaknesses() if self._predicates is not None else ()
        )
        return self._event_log.emit(
            sim_time=self._state.sim_time,
            event_type=event_type,
            actor=actor,
            source_entity=source_entity,
            target_entity=target_entity,
            malicious=malicious,
            observability_surfaces=observability_surfaces,
            detail=detail,
            suspicious=suspicious,
            suspicious_reasons=suspicious_reasons,
            telemetry_delay=_telemetry_delay(self._episode_config),
            blindspots=telemetry_blindspots(
                active_weaknesses,
                patched_targets=self._patched_targets,
            ),
            green_reactive=green_reactive,
            publish_event=self._hooks.publish_event,
        )

    def _service_surfaces(self, target: str) -> tuple[str, ...]:
        return service_observability_surfaces(
            self._snapshot.world.services if self._snapshot is not None else (),
            target,
        )

    def _execute_live_action(self, action: Action) -> ActionExecution:
        result = execute_runtime_action(
            action,
            action_backend=self.action_backend,
            predicates=self._predicates,
        )
        if result.service_health:
            self._state.service_health.update(result.service_health)
            self._state.continuity = update_continuity_state(self._state.service_health)
            self._refresh_blue_objectives()
        return result

    def _refresh_blue_objectives(self) -> None:
        if self._predicates is None:
            return
        self._blue_objectives_satisfied = self._predicates.evaluate_blue_objectives(
            initial_access_detected=self._blue_detected_initial_access,
            contained_before_asset_read=self._blue_contained,
            continuity=self._state.continuity,
        )

    def _advance_due_time(self, actor: ExternalRole) -> None:
        cadence = (
            1.0
            if (
                self._state.controls_red
                if actor == "red"
                else self._state.controls_blue
            )
            else opponent_cadence(
                actor,
                mode=resolved_opponent_mode(
                    self._episode_config.opponent_red
                    if actor == "red"
                    else self._episode_config.opponent_blue,
                    actor=actor,
                    snapshot_seed=(
                        None if self._snapshot is None else self._snapshot.seed
                    ),
                ),
            )
        )
        self._next_due_time[actor] = round(
            max(self._next_due_time[actor], self._state.sim_time) + cadence, 4
        )

    def _internal_action(self, actor: ExternalRole) -> Action:
        return select_internal_opponent_action(
            actor,
            mode=resolved_opponent_mode(
                self._episode_config.opponent_red
                if actor == "red"
                else self._episode_config.opponent_blue,
                actor=actor,
                snapshot_seed=None if self._snapshot is None else self._snapshot.seed,
            ),
            snapshot=self._snapshot,
            reference_step=self.reference_step(actor),
            visible_events=(
                self._event_log.visible_events(
                    "blue",
                    observed_event_ids=self._observed_event_ids["blue"],
                    sim_time=self._state.sim_time,
                )
                if actor == "blue"
                else ()
            ),
            detected_event_ids=self._detected_event_ids,
            remaining_red_targets=self.remaining_red_targets(),
            contained_targets=self._contained_targets,
            blue_detected=self._blue_detected,
        )


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
