from __future__ import annotations

import gc
import statistics
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from open_range._runtime_store import hydrate_runtime_snapshot
from open_range.admit import LocalAdmissionController
from open_range.cluster import ExecResult
from open_range.code_web import code_web_payload
from open_range.compiler import EnterpriseSaaSManifestCompiler
from open_range.episode_config import EpisodeConfig
from open_range.execution import PodActionBackend
from open_range.green import ScriptedGreenScheduler
from open_range.probe_planner import runtime_action
from open_range.render import EnterpriseSaaSKindRenderer
from open_range.runtime import OpenRangeRuntime
from open_range.runtime_types import Action, RuntimeEvent
from open_range.store import FileSnapshotStore
from open_range.synth import EnterpriseSaaSWorldSynthesizer
from open_range.weaknesses import CatalogWeaknessSeeder
from tests.support import OFFLINE_BUILD_CONFIG, manifest_payload


def _manifest_payload() -> dict:
    return manifest_payload()


def _snapshot(tmp_path: Path):
    world = CatalogWeaknessSeeder().apply(
        EnterpriseSaaSManifestCompiler().compile(_manifest_payload())
    )
    synth = EnterpriseSaaSWorldSynthesizer().synthesize(world, tmp_path / "synth")
    artifacts = EnterpriseSaaSKindRenderer().render(world, synth, tmp_path / "rendered")
    reference_bundle, report = LocalAdmissionController(mode="fail_fast").admit(
        world, artifacts, OFFLINE_BUILD_CONFIG
    )
    store = FileSnapshotStore(tmp_path / "snapshots")
    return hydrate_runtime_snapshot(
        store, store.create(world, artifacts, reference_bundle, report, synth=synth)
    )


def _code_web_response(
    snapshot, cmd: str, patched_services: set[str]
) -> ExecResult | None:
    weakness = next(
        (weak for weak in snapshot.world.weaknesses if weak.family == "code_web"), None
    )
    if weakness is None or weakness.target in patched_services:
        return None
    payload = code_web_payload(snapshot.world, weakness)
    path = str(payload.get("path", ""))
    if "http://svc-web:80" not in cmd or path not in cmd:
        return None
    return ExecResult(
        stdout=str(payload.get("expect_contains", "")), stderr="", exit_code=0
    )


def _benchmark_runtime_ms_per_action(
    snapshot, *, audit_enabled: bool, action_count: int
) -> float:
    runtime = OpenRangeRuntime()
    runtime.reset(
        snapshot,
        EpisodeConfig(
            mode="joint_pool",
            green_enabled=False,
            episode_horizon_minutes=float(action_count),
            audit={"enabled": audit_enabled},
        ),
    )

    start = time.perf_counter_ns()
    for _ in range(action_count):
        decision = runtime.next_decision()
        if decision.actor == "red":
            action = Action(
                actor_id="red",
                role="red",
                kind="shell",
                payload={
                    "command": "bash -lc 'git clone https://example.com/upstream.git'"
                },
            )
        else:
            action = Action(actor_id="blue", role="blue", kind="sleep", payload={})
        runtime.act(decision.actor, action)
    runtime.score()
    elapsed_ns = time.perf_counter_ns() - start
    return elapsed_ns / 1_000_000 / action_count


def test_joint_pool_next_decision_returns_actor_specific_observations(tmp_path: Path):
    snapshot = _snapshot(tmp_path)
    runtime = OpenRangeRuntime()
    state = runtime.reset(
        snapshot,
        EpisodeConfig(mode="joint_pool", green_enabled=False),
    )

    assert state.controls_red is True
    assert state.controls_blue is True
    assert state.next_actor == "red"

    first_red = snapshot.reference_bundle.reference_attack_traces[0].steps[0]
    red_decision = runtime.next_decision()
    assert red_decision.actor == "red"
    assert red_decision.obs.actor_id == "red"
    assert red_decision.obs.sim_time == 0.0
    assert "briefing_mode=zero_day" in red_decision.obs.stdout
    assert "known_risky_surfaces" not in red_decision.obs.stdout

    runtime.act(
        "red",
        Action(
            actor_id="red",
            role="red",
            kind=first_red.kind,
            payload={"target": first_red.target, **first_red.payload},
        ),
    )

    blue_decision = runtime.next_decision()
    assert blue_decision.actor == "blue"
    assert blue_decision.obs.actor_id == "blue"
    assert blue_decision.obs.sim_time >= 0.5
    assert any(event.malicious for event in blue_decision.obs.visible_events)
    assert any(
        event.event_type == "InitialAccess" for event in blue_decision.obs.alerts_delta
    )


def test_runtime_keeps_green_internal_and_never_exposes_green_decisions(tmp_path: Path):
    snapshot = _snapshot(tmp_path)
    runtime = OpenRangeRuntime()
    runtime.reset(
        snapshot,
        EpisodeConfig(mode="joint_pool", green_enabled=True),
    )

    red_step = snapshot.reference_bundle.reference_attack_traces[0].steps[0]
    decision = runtime.next_decision()
    assert decision.actor == "red"
    runtime.act(
        "red",
        Action(
            actor_id="red",
            role="red",
            kind=red_step.kind,
            payload={"target": red_step.target, **red_step.payload},
        ),
    )
    decision = runtime.next_decision()
    assert decision.actor == "blue"
    assert any(event.actor == "green" for event in runtime.export_events())


def test_one_day_prompt_mode_exposes_high_level_risky_surfaces(tmp_path: Path):
    snapshot = _snapshot(tmp_path)
    runtime = OpenRangeRuntime()
    runtime.reset(
        snapshot,
        EpisodeConfig(mode="red_only", prompt_mode="one_day", green_enabled=False),
    )

    decision = runtime.next_decision()

    assert decision.actor == "red"
    assert "briefing_mode=one_day" in decision.obs.stdout
    assert "known_risky_surfaces=" in decision.obs.stdout
    assert "@svc-" not in decision.obs.stdout
    assert "sql_injection" not in decision.obs.stdout


def test_blue_only_from_prefix_starts_blue_after_compromise_prefix(tmp_path: Path):
    snapshot = _snapshot(tmp_path)
    runtime = OpenRangeRuntime()
    state = runtime.reset(
        snapshot,
        EpisodeConfig(
            mode="blue_only_from_prefix",
            start_state="prefix_foothold",
            green_enabled=False,
        ),
    )

    assert state.controls_red is False
    assert state.controls_blue is True
    decision = runtime.next_decision()
    assert decision.actor == "blue"
    assert any(
        event.event_type == "InitialAccess" for event in decision.obs.visible_events
    )


def test_blue_only_from_prefix_delivery_and_click_do_not_collapse_without_matching_reference_steps(
    tmp_path: Path,
):
    snapshot = _snapshot(tmp_path)

    delivery_runtime = OpenRangeRuntime()
    delivery_runtime.reset(
        snapshot,
        EpisodeConfig(
            mode="blue_only_from_prefix",
            start_state="prefix_delivery",
            green_enabled=False,
        ),
    )
    delivery_decision = delivery_runtime.next_decision()
    assert delivery_decision.actor == "blue"
    assert not any(
        event.event_type == "InitialAccess"
        for event in delivery_decision.obs.visible_events
    )

    click_runtime = OpenRangeRuntime()
    click_runtime.reset(
        snapshot,
        EpisodeConfig(
            mode="blue_only_from_prefix",
            start_state="prefix_click",
            green_enabled=False,
        ),
    )
    click_decision = click_runtime.next_decision()
    assert click_decision.actor == "blue"
    assert not any(
        event.event_type == "InitialAccess"
        for event in click_decision.obs.visible_events
    )


def test_blue_only_live_can_win_by_detect_and_contain(tmp_path: Path):
    snapshot = _snapshot(tmp_path)
    runtime = OpenRangeRuntime()
    runtime.reset(
        snapshot,
        EpisodeConfig(mode="blue_only_live", green_enabled=False),
    )

    blue_steps = snapshot.reference_bundle.reference_defense_traces[0].steps
    detect_step = next(step for step in blue_steps if step.kind == "submit_finding")
    contain_step = next(step for step in blue_steps if step.kind == "control")
    decision = runtime.next_decision()
    assert decision.actor == "blue"
    detect = runtime.act(
        "blue",
        Action(
            actor_id="blue",
            role="blue",
            kind=detect_step.kind,
            payload={
                "event_type": str(detect_step.payload["event"]),
                "target": detect_step.target,
            },
        ),
    )
    assert "validated finding" in detect.stdout

    decision = runtime.next_decision()
    assert decision.actor == "blue"
    contain = runtime.act(
        "blue",
        Action(
            actor_id="blue",
            role="blue",
            kind=contain_step.kind,
            payload={"target": contain_step.target, "action": "contain"},
        ),
    )

    assert contain.done is True
    assert runtime.score().winner == "blue"


def test_runtime_flags_mock_git_clone_in_episode_audit(tmp_path: Path):
    snapshot = _snapshot(tmp_path)
    runtime = OpenRangeRuntime()
    runtime.reset(
        snapshot,
        EpisodeConfig(
            mode="red_only",
            green_enabled=False,
            audit={
                "suspicious_patterns": (r"\bgit\s+clone\b",),
                "minimum_actions_for_collapse": 1,
            },
        ),
    )

    decision = runtime.next_decision()
    assert decision.actor == "red"
    result = runtime.act(
        "red",
        Action(
            actor_id="red",
            role="red",
            kind="shell",
            payload={"command": "git clone https://example.com/upstream.git"},
        ),
    )

    audit = runtime.score().audit
    assert audit is not None
    assert audit.suspicious_actions
    assert audit.suspicious_actions[0].matched_patterns == (r"\bgit\s+clone\b",)
    assert audit.suspicious_actions[0].fingerprint_prefix == "git clone"
    assert result.emitted_events[0].event_type == "SuspiciousActionObserved"
    assert result.emitted_events[0].suspicious is True
    assert audit.suspicious_event_ids == (result.emitted_events[0].id,)


def test_runtime_hides_suspicious_audit_only_events_from_decision_observations(
    tmp_path: Path,
):
    snapshot = _snapshot(tmp_path)
    runtime = OpenRangeRuntime()
    runtime.reset(
        snapshot,
        EpisodeConfig(
            mode="joint_pool",
            green_enabled=False,
            audit={"suspicious_patterns": (r"\bgit\s+clone\b",)},
        ),
    )

    assert runtime.next_decision().actor == "red"
    runtime.act(
        "red",
        Action(
            actor_id="red",
            role="red",
            kind="shell",
            payload={"command": "git clone https://example.com/upstream.git"},
        ),
    )
    decision = runtime.next_decision()

    assert decision.actor == "blue"
    assert all(
        event.event_type != "SuspiciousActionObserved"
        for event in decision.obs.visible_events
    )


def test_runtime_audit_only_events_do_not_trigger_green_reactions(tmp_path: Path):
    snapshot = _snapshot(tmp_path)
    runtime = OpenRangeRuntime()
    runtime.reset(
        snapshot,
        EpisodeConfig(
            mode="joint_pool",
            green_enabled=True,
            audit={"suspicious_patterns": (r"\bgit\s+clone\b",)},
        ),
    )

    assert runtime.next_decision().actor == "red"
    runtime.act(
        "red",
        Action(
            actor_id="red",
            role="red",
            kind="shell",
            payload={"command": "git clone https://example.com/upstream.git"},
        ),
    )
    assert runtime.next_decision().actor == "blue"
    runtime.act(
        "blue",
        Action(actor_id="blue", role="blue", kind="sleep", payload={}),
    )
    runtime.next_decision()

    assert any(
        event.event_type == "SuspiciousActionObserved"
        for event in runtime.export_events()
    )
    assert not any(
        event.actor == "green" and event.event_type == "DetectionAlertRaised"
        for event in runtime.export_events()
    )


def test_runtime_audit_overhead_stays_below_issue_target(tmp_path: Path):
    snapshot = _snapshot(tmp_path)
    action_count = 400
    warmup_trials = 1
    measured_trials = 3
    overheads: list[float] = []

    for _ in range(warmup_trials):
        _benchmark_runtime_ms_per_action(
            snapshot, audit_enabled=False, action_count=action_count
        )
        _benchmark_runtime_ms_per_action(
            snapshot, audit_enabled=True, action_count=action_count
        )

    for _ in range(measured_trials):
        gc.collect()
        without_audit = _benchmark_runtime_ms_per_action(
            snapshot, audit_enabled=False, action_count=action_count
        )
        gc.collect()
        with_audit = _benchmark_runtime_ms_per_action(
            snapshot, audit_enabled=True, action_count=action_count
        )
        overheads.append(with_audit - without_audit)

    median_overhead_ms = statistics.median(overheads)
    assert median_overhead_ms < 50.0, (
        "audit overhead exceeded the issue target of 50 ms/action; "
        f"measured median overhead={median_overhead_ms:.3f} ms/action "
        f"across {measured_trials} trials with {action_count} actions/trial "
        f"(raw={overheads!r})"
    )


def test_runtime_tags_emitted_events_when_a_live_action_matches_audit_pattern(
    tmp_path: Path,
):
    snapshot = _snapshot(tmp_path)

    class FakePods:
        def __init__(self, pod_ids):
            self.pod_ids = pod_ids

        async def exec(
            self, service: str, cmd: str, timeout: float = 30.0
        ) -> ExecResult:
            del timeout
            if service == "sandbox-red":
                seeded = _code_web_response(snapshot, cmd, set())
                if seeded is not None:
                    return seeded
            return ExecResult(stdout=f"{service}:{cmd}", stderr="", exit_code=0)

        async def is_healthy(self, service: str) -> bool:
            return service in self.pod_ids

    pod_ids = {
        service.id: f"ns/{service.id}-pod" for service in snapshot.world.services
    }
    pod_ids["sandbox-red"] = "ns/sandbox-red-pod"
    pod_ids["sandbox-blue"] = "ns/sandbox-blue-pod"
    for persona in snapshot.world.green_personas:
        pod_ids[f"sandbox-green-{persona.id.replace('_', '-').lower()}"] = (
            f"ns/{persona.id}-pod"
        )

    backend = PodActionBackend()
    backend.bind(
        snapshot, SimpleNamespace(release_name="or-test", pods=FakePods(pod_ids))
    )
    runtime = OpenRangeRuntime(action_backend=backend)
    runtime.reset(
        snapshot,
        EpisodeConfig(
            mode="joint_pool",
            green_enabled=False,
            audit={"suspicious_patterns": (r"api svc-web /search\.php",)},
        ),
    )

    first_step = snapshot.reference_bundle.reference_attack_traces[0].steps[0]
    assert runtime.next_decision().actor == "red"
    result = runtime.act(
        "red",
        Action(
            actor_id="red",
            role="red",
            kind=first_step.kind,
            payload={"target": first_step.target, **first_step.payload},
        ),
    )

    assert result.emitted_events
    assert result.emitted_events[0].suspicious is True
    assert result.emitted_events[0].suspicious_reasons == (r"api svc-web /search\.php",)
    audit = runtime.score().audit
    assert audit is not None
    assert audit.suspicious_event_ids == (result.emitted_events[0].id,)


def test_runtime_serialized_events_keep_suspicious_fields(tmp_path: Path):
    snapshot = _snapshot(tmp_path)
    runtime = OpenRangeRuntime()
    runtime.reset(
        snapshot,
        EpisodeConfig(
            mode="joint_pool",
            green_enabled=False,
            audit={"suspicious_patterns": (r"api svc-web /search\.php",)},
        ),
    )

    first_step = snapshot.reference_bundle.reference_attack_traces[0].steps[0]
    assert runtime.next_decision().actor == "red"
    runtime.act(
        "red",
        Action(
            actor_id="red",
            role="red",
            kind=first_step.kind,
            payload={"target": first_step.target, **first_step.payload},
        ),
    )

    payload = runtime.export_events()[0].model_dump(mode="json")

    assert payload["suspicious"] is True
    assert payload["suspicious_reasons"] == [r"api svc-web /search\.php"]


def test_runtime_hard_done_rejects_more_decisions_and_actions(tmp_path: Path):
    snapshot = _snapshot(tmp_path)
    runtime = OpenRangeRuntime()
    runtime.reset(
        snapshot,
        EpisodeConfig(
            mode="joint_pool", green_enabled=False, episode_horizon_minutes=0.1
        ),
    )

    decision = runtime.next_decision()
    runtime.act(
        decision.actor, Action(actor_id="red", role="red", kind="sleep", payload={})
    )

    with pytest.raises(RuntimeError):
        runtime.next_decision()
    with pytest.raises(RuntimeError):
        runtime.act("red", Action(actor_id="red", role="red", kind="sleep", payload={}))


def test_runtime_matching_rejects_extra_api_path_when_reference_has_no_path() -> None:
    expected = SimpleNamespace(
        kind="api", target="svc-web", payload={"action": "traverse"}
    )
    action = Action(
        actor_id="red",
        role="red",
        kind="api",
        payload={"target": "svc-web", "path": "/"},
    )

    assert OpenRangeRuntime._matches_step(action, expected, "ok") is False


def test_runtime_prefers_shortest_live_foothold_for_next_red_origin(
    tmp_path: Path,
) -> None:
    snapshot = _snapshot(tmp_path)
    runtime = OpenRangeRuntime()
    runtime.reset(snapshot, EpisodeConfig(mode="red_only", green_enabled=False))
    runtime._red_footholds = {"svc-web", "svc-idp"}
    runtime._last_red_target = "svc-idp"

    assert runtime._live_red_origin("svc-fileshare") == "svc-web"


def test_runtime_internal_snapshot_helpers_raise_clear_errors_without_reset() -> None:
    runtime = OpenRangeRuntime()

    with pytest.raises(RuntimeError, match="runtime has no active snapshot"):
        runtime._briefing_text("red")
    with pytest.raises(RuntimeError, match="runtime has no active snapshot"):
        runtime._reference_attack_trace()
    with pytest.raises(RuntimeError, match="runtime has no active snapshot"):
        runtime._reference_defense_trace()


def test_runtime_live_containment_blocks_future_red_step(tmp_path: Path):
    snapshot = _snapshot(tmp_path)

    class FakePods:
        def __init__(self, pod_ids):
            self.pod_ids = pod_ids
            self.contained: set[str] = set()
            self.patched: set[str] = set()

        async def exec(
            self, service: str, cmd: str, timeout: float = 30.0
        ) -> ExecResult:
            del timeout
            if cmd == "touch /tmp/openrange-contained":
                self.contained.add(service)
                return ExecResult(stdout="contained", stderr="", exit_code=0)
            if cmd == "touch /tmp/openrange-patched":
                self.patched.add(service)
                return ExecResult(stdout="patched", stderr="", exit_code=0)
            if cmd == "rm -f /tmp/openrange-contained":
                self.contained.discard(service)
                return ExecResult(stdout="recovered", stderr="", exit_code=0)
            if cmd == "rm -f /tmp/openrange-contained /tmp/openrange-patched":
                self.contained.discard(service)
                self.patched.discard(service)
                return ExecResult(stdout="recovered", stderr="", exit_code=0)
            if cmd == "test ! -f /tmp/openrange-contained":
                return ExecResult(
                    stdout="",
                    stderr="",
                    exit_code=1 if service in self.contained else 0,
                )
            if cmd == "test ! -f /tmp/openrange-patched":
                return ExecResult(
                    stdout="", stderr="", exit_code=1 if service in self.patched else 0
                )
            return ExecResult(stdout=f"{service}:{cmd}", stderr="", exit_code=0)

        async def is_healthy(self, service: str) -> bool:
            return service in self.pod_ids

    pod_ids = {
        service.id: f"ns/{service.id}-pod" for service in snapshot.world.services
    }
    pod_ids["sandbox-red"] = "ns/sandbox-red-pod"
    pod_ids["sandbox-blue"] = "ns/sandbox-blue-pod"
    for persona in snapshot.world.green_personas:
        pod_ids[f"sandbox-green-{persona.id.replace('_', '-').lower()}"] = (
            f"ns/{persona.id}-pod"
        )

    backend = PodActionBackend()
    backend.bind(
        snapshot, SimpleNamespace(release_name="or-test", pods=FakePods(pod_ids))
    )
    runtime = OpenRangeRuntime(action_backend=backend)
    runtime.reset(
        snapshot,
        EpisodeConfig(mode="joint_pool", green_enabled=False),
    )

    first_step = snapshot.reference_bundle.reference_attack_traces[0].steps[0]
    second_step = snapshot.reference_bundle.reference_attack_traces[0].steps[1]

    red_decision = runtime.next_decision()
    assert red_decision.actor == "red"
    runtime.act(
        "red",
        Action(
            actor_id="red",
            role="red",
            kind=first_step.kind,
            payload={"target": first_step.target, **first_step.payload},
        ),
    )

    blue_decision = runtime.next_decision()
    assert blue_decision.actor == "blue"
    runtime.act(
        "blue",
        Action(
            actor_id="blue",
            role="blue",
            kind="control",
            payload={"target": second_step.target, "action": "contain"},
        ),
    )

    red_decision = runtime.next_decision()
    blocked = runtime.act(
        "red",
        Action(
            actor_id="red",
            role="red",
            kind=second_step.kind,
            payload={"target": second_step.target},
        ),
    )

    assert "contained" in blocked.stderr


def test_runtime_live_patch_blocks_future_red_step_and_emits_patch_event(
    tmp_path: Path,
):
    snapshot = _snapshot(tmp_path)

    class FakePods:
        def __init__(self, pod_ids):
            self.pod_ids = pod_ids
            self.contained: set[str] = set()
            self.patched: set[str] = set()

        async def exec(
            self, service: str, cmd: str, timeout: float = 30.0
        ) -> ExecResult:
            del timeout
            if cmd == "touch /tmp/openrange-contained":
                self.contained.add(service)
                return ExecResult(stdout="contained", stderr="", exit_code=0)
            if cmd == "touch /tmp/openrange-patched":
                self.patched.add(service)
                return ExecResult(stdout="patched", stderr="", exit_code=0)
            if cmd == "rm -f /tmp/openrange-contained /tmp/openrange-patched":
                self.contained.discard(service)
                self.patched.discard(service)
                return ExecResult(stdout="recovered", stderr="", exit_code=0)
            if cmd == "test ! -f /tmp/openrange-contained":
                return ExecResult(
                    stdout="",
                    stderr="",
                    exit_code=1 if service in self.contained else 0,
                )
            if cmd == "test ! -f /tmp/openrange-patched":
                return ExecResult(
                    stdout="", stderr="", exit_code=1 if service in self.patched else 0
                )
            return ExecResult(stdout=f"{service}:{cmd}", stderr="", exit_code=0)

        async def is_healthy(self, service: str) -> bool:
            return service in self.pod_ids

    pod_ids = {
        service.id: f"ns/{service.id}-pod" for service in snapshot.world.services
    }
    pod_ids["sandbox-red"] = "ns/sandbox-red-pod"
    pod_ids["sandbox-blue"] = "ns/sandbox-blue-pod"
    for persona in snapshot.world.green_personas:
        pod_ids[f"sandbox-green-{persona.id.replace('_', '-').lower()}"] = (
            f"ns/{persona.id}-pod"
        )

    backend = PodActionBackend()
    backend.bind(
        snapshot, SimpleNamespace(release_name="or-test", pods=FakePods(pod_ids))
    )
    runtime = OpenRangeRuntime(action_backend=backend)
    runtime.reset(
        snapshot,
        EpisodeConfig(mode="joint_pool", green_enabled=False),
    )

    first_step = snapshot.reference_bundle.reference_attack_traces[0].steps[0]
    second_step = snapshot.reference_bundle.reference_attack_traces[0].steps[1]

    assert runtime.next_decision().actor == "red"
    runtime.act(
        "red",
        Action(
            actor_id="red",
            role="red",
            kind=first_step.kind,
            payload={"target": first_step.target, **first_step.payload},
        ),
    )

    patch_decision = runtime.next_decision()
    assert patch_decision.actor == "blue"
    patched = runtime.act(
        "blue",
        Action(
            actor_id="blue",
            role="blue",
            kind="control",
            payload={"target": second_step.target, "action": "patch"},
        ),
    )

    assert "patch applied" in patched.stdout
    assert any(event.event_type == "PatchApplied" for event in patched.emitted_events)

    assert runtime.next_decision().actor == "red"
    blocked = runtime.act(
        "red",
        Action(
            actor_id="red",
            role="red",
            kind=second_step.kind,
            payload={"target": second_step.target},
        ),
    )

    assert "patched" in blocked.stderr


def test_runtime_live_patch_can_disable_exact_web_handler(tmp_path: Path):
    snapshot = _snapshot(tmp_path)

    class FakePods:
        def __init__(self, pod_ids):
            self.pod_ids = pod_ids
            self.contained: set[str] = set()
            self.patched: set[str] = set()
            self.web_guards: set[str] = set()

        async def exec(
            self, service: str, cmd: str, timeout: float = 30.0
        ) -> ExecResult:
            del timeout
            if cmd == "touch /tmp/openrange-contained":
                self.contained.add(service)
                return ExecResult(stdout="contained", stderr="", exit_code=0)
            if cmd == "touch /tmp/openrange-patched":
                self.patched.add(service)
                return ExecResult(stdout="patched", stderr="", exit_code=0)
            if "touch /var/www/html/.openrange/guards/" in cmd:
                self.web_guards.add(service)
                return ExecResult(stdout="guarded", stderr="", exit_code=0)
            if cmd == "rm -f /tmp/openrange-contained /tmp/openrange-patched":
                self.contained.discard(service)
                self.patched.discard(service)
                return ExecResult(stdout="recovered", stderr="", exit_code=0)
            if "rm -f /var/www/html/.openrange/guards/" in cmd:
                self.web_guards.discard(service)
                return ExecResult(stdout="unguarded", stderr="", exit_code=0)
            if cmd == "test ! -f /tmp/openrange-contained":
                return ExecResult(
                    stdout="",
                    stderr="",
                    exit_code=1 if service in self.contained else 0,
                )
            if cmd == "test ! -f /tmp/openrange-patched":
                return ExecResult(
                    stdout="", stderr="", exit_code=1 if service in self.patched else 0
                )
            if "test ! -f /var/www/html/.openrange/guards/" in cmd:
                return ExecResult(
                    stdout="",
                    stderr="",
                    exit_code=1 if service in self.web_guards else 0,
                )
            if service == "sandbox-red":
                seeded = _code_web_response(snapshot, cmd, self.web_guards)
                if seeded is not None:
                    return seeded
            return ExecResult(stdout=f"{service}:{cmd}", stderr="", exit_code=0)

        async def is_healthy(self, service: str) -> bool:
            return service in self.pod_ids

    pod_ids = {
        service.id: f"ns/{service.id}-pod" for service in snapshot.world.services
    }
    pod_ids["sandbox-red"] = "ns/sandbox-red-pod"
    pod_ids["sandbox-blue"] = "ns/sandbox-blue-pod"
    for persona in snapshot.world.green_personas:
        pod_ids[f"sandbox-green-{persona.id.replace('_', '-').lower()}"] = (
            f"ns/{persona.id}-pod"
        )

    backend = PodActionBackend()
    backend.bind(
        snapshot, SimpleNamespace(release_name="or-test", pods=FakePods(pod_ids))
    )
    runtime = OpenRangeRuntime(action_backend=backend)
    runtime.reset(
        snapshot,
        EpisodeConfig(mode="joint_pool", green_enabled=False),
    )

    first_step = snapshot.reference_bundle.reference_attack_traces[0].steps[0]

    assert runtime.next_decision().actor == "red"
    runtime.act(
        "red",
        Action(actor_id="red", role="red", kind="sleep", payload={}),
    )

    assert runtime.next_decision().actor == "blue"
    patched = runtime.act(
        "blue",
        Action(
            actor_id="blue",
            role="blue",
            kind="control",
            payload={"target": first_step.target, "action": "patch"},
        ),
    )
    assert "patch applied" in patched.stdout

    assert runtime.next_decision().actor == "red"
    blocked = runtime.act(
        "red",
        Action(
            actor_id="red",
            role="red",
            kind=first_step.kind,
            payload={"target": first_step.target, **first_step.payload},
        ),
    )

    assert "patched" in blocked.stderr


def test_runtime_accepts_mitigate_as_patch_alias(tmp_path: Path):
    snapshot = _snapshot(tmp_path)
    runtime = OpenRangeRuntime()
    runtime.reset(
        snapshot,
        EpisodeConfig(mode="joint_pool", green_enabled=False),
    )

    first_step = snapshot.reference_bundle.reference_attack_traces[0].steps[0]
    second_step = snapshot.reference_bundle.reference_attack_traces[0].steps[1]

    assert runtime.next_decision().actor == "red"
    runtime.act(
        "red",
        Action(
            actor_id="red",
            role="red",
            kind=first_step.kind,
            payload={"target": first_step.target, **first_step.payload},
        ),
    )

    assert runtime.next_decision().actor == "blue"
    mitigated = runtime.act(
        "blue",
        Action(
            actor_id="blue",
            role="blue",
            kind="control",
            payload={"target": second_step.target, "action": "mitigate"},
        ),
    )

    assert "mitigation applied" in mitigated.stdout
    assert any(event.event_type == "PatchApplied" for event in mitigated.emitted_events)


def test_internal_blue_controller_modes_are_not_aliases(tmp_path: Path):
    snapshot = _snapshot(tmp_path)
    first_step = snapshot.reference_bundle.reference_attack_traces[0].steps[0]

    reference_runtime = OpenRangeRuntime()
    reference_runtime.reset(
        snapshot,
        EpisodeConfig(
            mode="red_only",
            opponent_blue="reference",
            green_enabled=False,
            telemetry_delay_enabled=False,
            telemetry_delay_profile="none",
        ),
    )
    assert reference_runtime.next_decision().actor == "red"
    reference_runtime.act(
        "red",
        Action(
            actor_id="red",
            role="red",
            kind=first_step.kind,
            payload={"target": first_step.target, **first_step.payload},
        ),
    )
    reference_action = reference_runtime._internal_blue_action()
    assert reference_action.kind == "shell"
    assert reference_action.payload["action"] == "observe_events"

    scripted_runtime = OpenRangeRuntime()
    scripted_runtime.reset(
        snapshot,
        EpisodeConfig(
            mode="red_only",
            opponent_blue="scripted",
            green_enabled=False,
            telemetry_delay_enabled=False,
            telemetry_delay_profile="none",
        ),
    )
    assert scripted_runtime.next_decision().actor == "red"
    scripted_runtime.act(
        "red",
        Action(
            actor_id="red",
            role="red",
            kind=first_step.kind,
            payload={"target": first_step.target, **first_step.payload},
        ),
    )
    scripted_action = scripted_runtime._internal_blue_action()
    assert scripted_action.kind == "submit_finding"
    assert scripted_action.payload["target"] == first_step.target


def test_external_blue_reference_step_advances_between_decisions(tmp_path: Path):
    snapshot = _snapshot(tmp_path)
    defense_trace = snapshot.reference_bundle.reference_defense_traces[0]
    assert len(defense_trace.steps) >= 2

    runtime = OpenRangeRuntime()
    runtime.reset(
        snapshot,
        EpisodeConfig(
            mode="blue_only_live",
            opponent_red="reference",
            green_enabled=False,
            telemetry_delay_enabled=False,
            telemetry_delay_profile="none",
        ),
        reference_defense_index=0,
    )

    first_decision = runtime.next_decision()
    assert first_decision.actor == "blue"
    assert runtime.reference_step("blue") == defense_trace.steps[0]

    runtime.act("blue", runtime_action("blue", defense_trace.steps[0]))

    second_decision = runtime.next_decision()
    assert second_decision.actor == "blue"
    assert runtime.reference_step("blue") == defense_trace.steps[1]


def test_next_decision_raises_done_after_internal_terminal_progress(tmp_path: Path):
    snapshot = _snapshot(tmp_path)
    runtime = OpenRangeRuntime()
    runtime.reset(
        snapshot,
        EpisodeConfig(mode="red_only", opponent_blue="scripted", green_enabled=False),
    )
    runtime._pending_actor = ""

    def _finish_internally() -> None:
        runtime._state.done = True
        runtime._state.winner = "blue"
        runtime._state.terminal_reason = "blue_terminal"

    runtime._advance_until_external_decision = _finish_internally  # type: ignore[method-assign]

    with pytest.raises(RuntimeError, match="episode is done"):
        runtime.next_decision()


def test_green_branch_backends_are_not_aliases(tmp_path: Path):
    snapshot = _snapshot(tmp_path)
    first_step = snapshot.reference_bundle.reference_attack_traces[0].steps[0]

    scripted_runtime = OpenRangeRuntime()
    scripted_runtime.reset(
        snapshot,
        EpisodeConfig(
            mode="joint_pool",
            green_enabled=True,
            green_routine_enabled=False,
            green_branch_backend="scripted",
        ),
    )
    assert scripted_runtime.next_decision().actor == "red"
    scripted_runtime.act(
        "red",
        Action(
            actor_id="red",
            role="red",
            kind=first_step.kind,
            payload={"target": first_step.target, **first_step.payload},
        ),
    )
    assert scripted_runtime.next_decision().actor == "blue"
    scripted_runtime.act(
        "blue", Action(actor_id="blue", role="blue", kind="sleep", payload={})
    )
    assert scripted_runtime.next_decision().actor == "red"
    scripted_green_events = [
        event for event in scripted_runtime.export_events() if event.actor == "green"
    ]

    orchestrated_runtime = OpenRangeRuntime()
    orchestrated_runtime.reset(
        snapshot,
        EpisodeConfig(
            mode="joint_pool",
            green_enabled=True,
            green_routine_enabled=False,
            green_branch_backend="workflow_orchestrator",
        ),
    )
    assert orchestrated_runtime.next_decision().actor == "red"
    orchestrated_runtime.act(
        "red",
        Action(
            actor_id="red",
            role="red",
            kind=first_step.kind,
            payload={"target": first_step.target, **first_step.payload},
        ),
    )
    assert orchestrated_runtime.next_decision().actor == "blue"
    orchestrated_runtime.act(
        "blue", Action(actor_id="blue", role="blue", kind="sleep", payload={})
    )
    assert orchestrated_runtime.next_decision().actor == "red"
    orchestrated_green_events = [
        event
        for event in orchestrated_runtime.export_events()
        if event.actor == "green"
    ]

    assert len(orchestrated_green_events) > len(scripted_green_events)
    assert any(
        event.event_type == "RecoveryCompleted" for event in orchestrated_green_events
    )


def test_small_llm_green_branch_handles_profiled_susceptibility_maps(tmp_path: Path):
    payload = _manifest_payload()
    payload["npc_profiles"] = {
        "sales": {
            "awareness": 0.9,
            "susceptibility": {"credential_obtained": 0.8, "phishing": 0.6},
        }
    }
    world = CatalogWeaknessSeeder().apply(
        EnterpriseSaaSManifestCompiler().compile(payload)
    )
    synth = EnterpriseSaaSWorldSynthesizer().synthesize(
        world, tmp_path / "synth-small-llm"
    )
    artifacts = EnterpriseSaaSKindRenderer().render(
        world, synth, tmp_path / "rendered-small-llm"
    )
    reference_bundle, report = LocalAdmissionController(mode="fail_fast").admit(
        world, artifacts, OFFLINE_BUILD_CONFIG
    )
    store = FileSnapshotStore(tmp_path / "snapshots-small-llm")
    snapshot = hydrate_runtime_snapshot(
        store, store.create(world, artifacts, reference_bundle, report, synth=synth)
    )

    scheduler = ScriptedGreenScheduler()
    scheduler.reset(
        snapshot,
        EpisodeConfig(
            mode="joint_pool",
            green_enabled=True,
            green_routine_enabled=False,
            green_branch_backend="small_llm",
        ),
    )
    scheduler.record_event(
        RuntimeEvent(
            id="evt-1",
            event_type="CredentialObtained",
            actor="red",
            time=0.0,
            source_entity="svc-web",
            target_entity="idp_admin_cred",
            malicious=True,
        )
    )
    scheduler.advance_until(1.0)
    actions = scheduler.pop_ready_actions()

    assert any(
        action.payload.get("branch") == "report_suspicious_activity"
        for action in actions
    )
    assert any(action.payload.get("branch") == "reset_password" for action in actions)
