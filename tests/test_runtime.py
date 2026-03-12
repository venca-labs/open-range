from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from open_range.admit import LocalAdmissionController
from open_range.cluster import ExecResult
from open_range.code_web import code_web_payload
from open_range.compiler import EnterpriseSaaSManifestCompiler
from open_range.episode_config import EpisodeConfig
from open_range.execution import PodActionBackend
from open_range.render import EnterpriseSaaSKindRenderer
from open_range.runtime import WitnessDrivenRuntime
from open_range.runtime_types import Action
from open_range.store import FileSnapshotStore
from open_range.synth import EnterpriseSaaSWorldSynthesizer
from open_range.weaknesses import CatalogWeaknessSeeder


def _manifest_payload() -> dict:
    return {
        "version": 1,
        "world_family": "enterprise_saas_v1",
        "seed": 1337,
        "business": {
            "archetype": "healthcare_saas",
            "workflows": [
                "helpdesk_ticketing",
                "payroll_approval",
                "document_sharing",
                "internal_email",
            ],
        },
        "topology": {
            "zones": ["external", "dmz", "corp", "data", "management"],
            "services": ["web_app", "email", "idp", "fileshare", "db", "siem"],
        },
        "users": {
            "roles": {
                "sales": 2,
                "engineer": 1,
                "finance": 1,
                "it_admin": 1,
            },
        },
        "assets": [
            {"id": "finance_docs", "class": "crown_jewel"},
            {"id": "payroll_db", "class": "crown_jewel"},
            {"id": "idp_admin_cred", "class": "sensitive"},
        ],
        "objectives": {
            "red": [
                {"predicate": "credential_obtained(idp_admin_cred)"},
                {"predicate": "asset_read(finance_docs)"},
            ],
            "blue": [
                {"predicate": "intrusion_detected(initial_access)"},
                {"predicate": "intrusion_contained(before_asset_read)"},
                {"predicate": "service_health_above(0.9)"},
            ],
        },
        "security": {
            "allowed_weakness_families": [
                "config_identity",
                "workflow_abuse",
                "secret_exposure",
                "code_web",
                "telemetry_blindspot",
            ],
            "observability": {
                "require_web_logs": True,
                "require_idp_logs": True,
                "require_email_logs": True,
                "require_siem_ingest": True,
            },
        },
        "difficulty": {
            "target_red_path_depth": 4,
            "target_blue_signal_points": 4,
            "target_noise_density": "medium",
        },
        "mutation_bounds": {
            "max_new_hosts": 2,
            "max_new_services": 1,
            "max_new_users": 5,
            "max_new_weaknesses": 2,
        },
    }


def _snapshot(tmp_path: Path):
    world = CatalogWeaknessSeeder().apply(EnterpriseSaaSManifestCompiler().compile(_manifest_payload()))
    synth = EnterpriseSaaSWorldSynthesizer().synthesize(world, tmp_path / "synth")
    artifacts = EnterpriseSaaSKindRenderer().render(world, synth, tmp_path / "rendered")
    witness_bundle, report = LocalAdmissionController(mode="fail_fast").admit(world, artifacts)
    return FileSnapshotStore(tmp_path / "snapshots").create(world, artifacts, witness_bundle, report, synth=synth)


def _code_web_response(snapshot, cmd: str, patched_services: set[str]) -> ExecResult | None:
    weakness = next((weak for weak in snapshot.world.weaknesses if weak.family == "code_web"), None)
    if weakness is None or weakness.target in patched_services:
        return None
    payload = code_web_payload(snapshot.world, weakness)
    path = str(payload.get("path", ""))
    if "http://svc-web:80" not in cmd or path not in cmd:
        return None
    return ExecResult(stdout=str(payload.get("expect_contains", "")), stderr="", exit_code=0)


def test_joint_pool_next_decision_returns_actor_specific_observations(tmp_path: Path):
    snapshot = _snapshot(tmp_path)
    runtime = WitnessDrivenRuntime()
    state = runtime.reset(
        snapshot,
        EpisodeConfig(mode="joint_pool", green_enabled=False),
    )

    assert state.controls_red is True
    assert state.controls_blue is True
    assert state.next_actor == "red"

    first_red = snapshot.witness_bundle.red_witnesses[0].steps[0]
    red_decision = runtime.next_decision()
    assert red_decision.actor == "red"
    assert red_decision.obs.actor_id == "red"
    assert red_decision.obs.sim_time == 0.0
    assert "briefing_mode=zero_day" in red_decision.obs.stdout
    assert "known_risky_surfaces" not in red_decision.obs.stdout

    runtime.act(
        "red",
        Action(actor_id="red", role="red", kind=first_red.kind, payload={"target": first_red.target, **first_red.payload}),
    )

    blue_decision = runtime.next_decision()
    assert blue_decision.actor == "blue"
    assert blue_decision.obs.actor_id == "blue"
    assert blue_decision.obs.sim_time >= 0.5
    assert any(event.malicious for event in blue_decision.obs.visible_events)
    assert any(event.event_type == "InitialAccess" for event in blue_decision.obs.alerts_delta)


def test_runtime_keeps_green_internal_and_never_exposes_green_decisions(tmp_path: Path):
    snapshot = _snapshot(tmp_path)
    runtime = WitnessDrivenRuntime()
    runtime.reset(
        snapshot,
        EpisodeConfig(mode="joint_pool", green_enabled=True),
    )

    red_step = snapshot.witness_bundle.red_witnesses[0].steps[0]
    decision = runtime.next_decision()
    assert decision.actor == "red"
    runtime.act(
        "red",
        Action(actor_id="red", role="red", kind=red_step.kind, payload={"target": red_step.target, **red_step.payload}),
    )
    decision = runtime.next_decision()
    assert decision.actor == "blue"
    assert any(event.actor == "green" for event in runtime.export_events())


def test_one_day_prompt_mode_exposes_high_level_risky_surfaces(tmp_path: Path):
    snapshot = _snapshot(tmp_path)
    runtime = WitnessDrivenRuntime()
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
    runtime = WitnessDrivenRuntime()
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
    assert any(event.event_type == "InitialAccess" for event in decision.obs.visible_events)


def test_blue_only_from_prefix_delivery_and_click_do_not_collapse_without_matching_witness_steps(tmp_path: Path):
    snapshot = _snapshot(tmp_path)

    delivery_runtime = WitnessDrivenRuntime()
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
    assert not any(event.event_type == "InitialAccess" for event in delivery_decision.obs.visible_events)

    click_runtime = WitnessDrivenRuntime()
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
    assert not any(event.event_type == "InitialAccess" for event in click_decision.obs.visible_events)


def test_blue_only_live_can_win_by_detect_and_contain(tmp_path: Path):
    snapshot = _snapshot(tmp_path)
    runtime = WitnessDrivenRuntime()
    runtime.reset(
        snapshot,
        EpisodeConfig(mode="blue_only_live", green_enabled=False),
    )

    blue_steps = snapshot.witness_bundle.blue_witnesses[0].steps
    decision = runtime.next_decision()
    assert decision.actor == "blue"
    detect = runtime.act(
        "blue",
        Action(
            actor_id="blue",
            role="blue",
            kind=blue_steps[1].kind,
            payload={"event_type": "InitialAccess", "target": blue_steps[1].target},
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
            kind=blue_steps[2].kind,
            payload={"target": blue_steps[2].target, "action": "contain"},
        ),
    )

    assert contain.done is True
    assert runtime.score().winner == "blue"


def test_runtime_hard_done_rejects_more_decisions_and_actions(tmp_path: Path):
    snapshot = _snapshot(tmp_path)
    runtime = WitnessDrivenRuntime()
    runtime.reset(
        snapshot,
        EpisodeConfig(mode="joint_pool", green_enabled=False, episode_horizon_minutes=0.1),
    )

    decision = runtime.next_decision()
    runtime.act(decision.actor, Action(actor_id="red", role="red", kind="sleep", payload={}))

    with pytest.raises(RuntimeError):
        runtime.next_decision()
    with pytest.raises(RuntimeError):
        runtime.act("red", Action(actor_id="red", role="red", kind="sleep", payload={}))


def test_runtime_matching_rejects_extra_api_path_when_witness_has_no_path() -> None:
    expected = SimpleNamespace(kind="api", target="svc-web", payload={"action": "traverse"})
    action = Action(actor_id="red", role="red", kind="api", payload={"target": "svc-web", "path": "/"})

    assert WitnessDrivenRuntime._matches_step(action, expected, "ok") is False


def test_runtime_live_containment_blocks_future_red_step(tmp_path: Path):
    snapshot = _snapshot(tmp_path)

    class FakePods:
        def __init__(self, pod_ids):
            self.pod_ids = pod_ids
            self.contained: set[str] = set()
            self.patched: set[str] = set()

        async def exec(self, service: str, cmd: str, timeout: float = 30.0) -> ExecResult:
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
                return ExecResult(stdout="", stderr="", exit_code=1 if service in self.contained else 0)
            if cmd == "test ! -f /tmp/openrange-patched":
                return ExecResult(stdout="", stderr="", exit_code=1 if service in self.patched else 0)
            return ExecResult(stdout=f"{service}:{cmd}", stderr="", exit_code=0)

        async def is_healthy(self, service: str) -> bool:
            return service in self.pod_ids

    pod_ids = {service.id: f"ns/{service.id}-pod" for service in snapshot.world.services}
    pod_ids["sandbox-red"] = "ns/sandbox-red-pod"
    pod_ids["sandbox-blue"] = "ns/sandbox-blue-pod"
    for persona in snapshot.world.green_personas:
        pod_ids[f"sandbox-green-{persona.id.replace('_', '-').lower()}"] = f"ns/{persona.id}-pod"

    backend = PodActionBackend()
    backend.bind(snapshot, SimpleNamespace(release_name="or-test", pods=FakePods(pod_ids)))
    runtime = WitnessDrivenRuntime(action_backend=backend)
    runtime.reset(
        snapshot,
        EpisodeConfig(mode="joint_pool", green_enabled=False),
    )

    first_step = snapshot.witness_bundle.red_witnesses[0].steps[0]
    second_step = snapshot.witness_bundle.red_witnesses[0].steps[1]

    red_decision = runtime.next_decision()
    assert red_decision.actor == "red"
    runtime.act(
        "red",
        Action(actor_id="red", role="red", kind=first_step.kind, payload={"target": first_step.target, **first_step.payload}),
    )

    blue_decision = runtime.next_decision()
    assert blue_decision.actor == "blue"
    runtime.act(
        "blue",
        Action(actor_id="blue", role="blue", kind="control", payload={"target": second_step.target, "action": "contain"}),
    )

    red_decision = runtime.next_decision()
    blocked = runtime.act(
        "red",
        Action(actor_id="red", role="red", kind=second_step.kind, payload={"target": second_step.target}),
    )

    assert "contained" in blocked.stderr


def test_runtime_live_patch_blocks_future_red_step_and_emits_patch_event(tmp_path: Path):
    snapshot = _snapshot(tmp_path)

    class FakePods:
        def __init__(self, pod_ids):
            self.pod_ids = pod_ids
            self.contained: set[str] = set()
            self.patched: set[str] = set()

        async def exec(self, service: str, cmd: str, timeout: float = 30.0) -> ExecResult:
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
                return ExecResult(stdout="", stderr="", exit_code=1 if service in self.contained else 0)
            if cmd == "test ! -f /tmp/openrange-patched":
                return ExecResult(stdout="", stderr="", exit_code=1 if service in self.patched else 0)
            return ExecResult(stdout=f"{service}:{cmd}", stderr="", exit_code=0)

        async def is_healthy(self, service: str) -> bool:
            return service in self.pod_ids

    pod_ids = {service.id: f"ns/{service.id}-pod" for service in snapshot.world.services}
    pod_ids["sandbox-red"] = "ns/sandbox-red-pod"
    pod_ids["sandbox-blue"] = "ns/sandbox-blue-pod"
    for persona in snapshot.world.green_personas:
        pod_ids[f"sandbox-green-{persona.id.replace('_', '-').lower()}"] = f"ns/{persona.id}-pod"

    backend = PodActionBackend()
    backend.bind(snapshot, SimpleNamespace(release_name="or-test", pods=FakePods(pod_ids)))
    runtime = WitnessDrivenRuntime(action_backend=backend)
    runtime.reset(
        snapshot,
        EpisodeConfig(mode="joint_pool", green_enabled=False),
    )

    first_step = snapshot.witness_bundle.red_witnesses[0].steps[0]
    second_step = snapshot.witness_bundle.red_witnesses[0].steps[1]

    assert runtime.next_decision().actor == "red"
    runtime.act(
        "red",
        Action(actor_id="red", role="red", kind=first_step.kind, payload={"target": first_step.target, **first_step.payload}),
    )

    patch_decision = runtime.next_decision()
    assert patch_decision.actor == "blue"
    patched = runtime.act(
        "blue",
        Action(actor_id="blue", role="blue", kind="control", payload={"target": second_step.target, "action": "patch"}),
    )

    assert "patch applied" in patched.stdout
    assert any(event.event_type == "PatchApplied" for event in patched.emitted_events)

    assert runtime.next_decision().actor == "red"
    blocked = runtime.act(
        "red",
        Action(actor_id="red", role="red", kind=second_step.kind, payload={"target": second_step.target}),
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

        async def exec(self, service: str, cmd: str, timeout: float = 30.0) -> ExecResult:
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
                return ExecResult(stdout="", stderr="", exit_code=1 if service in self.contained else 0)
            if cmd == "test ! -f /tmp/openrange-patched":
                return ExecResult(stdout="", stderr="", exit_code=1 if service in self.patched else 0)
            if "test ! -f /var/www/html/.openrange/guards/" in cmd:
                return ExecResult(stdout="", stderr="", exit_code=1 if service in self.web_guards else 0)
            if service == "sandbox-red":
                seeded = _code_web_response(snapshot, cmd, self.web_guards)
                if seeded is not None:
                    return seeded
            return ExecResult(stdout=f"{service}:{cmd}", stderr="", exit_code=0)

        async def is_healthy(self, service: str) -> bool:
            return service in self.pod_ids

    pod_ids = {service.id: f"ns/{service.id}-pod" for service in snapshot.world.services}
    pod_ids["sandbox-red"] = "ns/sandbox-red-pod"
    pod_ids["sandbox-blue"] = "ns/sandbox-blue-pod"
    for persona in snapshot.world.green_personas:
        pod_ids[f"sandbox-green-{persona.id.replace('_', '-').lower()}"] = f"ns/{persona.id}-pod"

    backend = PodActionBackend()
    backend.bind(snapshot, SimpleNamespace(release_name="or-test", pods=FakePods(pod_ids)))
    runtime = WitnessDrivenRuntime(action_backend=backend)
    runtime.reset(
        snapshot,
        EpisodeConfig(mode="joint_pool", green_enabled=False),
    )

    first_step = snapshot.witness_bundle.red_witnesses[0].steps[0]

    assert runtime.next_decision().actor == "red"
    runtime.act(
        "red",
        Action(actor_id="red", role="red", kind="sleep", payload={}),
    )

    assert runtime.next_decision().actor == "blue"
    patched = runtime.act(
        "blue",
        Action(actor_id="blue", role="blue", kind="control", payload={"target": first_step.target, "action": "patch"}),
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
    runtime = WitnessDrivenRuntime()
    runtime.reset(
        snapshot,
        EpisodeConfig(mode="joint_pool", green_enabled=False),
    )

    first_step = snapshot.witness_bundle.red_witnesses[0].steps[0]
    second_step = snapshot.witness_bundle.red_witnesses[0].steps[1]

    assert runtime.next_decision().actor == "red"
    runtime.act(
        "red",
        Action(actor_id="red", role="red", kind=first_step.kind, payload={"target": first_step.target, **first_step.payload}),
    )

    assert runtime.next_decision().actor == "blue"
    mitigated = runtime.act(
        "blue",
        Action(actor_id="blue", role="blue", kind="control", payload={"target": second_step.target, "action": "mitigate"}),
    )

    assert "mitigation applied" in mitigated.stdout
    assert any(event.event_type == "PatchApplied" for event in mitigated.emitted_events)


def test_internal_blue_controller_modes_are_not_aliases(tmp_path: Path):
    snapshot = _snapshot(tmp_path)
    first_step = snapshot.witness_bundle.red_witnesses[0].steps[0]

    witness_runtime = WitnessDrivenRuntime()
    witness_runtime.reset(
        snapshot,
        EpisodeConfig(mode="red_only", opponent_blue="witness", green_enabled=False),
    )
    assert witness_runtime.next_decision().actor == "red"
    witness_runtime.act(
        "red",
        Action(actor_id="red", role="red", kind=first_step.kind, payload={"target": first_step.target, **first_step.payload}),
    )
    assert witness_runtime.next_decision().actor == "red"
    witness_blue_events = [event.event_type for event in witness_runtime.export_events() if event.actor == "blue"]
    assert "DetectionAlertRaised" not in witness_blue_events

    scripted_runtime = WitnessDrivenRuntime()
    scripted_runtime.reset(
        snapshot,
        EpisodeConfig(mode="red_only", opponent_blue="scripted", green_enabled=False),
    )
    assert scripted_runtime.next_decision().actor == "red"
    scripted_runtime.act(
        "red",
        Action(actor_id="red", role="red", kind=first_step.kind, payload={"target": first_step.target, **first_step.payload}),
    )
    assert scripted_runtime.next_decision().actor == "red"
    scripted_blue_events = [event.event_type for event in scripted_runtime.export_events() if event.actor == "blue"]
    assert "DetectionAlertRaised" in scripted_blue_events


def test_next_decision_raises_done_after_internal_terminal_progress(tmp_path: Path):
    snapshot = _snapshot(tmp_path)
    runtime = WitnessDrivenRuntime()
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
    first_step = snapshot.witness_bundle.red_witnesses[0].steps[0]

    scripted_runtime = WitnessDrivenRuntime()
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
        Action(actor_id="red", role="red", kind=first_step.kind, payload={"target": first_step.target, **first_step.payload}),
    )
    assert scripted_runtime.next_decision().actor == "blue"
    scripted_runtime.act("blue", Action(actor_id="blue", role="blue", kind="sleep", payload={}))
    assert scripted_runtime.next_decision().actor == "red"
    scripted_green_events = [event for event in scripted_runtime.export_events() if event.actor == "green"]

    orchestrated_runtime = WitnessDrivenRuntime()
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
        Action(actor_id="red", role="red", kind=first_step.kind, payload={"target": first_step.target, **first_step.payload}),
    )
    assert orchestrated_runtime.next_decision().actor == "blue"
    orchestrated_runtime.act("blue", Action(actor_id="blue", role="blue", kind="sleep", payload={}))
    assert orchestrated_runtime.next_decision().actor == "red"
    orchestrated_green_events = [event for event in orchestrated_runtime.export_events() if event.actor == "green"]

    assert len(orchestrated_green_events) > len(scripted_green_events)
    assert any(event.event_type == "RecoveryCompleted" for event in orchestrated_green_events)
