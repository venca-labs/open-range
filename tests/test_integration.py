from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from open_range import (
    Action,
    BuildPipeline,
    EpisodeConfig,
    ExecResult,
    FileSnapshotStore,
    LocalAdmissionController,
    OpenRange,
    ScriptedRuntimeAgent,
    TandemEpisodeDriver,
)
from open_range.code_web import code_web_payload


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
            "roles": {"sales": 2, "engineer": 1, "finance": 1, "it_admin": 1},
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


def _code_web_response(world, cmd: str, patched_services: set[str]) -> ExecResult | None:
    weakness = next((weak for weak in world.weaknesses if weak.family == "code_web"), None)
    if weakness is None or weakness.target in patched_services:
        return None
    payload = code_web_payload(world, weakness)
    path = str(payload.get("path", ""))
    if "http://svc-web:80" not in cmd or path not in cmd:
        return None
    return ExecResult(stdout=str(payload.get("expect_contains", "")), stderr="", exit_code=0)


def test_end_to_end_pipeline_store_reset_and_tandem_episode(tmp_path: Path):
    store = FileSnapshotStore(tmp_path / "snapshots")
    pipeline = BuildPipeline(store=store)

    candidate = pipeline.build(_manifest_payload(), tmp_path / "rendered")
    snapshot = pipeline.admit(candidate, split="train")

    runtime_service = OpenRange(store=store)
    runtime_service.reset(snapshot.snapshot_id, EpisodeConfig(mode="joint_pool", green_enabled=True))
    runtime_service.close()

    red_steps = snapshot.witness_bundle.red_witnesses[0].steps
    blue_steps = snapshot.witness_bundle.blue_witnesses[0].steps
    red_agent = ScriptedRuntimeAgent(
        [
            Action(
                actor_id="red",
                role="red",
                kind=red_steps[0].kind,
                payload={"target": red_steps[0].target, **red_steps[0].payload},
            ),
            Action(actor_id="red", role="red", kind="sleep", payload={}),
        ]
    )
    blue_agent = ScriptedRuntimeAgent(
        [
            Action(
                actor_id="blue",
                role="blue",
                kind=blue_steps[1].kind,
                payload={"event_type": "InitialAccess", "target": red_steps[0].target},
            ),
            Action(
                actor_id="blue",
                role="blue",
                kind=blue_steps[2].kind,
                payload={"target": blue_steps[2].target, "action": "contain"},
            ),
        ]
    )
    driver = TandemEpisodeDriver(runtime_service.runtime)

    episode = driver.run_episode(
        snapshot,
        red_agent=red_agent,
        blue_agent=blue_agent,
        episode_config=EpisodeConfig(mode="joint_pool", green_enabled=True),
    )
    score = runtime_service.score()

    assert candidate.synth.generated_files
    assert snapshot.validator_report.admitted is True
    assert store.load(snapshot.snapshot_id).snapshot_id == snapshot.snapshot_id
    assert episode.done is True
    assert episode.winner == "blue"
    assert score.winner == "blue"
    assert any(turn.role == "red" for turn in episode.turns)
    assert any(turn.role == "blue" for turn in episode.turns)
    assert any(event.actor == "green" for event in runtime_service.runtime.export_events())


def test_live_backend_integration_carries_logs_from_runtime_events(tmp_path: Path):
    store = FileSnapshotStore(tmp_path / "snapshots")
    boots: list[str] = []
    teardowns: list[str] = []
    pod_registry: dict[str, object] = {}
    built_world = None

    class FakePods:
        def __init__(self, world, pod_ids):
            self.world = world
            self.pod_ids = pod_ids
            self.logs: list[str] = []
            self.contained: set[str] = set()
            self.patched: set[str] = set()
            self.web_guards: set[str] = set()

        async def is_healthy(self, service: str) -> bool:
            return service in self.pod_ids

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
            if cmd == "rm -f /tmp/openrange-contained":
                self.contained.discard(service)
                return ExecResult(stdout="recovered", stderr="", exit_code=0)
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
            if ">> /srv/http/siem/all.log" in cmd:
                line = cmd.split("printf '%s\\n' ", 1)[1].split(" >> /srv/http/siem/all.log", 1)[0]
                self.logs.append(line.strip("'"))
                return ExecResult(stdout="", stderr="", exit_code=0)
            if "grep -q 'InitialAccess' /srv/http/siem/all.log" in cmd:
                seen = any("InitialAccess" in line for line in self.logs)
                return ExecResult(stdout="", stderr="", exit_code=0 if seen else 1)
            if service == "sandbox-red":
                seeded = _code_web_response(self.world, cmd, self.web_guards)
                if seeded is not None:
                    return seeded
            if service == "sandbox-red" and any(target in cmd for target in ("svc-fileshare", "svc-db", "svc-idp")):
                return ExecResult(stdout="", stderr="blocked", exit_code=1)
            if service.startswith("sandbox-") and "wget -qO- http://svc-siem:9200/all.log" in cmd:
                return ExecResult(stdout="\n".join(self.logs), stderr="", exit_code=0)
            return ExecResult(stdout=f"{service}:{cmd}", stderr="", exit_code=0)

    class FakeBackend:
        def boot(self, *, snapshot_id: str, artifacts_dir: Path):
            boots.append(snapshot_id)
            if built_world is not None and built_world.world_id == snapshot_id:
                world = built_world
            else:
                world = store.load(snapshot_id).world
            pod_ids = {service.id: f"ns/{service.id}-pod" for service in world.services}
            pod_ids["sandbox-red"] = "ns/sandbox-red-pod"
            pod_ids["sandbox-blue"] = "ns/sandbox-blue-pod"
            for persona in world.green_personas:
                pod_ids[f"sandbox-green-{persona.id.replace('_', '-').lower()}"] = f"ns/{persona.id}-pod"
            pods = FakePods(world, pod_ids)
            pod_registry[snapshot_id] = pods
            return SimpleNamespace(release_name=f"or-{snapshot_id}", artifacts_dir=artifacts_dir, pods=pods)

        def teardown(self, release) -> None:
            teardowns.append(release.release_name)

    backend = FakeBackend()
    admission = LocalAdmissionController(mode="fail_fast", live_backend=backend)
    pipeline = BuildPipeline(store=store, admission=admission)
    candidate = pipeline.build(_manifest_payload(), tmp_path / "rendered")
    built_world = candidate.world
    snapshot = pipeline.admit(candidate, split="train")

    service = OpenRange(store=store, live_backend=backend)
    service.reset(snapshot.snapshot_id, EpisodeConfig(mode="joint_pool", green_enabled=False))

    red_first = snapshot.witness_bundle.red_witnesses[0].steps[0]
    decision = service.next_decision()
    assert decision.actor == "red"
    service.act(
        "red",
        Action(actor_id="red", role="red", kind=red_first.kind, payload={"target": red_first.target, **red_first.payload}),
    )

    live_pods = pod_registry[snapshot.snapshot_id]
    assert boots
    assert any("InitialAccess" in line for line in live_pods.logs)

    service.close()
    assert teardowns


def test_green_reactive_branches_flow_through_runtime_between_external_decisions(tmp_path: Path):
    store = FileSnapshotStore(tmp_path / "snapshots")
    pipeline = BuildPipeline(store=store)
    snapshot = pipeline.admit(pipeline.build(_manifest_payload(), tmp_path / "rendered"), split="train")
    service = OpenRange(store=store)
    service.reset(snapshot.snapshot_id, EpisodeConfig(mode="joint_pool", green_enabled=True))

    red_steps = snapshot.witness_bundle.red_witnesses[0].steps
    credential_index = next(
        idx
        for idx, step in enumerate(red_steps)
        if "cred" in str(step.payload.get("asset", ""))
    )

    for idx, step in enumerate(red_steps[: credential_index + 1]):
        decision = service.next_decision()
        assert decision.actor == "red"
        service.act(
            "red",
            Action(actor_id="red", role="red", kind=step.kind, payload={"target": step.target, **step.payload}),
        )
        decision = service.next_decision()
        assert decision.actor == "blue"
        service.act("blue", Action(actor_id="blue", role="blue", kind="sleep", payload={}))

    decision = service.next_decision()
    assert decision.actor == "red"
    service.act("red", Action(actor_id="red", role="red", kind="sleep", payload={}))
    decision = service.next_decision()
    assert decision.actor == "blue"
    service.act("blue", Action(actor_id="blue", role="blue", kind="sleep", payload={}))

    for _ in range(4):
        events = service.runtime.export_events()
        if any(
            event.actor == "green"
            and event.event_type == "RecoveryCompleted"
            and event.target_entity == "idp_admin_cred"
            for event in events
        ):
            break
        decision = service.next_decision()
        service.act(decision.actor, Action(actor_id=decision.actor, role=decision.actor, kind="sleep", payload={}))

    events = service.runtime.export_events()
    assert any(event.actor == "green" and event.event_type == "DetectionAlertRaised" for event in events)
    assert any(
        event.actor == "green"
        and event.event_type == "RecoveryCompleted"
        and event.target_entity == "idp_admin_cred"
        for event in events
    )
