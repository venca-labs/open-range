from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from open_range.cluster import ExecResult
from open_range.episode_config import EpisodeConfig
from open_range.pipeline import BuildPipeline
from open_range.runtime_types import Action
from open_range.service import OpenRange
from open_range.store import FileSnapshotStore


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


def _service_and_snapshots(tmp_path: Path):
    store = FileSnapshotStore(tmp_path / "snapshots")
    pipeline = BuildPipeline(store=store)
    train_snapshot = pipeline.admit(pipeline.build(_manifest_payload(), tmp_path / "train-render"), split="train")

    eval_payload = _manifest_payload()
    eval_payload["seed"] = 2048
    eval_snapshot = pipeline.admit(pipeline.build(eval_payload, tmp_path / "eval-render"), split="eval")
    return OpenRange(store=store), train_snapshot, eval_snapshot


def test_service_reset_loads_snapshot_and_primes_first_decision(tmp_path: Path):
    service, train_snapshot, _eval_snapshot = _service_and_snapshots(tmp_path)

    state = service.reset(train_snapshot.snapshot_id, EpisodeConfig(mode="joint_pool", green_enabled=False))

    assert state.snapshot_id == train_snapshot.snapshot_id
    assert service.active_snapshot_id == train_snapshot.snapshot_id
    assert state.next_actor == "red"
    assert state.controls_red is True
    assert state.controls_blue is True


def test_service_can_sample_held_out_eval_pool(tmp_path: Path):
    service, _train_snapshot, eval_snapshot = _service_and_snapshots(tmp_path)

    state = service.reset(
        None,
        EpisodeConfig(mode="joint_pool", green_enabled=False),
        split="eval",
        strategy="latest",
        sample_seed=11,
    )

    assert state.snapshot_id == eval_snapshot.snapshot_id
    assert service.active_snapshot_id == eval_snapshot.snapshot_id


def test_service_proxies_runtime_decisions_and_actions(tmp_path: Path):
    service, train_snapshot, _eval_snapshot = _service_and_snapshots(tmp_path)
    service.reset(train_snapshot.snapshot_id, EpisodeConfig(mode="joint_pool", green_enabled=False))

    decision = service.next_decision()
    red_step = train_snapshot.witness_bundle.red_witnesses[0].steps[0]
    result = service.act(
        "red",
        Action(actor_id="red", role="red", kind=red_step.kind, payload={"target": red_step.target, **red_step.payload}),
    )

    assert decision.actor == "red"
    assert decision.obs.actor_id == "red"
    assert result.sim_time == 0.0
    assert service.state().next_actor == ""


def test_service_boots_and_tears_down_live_release(tmp_path: Path):
    store = FileSnapshotStore(tmp_path / "snapshots")
    pipeline = BuildPipeline(store=store)
    snapshot = pipeline.admit(pipeline.build(_manifest_payload(), tmp_path / "rendered"), split="train")
    calls: list[str] = []

    class FakePods:
        def __init__(self, pod_ids):
            self.pod_ids = pod_ids

        async def is_healthy(self, service: str) -> bool:
            return service in self.pod_ids

        async def exec(self, service: str, cmd: str, timeout: float = 30.0) -> ExecResult:
            del timeout
            return ExecResult(stdout=f"{service}:{cmd}", stderr="", exit_code=0)

    class FakeBackend:
        def boot(self, *, snapshot_id: str, artifacts_dir: Path):
            calls.append(f"boot:{snapshot_id}:{artifacts_dir.name}")
            pod_ids = {service.id: f"ns/{service.id}-pod" for service in snapshot.world.services}
            pod_ids["sandbox-red"] = "ns/sandbox-red-pod"
            pod_ids["sandbox-blue"] = "ns/sandbox-blue-pod"
            for persona in snapshot.world.green_personas:
                pod_ids[f"sandbox-green-{persona.id.replace('_', '-').lower()}"] = f"ns/{persona.id}-pod"
            return SimpleNamespace(release_name=f"or-{snapshot_id}", pods=FakePods(pod_ids))

        def teardown(self, release) -> None:
            calls.append(f"down:{release.release_name}")

    service = OpenRange(store=store, live_backend=FakeBackend())
    service.reset(snapshot.snapshot_id, EpisodeConfig(mode="joint_pool", green_enabled=False))
    assert service.live_release is not None
    service.close()

    assert calls[0].startswith("boot:")
    assert calls[-1].startswith("down:")
