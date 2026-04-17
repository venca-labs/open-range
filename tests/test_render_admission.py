from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import open_range.admission.controller as controller_mod
import open_range.admission.live as live_checks_mod
from open_range.admission.controller import LocalAdmissionController
from open_range.compiler import EnterpriseSaaSManifestCompiler
from open_range.config import BuildConfig
from open_range.objectives.engine import PredicateEngine
from open_range.render import EnterpriseSaaSKindRenderer
from open_range.render.images import SANDBOX_IMAGE_BY_ROLE, service_image_for_kind
from open_range.render.live import ExecResult, KindBackend
from open_range.store import BuildPipeline, FileSnapshotStore, load_runtime_snapshot
from open_range.synth import EnterpriseSaaSWorldSynthesizer
from open_range.training.curriculum import FrontierMutationPolicy, PopulationStats
from open_range.weaknesses import CatalogWeaknessSeeder
from open_range.weaknesses.code_web import code_web_payload
from tests.support import (
    OFFLINE_BUILD_CONFIG,
    OFFLINE_REFERENCE_BUILD_CONFIG,
    manifest_payload,
)


def _manifest_payload() -> dict:
    payload = manifest_payload()
    payload["objectives"]["red"] = [
        {"predicate": "asset_read(finance_docs)"},
        {"predicate": "credential_obtained(idp_admin_cred)"},
    ]
    return payload


def _build_seeded_world():
    world = EnterpriseSaaSManifestCompiler().compile(_manifest_payload())
    return CatalogWeaknessSeeder().apply(world)


def _synth(world, tmp_path: Path):
    return EnterpriseSaaSWorldSynthesizer().synthesize(world, tmp_path / "synth")


def _code_web_response(
    world, cmd: str, patched_services: set[str]
) -> ExecResult | None:
    weakness = next(
        (weak for weak in world.weaknesses if weak.family == "code_web"), None
    )
    if weakness is None or weakness.target in patched_services:
        return None
    payload = code_web_payload(world, weakness)
    path = str(payload.get("path", ""))
    if "http://svc-web:80" not in cmd or path not in cmd:
        return None
    return ExecResult(
        stdout=str(payload.get("expect_contains", "")), stderr="", exit_code=0
    )


def test_kind_renderer_emits_expected_files(tmp_path: Path):
    world = _build_seeded_world()
    synth = _synth(world, tmp_path)
    artifacts = EnterpriseSaaSKindRenderer().render(world, synth, tmp_path / "rendered")
    finance_docs = next(asset for asset in world.assets if asset.id == "finance_docs")

    assert Path(artifacts.values_path).exists()
    assert Path(artifacts.kind_config_path).exists()
    assert Path(artifacts.manifest_summary_path).exists()
    assert Path(synth.summary_path).exists()
    assert "svc-web" in artifacts.chart_values["services"]
    assert "mailboxes" not in artifacts.chart_values
    assert "weaknesses" not in artifacts.chart_values
    assert artifacts.chart_values["services"]["svc-web"]["enabled"] is True
    assert (
        artifacts.chart_values["services"]["svc-web"]["payloads"][0]["mountPath"]
        == "/var/www/html/index.html"
    )
    assert artifacts.chart_values["global"]["namePrefix"].startswith(
        "enterprise-saas-v1-"
    )
    assert "sandbox-red" in artifacts.chart_values["sandboxes"]
    assert (
        artifacts.chart_values["sandboxes"]["sandbox-red"]["image"]
        == SANDBOX_IMAGE_BY_ROLE["red"]
    )
    assert (
        artifacts.chart_values["sandboxes"]["sandbox-blue"]["image"]
        == SANDBOX_IMAGE_BY_ROLE["blue"]
    )
    assert (
        artifacts.chart_values["services"]["svc-db"]["payloads"][0]["mountPath"]
        == "/docker-entrypoint-initdb.d/01-init.sql"
    )
    assert finance_docs.location == "svc-fileshare:/srv/shared/finance_docs.txt"
    assert (
        PredicateEngine(world).objective_grader("asset_read(finance_docs)").path
        == "/srv/shared/finance_docs.txt"
    )
    siem_command = artifacts.chart_values["services"]["svc-siem"]["command"][-1]
    assert "busybox nc -lp 9201" in siem_command
    assert "busybox httpd -f -p 9200 -h /srv/http/siem" in siem_command
    assert all(
        payload["mountPath"] != "/srv/http/siem/all.log"
        for payload in artifacts.chart_values["services"]["svc-siem"]["payloads"]
    )
    assert any(
        rule["fromZone"] == "external" and rule["toZone"] == "dmz"
        for rule in artifacts.chart_values["firewallRules"]
    )
    assert artifacts.pinned_image_digests["svc-web"].startswith(
        f"{service_image_for_kind('web_app')}@sha256:"
    )


def test_admission_controller_admits_seeded_world(tmp_path: Path):
    world = _build_seeded_world()
    artifacts = EnterpriseSaaSKindRenderer().render(
        world, _synth(world, tmp_path), tmp_path / "rendered"
    )

    reference_bundle, report = LocalAdmissionController(mode="fail_fast").admit(
        world, artifacts, OFFLINE_REFERENCE_BUILD_CONFIG
    )

    assert report.admitted is True
    assert report.graph_ok is True
    assert report.reference_attack_ok is True
    assert report.blue_signal_points == len(
        {edge.source for edge in world.telemetry_edges}
    )
    assert report.benchmark_tags_covered
    assert report.stages[-1].name == "determinism"
    objective_grounding = next(
        stage for stage in report.stages if stage.name == "static"
    ).checks[3]
    assert objective_grounding.name == "objective_grounding"
    assert objective_grounding.details["graders"]
    red_reference = next(
        stage for stage in report.stages if stage.name == "red_reference"
    ).checks[0]
    assert sorted(red_reference.details["satisfied_predicates"]) == sorted(
        objective.predicate for objective in world.red_objectives if objective.terminal
    )
    assert reference_bundle.reference_attack_traces
    assert reference_bundle.reference_defense_traces


def test_auto_live_backend_uses_resolved_host_binaries(monkeypatch) -> None:
    monkeypatch.setattr(
        controller_mod,
        "resolve_host_binary",
        lambda name: {
            "helm": "/opt/tools/helm",
            "kind": "/opt/tools/kind",
            "docker": "/opt/tools/docker",
        }.get(name),
    )
    calls: list[list[str]] = []

    def fake_run(args, **kwargs):
        del kwargs
        calls.append(list(args))
        return SimpleNamespace(returncode=0, stdout="openrange\n")

    monkeypatch.setattr(controller_mod.subprocess, "run", fake_run)

    backend = LocalAdmissionController()._auto_live_backend(
        BuildConfig(validation_profile="full", cluster_backend="kind")
    )

    assert isinstance(backend, KindBackend)
    assert calls == [["/opt/tools/kind", "get", "clusters"]]


def test_admission_controller_registers_security_stage_when_enabled(tmp_path: Path):
    pipeline = BuildPipeline(store=FileSnapshotStore(tmp_path / "snapshots"))
    candidate = pipeline.build(
        _manifest_payload(),
        tmp_path / "rendered-security",
        BuildConfig(
            validation_profile="graph_only",
            security_integration_enabled=True,
            security_tier=3,
        ),
    )

    _reference_bundle, report = LocalAdmissionController(mode="fail_fast").admit(
        candidate.world,
        candidate.artifacts,
        candidate.build_config,
    )

    security_stage = next(stage for stage in report.stages if stage.name == "security")

    assert {check.name for check in security_stage.checks} == {
        "identity_enforcement",
        "encryption_enforcement",
        "mtls_enforcement",
    }


def test_admission_controller_offline_witness_can_ground_pinned_non_code_weakness(
    tmp_path: Path,
):
    payload = _manifest_payload()
    payload["security"]["allowed_weakness_families"] = ["secret_exposure"]
    payload["security"]["pinned_weaknesses"] = [
        {
            "family": "secret_exposure",
            "kind": "credential_in_share",
            "target": "asset:idp_admin_cred",
        },
    ]
    world = CatalogWeaknessSeeder().apply(
        EnterpriseSaaSManifestCompiler().compile(payload)
    )
    artifacts = EnterpriseSaaSKindRenderer().render(
        world, _synth(world, tmp_path), tmp_path / "rendered-non-code"
    )

    reference_bundle, report = LocalAdmissionController(mode="fail_fast").admit(
        world, artifacts, OFFLINE_REFERENCE_BUILD_CONFIG
    )

    assert report.admitted is True


def test_admission_rejects_unsupported_runtime_blue_objective(tmp_path: Path) -> None:
    payload = _manifest_payload()
    payload["objectives"]["blue"] = [
        {"predicate": "intrusion_detected(credential_obtained)"},
        {"predicate": "intrusion_contained(before_asset_read)"},
        {"predicate": "service_health_above(0.9)"},
    ]
    world = CatalogWeaknessSeeder().apply(
        EnterpriseSaaSManifestCompiler().compile(payload)
    )
    artifacts = EnterpriseSaaSKindRenderer().render(
        world, _synth(world, tmp_path), tmp_path / "rendered-unsupported-blue"
    )

    _reference_bundle, report = LocalAdmissionController(mode="fail_fast").admit(
        world, artifacts, OFFLINE_REFERENCE_BUILD_CONFIG
    )

    objective_grounding = next(
        check
        for stage in report.stages
        if stage.name == "static"
        for check in stage.checks
        if check.name == "objective_grounding"
    )
    assert report.admitted is False
    assert objective_grounding.passed is False
    assert (
        "unsupported runtime blue objective intrusion_detected(credential_obtained)"
        in objective_grounding.error
    )


def test_mutated_world_blue_reference_does_not_claim_initial_access_from_later_event(
    tmp_path: Path,
) -> None:
    base_world = _build_seeded_world()
    mutation = FrontierMutationPolicy().mutate(
        base_world,
        parent_stats=PopulationStats(
            snapshot_id="snap-base",
            world_id=base_world.world_id,
            split="train",
            episodes=4,
            red_win_rate=0.25,
            blue_win_rate=0.75,
            avg_ticks=7.0,
            flake_rate=0.0,
            novelty=0.6,
            blue_signal_points=4,
        ),
        child_seed=1102,
    )
    artifacts = EnterpriseSaaSKindRenderer().render(
        mutation, _synth(mutation, tmp_path), tmp_path / "rendered-mutation"
    )

    reference_bundle, report = LocalAdmissionController(mode="fail_fast").admit(
        mutation, artifacts, OFFLINE_REFERENCE_BUILD_CONFIG
    )

    assert report.admitted is False
    defense_trace = reference_bundle.reference_defense_traces[0]
    finding_step = next(
        step for step in defense_trace.steps if step.kind == "submit_finding"
    )
    assert finding_step.target != "svc-email"
    assert report.reference_attack_ok is True
    assert report.reference_defense_ok is False


def test_admission_controller_can_run_optional_live_backend(tmp_path: Path):
    world = _build_seeded_world()
    artifacts = EnterpriseSaaSKindRenderer().render(
        world, _synth(world, tmp_path), tmp_path / "rendered"
    )
    calls: list[str] = []

    class FakePods:
        def __init__(self, pod_ids):
            self.pod_ids = pod_ids
            self.logs: list[str] = []
            self.contained: set[str] = set()
            self.patched: set[str] = set()
            self.web_guards: set[str] = set()

        async def is_healthy(self, service: str) -> bool:
            return service in self.pod_ids

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
            if ">> /srv/http/siem/all.log" in cmd:
                line = cmd.split("printf '%s\\n' ", 1)[1].split(
                    " >> /srv/http/siem/all.log", 1
                )[0]
                self.logs.append(line.strip("'"))
                return ExecResult(stdout="", stderr="", exit_code=0)
            if "grep -q 'InitialAccess' /srv/http/siem/all.log" in cmd:
                present = any("InitialAccess" in line for line in self.logs)
                return ExecResult(stdout="", stderr="", exit_code=0 if present else 1)
            if service.startswith("sandbox-") and (
                "wget -qO- http://svc-siem:9200/all.log" in cmd
            ):
                return ExecResult(stdout="\n".join(self.logs), stderr="", exit_code=0)
            if service == "sandbox-red":
                seeded = _code_web_response(world, cmd, self.web_guards)
                if seeded is not None:
                    return seeded
            if service == "sandbox-red" and any(
                target in cmd for target in ("svc-fileshare", "svc-db", "svc-idp")
            ):
                return ExecResult(stdout="", stderr="blocked", exit_code=1)
            return ExecResult(stdout=f"{service}:{cmd}", stderr="", exit_code=0)

    class FakeBackend:
        def boot(self, *, snapshot_id: str, artifacts_dir: Path):
            calls.append(f"boot:{snapshot_id}:{artifacts_dir.name}")
            pod_ids = {service.id: f"ns/{service.id}-pod" for service in world.services}
            pod_ids["sandbox-red"] = "ns/sandbox-red-pod"
            pod_ids["sandbox-blue"] = "ns/sandbox-blue-pod"
            for persona in world.green_personas:
                pod_ids[f"sandbox-green-{persona.id.replace('_', '-').lower()}"] = (
                    f"ns/{persona.id}-pod"
                )
            return SimpleNamespace(
                release_name=f"or-{snapshot_id}",
                artifacts_dir=artifacts_dir,
                pods=FakePods(pod_ids),
            )

        def teardown(self, release) -> None:
            calls.append(f"down:{release.release_name}")

    reference_bundle, report = LocalAdmissionController(
        mode="fail_fast",
        live_backend=FakeBackend(),
    ).admit(world, artifacts, OFFLINE_BUILD_CONFIG)

    assert reference_bundle.reference_attack_traces
    assert report.admitted is True
    assert any(stage.name == "kind_live" for stage in report.stages)
    assert calls[0].startswith("boot:")
    assert calls[-1].startswith("down:")


def test_graph_plus_live_skips_full_only_live_checks(tmp_path: Path) -> None:
    world = _build_seeded_world()
    artifacts = EnterpriseSaaSKindRenderer().render(
        world, _synth(world, tmp_path), tmp_path / "rendered-graph-plus-live"
    )
    pod_ids = {service.id: f"ns/{service.id}-pod" for service in world.services}
    pod_ids["sandbox-red"] = "ns/sandbox-red-pod"
    pod_ids["sandbox-blue"] = "ns/sandbox-blue-pod"

    class FakePods:
        def __init__(self, pods):
            self.pod_ids = pods
            self.logs: list[str] = []

        async def is_healthy(self, service: str) -> bool:
            return service in self.pod_ids

        async def exec(
            self,
            service: str,
            cmd: str,
            timeout: float = 30.0,
            *,
            container: str | None = None,
        ) -> ExecResult:
            del timeout, container
            if "grep -q 'InitialAccess' /srv/http/siem/all.log" in cmd:
                return ExecResult(stdout="", stderr="", exit_code=0)
            self.logs.append(f"{service}:{cmd}")
            return ExecResult(stdout="ok", stderr="", exit_code=0)

    class FakeBackend:
        def boot(self, snapshot_id: str, artifacts_dir: Path):
            del snapshot_id, artifacts_dir
            return SimpleNamespace(
                release_name="or-graph-plus-live",
                pods=FakePods(pod_ids),
            )

        def teardown(self, release) -> None:
            del release

    _bundle, report = LocalAdmissionController(
        mode="analysis",
        live_backend=FakeBackend(),
    ).admit(
        world,
        artifacts,
        BuildConfig(validation_profile="graph_plus_live"),
    )

    kind_live = next(stage for stage in report.stages if stage.name == "kind_live")
    check_names = {check.name for check in kind_live.checks}

    assert "live_red_reference" in check_names
    assert "live_blue_reference" in check_names
    assert "live_determinism" not in check_names
    assert "live_necessity" not in check_names
    assert "live_shortcuts" not in check_names


def test_fail_fast_does_not_report_missing_live_backend_when_backend_exists(
    tmp_path: Path,
) -> None:
    world = _build_seeded_world().replace_edges(telemetry=())
    artifacts = EnterpriseSaaSKindRenderer().render(
        world, _synth(world, tmp_path), tmp_path / "rendered-fail-fast"
    )

    class FakeBackend:
        def boot(self, snapshot_id: str, artifacts_dir: Path):
            del snapshot_id, artifacts_dir
            raise AssertionError("live backend should not run after offline fail-fast")

        def teardown(self, release) -> None:
            del release

    _bundle, report = LocalAdmissionController(
        mode="fail_fast",
        live_backend=FakeBackend(),
    ).admit(
        world,
        artifacts,
        BuildConfig(validation_profile="graph_plus_live"),
    )

    failed = {
        check.name
        for stage in report.stages
        for check in stage.checks
        if not check.passed
    }

    assert "live_backend_required" not in failed


def test_live_service_smoke_check_uses_reachable_zone_runners() -> None:
    world = _build_seeded_world()
    calls: list[tuple[str, str]] = []

    class FakePods:
        async def exec(
            self, service: str, cmd: str, timeout: float = 30.0
        ) -> ExecResult:
            del timeout
            calls.append((service, cmd))
            return ExecResult(stdout="ok", stderr="", exit_code=0)

    report = live_checks_mod.check_live_service_smoke(
        world, SimpleNamespace(pods=FakePods())
    )
    calls_by_target = {
        service.id: runner for service, (runner, _cmd) in zip(world.services, calls)
    }

    assert report.passed is True
    assert calls_by_target["svc-web"] == "sandbox-red"
    assert calls_by_target["svc-email"] == "sandbox-red"
    assert calls_by_target["svc-idp"] == "sandbox-blue"
    assert calls_by_target["svc-siem"] == "sandbox-blue"
    assert calls_by_target["svc-fileshare"].startswith("sandbox-green-")
    assert calls_by_target["svc-db"].startswith("sandbox-green-")


def test_live_service_smoke_retries_svc_email_like_db(monkeypatch) -> None:
    world = _build_seeded_world()
    attempts_by_command: dict[str, int] = {}

    monkeypatch.setattr(live_checks_mod.time, "sleep", lambda _seconds: None)

    class FakePods:
        async def exec(
            self, service: str, cmd: str, timeout: float = 30.0
        ) -> ExecResult:
            del service, timeout
            attempts_by_command[cmd] = attempts_by_command.get(cmd, 0) + 1
            if "svc-email" in cmd and attempts_by_command[cmd] < 10:
                return ExecResult(stdout="", stderr="warming up", exit_code=1)
            return ExecResult(stdout="ok", stderr="", exit_code=0)

    report = live_checks_mod.check_live_service_smoke(
        world, SimpleNamespace(pods=FakePods())
    )

    assert report.passed is True
    email_probe = next(cmd for cmd in attempts_by_command if "svc-email" in cmd)
    assert attempts_by_command[email_probe] == 10


def test_live_db_mtls_check_proves_client_cert_required(tmp_path: Path) -> None:
    pipeline = BuildPipeline(store=FileSnapshotStore(tmp_path / "snapshots"))
    candidate = pipeline.build(
        _manifest_payload(),
        tmp_path / "rendered-security",
        BuildConfig(
            validation_profile="graph_only",
            security_integration_enabled=True,
            security_tier=3,
        ),
    )
    calls: list[tuple[str, str]] = []

    class FakePods:
        async def exec(
            self,
            service: str,
            cmd: str,
            timeout: float = 30.0,
            *,
            container: str | None = None,
        ) -> ExecResult:
            del timeout
            calls.append((service, container or "", cmd))
            if container == "db-client-mtls":
                return ExecResult(stdout="1\n", stderr="", exit_code=0)
            if "mysql --protocol=TCP" in cmd:
                return ExecResult(stdout="", stderr="ERROR 1045 (28000)", exit_code=1)
            return ExecResult(stdout="", stderr="miss", exit_code=1)

    report = live_checks_mod.check_live_db_mtls(
        candidate.world, SimpleNamespace(pods=FakePods())
    )

    assert report.passed is True
    assert calls[0][0] == "svc-web"
    assert calls[0][1] == "db-client-mtls"
    assert (
        "--defaults-extra-file=/etc/mysql/conf.d/openrange-client-mtls.cnf"
        in calls[0][2]
    )
    assert calls[1][0] == "sandbox-red"
    assert "--ssl-cert=/etc/mtls/cert.pem" not in calls[1][2]


def test_admission_controller_rejects_world_without_telemetry(tmp_path: Path):
    world = _build_seeded_world()
    broken = world.replace_edges(telemetry=())
    artifacts = EnterpriseSaaSKindRenderer().render(
        broken, _synth(broken, tmp_path), tmp_path / "rendered"
    )

    _bundle, report = LocalAdmissionController(mode="analysis").admit(
        broken, artifacts, OFFLINE_REFERENCE_BUILD_CONFIG
    )

    assert report.admitted is False
    failed = {
        check.name
        for stage in report.stages
        for check in stage.checks
        if not check.passed
    }
    assert "siem_ingest" in failed


def test_admission_controller_rejects_public_secret_leak_in_artifacts(tmp_path: Path):
    world = _build_seeded_world()
    synth = _synth(world, tmp_path)
    leak_path = next(
        file
        for file in synth.generated_files
        if "/svc-web/" in file and file.endswith("index.html")
    )
    Path(leak_path).write_text(
        Path(leak_path).read_text(encoding="utf-8")
        + "\nseeded-sensitive-idp_admin_cred\n",
        encoding="utf-8",
    )
    artifacts = EnterpriseSaaSKindRenderer().render(world, synth, tmp_path / "rendered")

    _bundle, report = LocalAdmissionController(mode="analysis").admit(
        world, artifacts, OFFLINE_REFERENCE_BUILD_CONFIG
    )

    assert report.admitted is False
    failed = {
        check.name
        for stage in report.stages
        for check in stage.checks
        if not check.passed
    }
    assert "shortcut_probes" in failed


def test_admission_controller_rejects_unlogged_critical_action_targets(tmp_path: Path):
    world = _build_seeded_world()
    weakened_services = []
    for service in world.services:
        if service.id == "svc-web":
            weakened_services.append(
                service.model_copy(update={"telemetry_surfaces": ()})
            )
        else:
            weakened_services.append(service)
    broken = world.model_copy(update={"services": tuple(weakened_services)})
    artifacts = EnterpriseSaaSKindRenderer().render(
        broken, _synth(broken, tmp_path), tmp_path / "rendered"
    )

    _bundle, report = LocalAdmissionController(mode="analysis").admit(
        broken, artifacts, OFFLINE_REFERENCE_BUILD_CONFIG
    )

    assert report.admitted is False
    failed = {
        check.name
        for stage in report.stages
        for check in stage.checks
        if not check.passed
    }
    assert "shortcut_probes" in failed


def test_snapshot_store_persists_v1_snapshot(tmp_path: Path):
    world = _build_seeded_world()
    synth = _synth(world, tmp_path)
    artifacts = EnterpriseSaaSKindRenderer().render(world, synth, tmp_path / "rendered")
    reference_bundle, report = LocalAdmissionController(mode="fail_fast").admit(
        world, artifacts, OFFLINE_BUILD_CONFIG
    )
    store = FileSnapshotStore(tmp_path / "snapshots")

    snapshot = store.create(world, artifacts, reference_bundle, report, synth=synth)
    loaded = load_runtime_snapshot(store, snapshot.snapshot_id)

    assert snapshot.snapshot_id == loaded.snapshot_id
    assert snapshot.db_seed_state == {}
    assert snapshot.file_assets == {}
    assert not any(Path(snapshot.state_seed_dir).iterdir())
    assert not (Path(snapshot.artifacts_dir) / "security").exists()
    assert not (Path(snapshot.artifacts_dir) / "synth").exists()
    assert all(
        "content" not in payload
        for service in snapshot.artifacts.chart_values["services"].values()
        for payload in service.get("payloads", ())
    )
    assert loaded.snapshot_id == snapshot.snapshot_id
    assert loaded.world_id == world.world_id
    assert loaded.seed == world.seed
    assert loaded.world.world_id == world.world_id
    assert loaded.validator_report.admitted is True
    assert loaded.reference_bundle.reference_attack_traces
    assert loaded.artifacts_dir != snapshot.artifacts_dir
    assert loaded.state_seed_dir != snapshot.state_seed_dir
    assert any(
        "content" in payload
        for service in loaded.artifacts.chart_values["services"].values()
        for payload in service.get("payloads", ())
    )
    assert Path(loaded.validator_report_path).exists()
    assert all(
        not check.details
        for stage in loaded.validator_report.stages
        for check in stage.checks
    )
