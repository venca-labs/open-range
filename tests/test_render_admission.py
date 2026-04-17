from __future__ import annotations

import importlib
import re
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import urlparse

from open_range._runtime_store import load_runtime_snapshot
from open_range.admission import ValidatorCheckReport
from open_range.admit import LocalAdmissionController
from open_range.build_config import BuildConfig
from open_range.cluster import ExecResult
from open_range.code_web import code_web_payload
from open_range.compiler import EnterpriseSaaSManifestCompiler
from open_range.curriculum import FrontierMutationPolicy, PopulationStats
from open_range.image_policy import SANDBOX_IMAGE_BY_ROLE, service_image_for_kind
from open_range.pipeline import BuildPipeline
from open_range.predicates import PredicateEngine
from open_range.probe_planner import build_reference_bundle
from open_range.render import EnterpriseSaaSKindRenderer
from open_range.store import FileSnapshotStore
from open_range.synth import EnterpriseSaaSWorldSynthesizer
from open_range.weaknesses import CatalogWeaknessSeeder
from tests.support import (
    OFFLINE_BUILD_CONFIG,
    OFFLINE_REFERENCE_BUILD_CONFIG,
    manifest_payload,
)

admit_mod = importlib.import_module("open_range.admit")
live_checks_mod = importlib.import_module("open_range.live_checks")


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
    for url in _command_urls(cmd):
        parsed = urlparse(url)
        host = (parsed.hostname or "").split(".", 1)[0]
        if host == weakness.target and parsed.path == path:
            return ExecResult(
                stdout=str(payload.get("expect_contains", "")),
                stderr="",
                exit_code=0,
            )
    return None


def _asset_bridge_response(world, cmd: str) -> ExecResult | None:
    for url in _command_urls(cmd):
        parsed = urlparse(url)
        host = (parsed.hostname or "").split(".", 1)[0]
        if parsed.port != 8080:
            continue
        for asset in world.assets:
            if asset.owner_service != host:
                continue
            if parsed.path != f"/{asset.id}.txt":
                continue
            return ExecResult(
                stdout=f"seeded-{asset.asset_class}-{asset.id}",
                stderr="",
                exit_code=0,
            )
    return None


def _command_urls(cmd: str) -> list[str]:
    return re.findall(r"https?://[^'\" ]+", cmd)


def test_weakness_seeder_is_deterministic():
    world_a = _build_seeded_world()
    world_b = _build_seeded_world()

    assert world_a.weaknesses == world_b.weaknesses
    assert len(world_a.weaknesses) == 2
    assert any(
        weak.objective_tags for weak in world_a.weaknesses if weak.family == "code_web"
    )


def test_weakness_seeder_respects_allowed_families():
    payload = _manifest_payload()
    payload["security"]["allowed_weakness_families"] = ["code_web"]
    world = EnterpriseSaaSManifestCompiler().compile(payload)

    seeded = CatalogWeaknessSeeder().apply(world)

    assert {weak.family for weak in seeded.weaknesses} == {"code_web"}


def test_kind_renderer_emits_expected_files(tmp_path: Path):
    world = _build_seeded_world()
    synth = _synth(world, tmp_path)
    artifacts = EnterpriseSaaSKindRenderer().render(world, synth, tmp_path / "rendered")
    finance_docs = next(asset for asset in world.assets if asset.id == "finance_docs")
    idp_admin_cred = next(
        asset for asset in world.assets if asset.id == "idp_admin_cred"
    )

    assert Path(artifacts.values_path).exists()
    assert Path(artifacts.kind_config_path).exists()
    assert Path(artifacts.manifest_summary_path).exists()
    assert Path(synth.summary_path).exists()
    assert "svc-web" in artifacts.chart_values["services"]
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
    idp_service = artifacts.chart_values["services"]["svc-idp"]
    fileshare_service = artifacts.chart_values["services"]["svc-fileshare"]
    assert artifacts.chart_values["services"]["svc-email"]["env"] == {
        "MAILNAME": "corp.local",
        "ALLOWED_SENDER_DOMAINS": "corp.local",
    }
    assert finance_docs.location == "svc-fileshare:/srv/shared/finance_docs.txt"
    assert (
        idp_admin_cred.location
        == "svc-idp:/var/lib/openrange/secrets/idp_admin_cred.txt"
    )
    assert (
        PredicateEngine(world).objective_grader("asset_read(finance_docs)").path
        == "/srv/shared/finance_docs.txt"
    )
    siem_command = artifacts.chart_values["services"]["svc-siem"]["command"][-1]
    assert "busybox nc -lp 9201" in siem_command
    assert "busybox httpd -f -p 9200 -h /srv/http/siem" in siem_command
    assert any(port["port"] == 8080 for port in idp_service["ports"])
    assert any(port["port"] == 8080 for port in fileshare_service["ports"])
    assert idp_service["sidecars"][0]["name"] == "openrange-asset-bridge"
    assert fileshare_service["sidecars"][0]["name"] == "openrange-asset-bridge"
    assert idp_service["sidecars"][0]["command"] == [
        "/bin/sh",
        "-lc",
        "busybox httpd -f -p 8080 -h /var/lib/openrange/secrets",
    ]
    assert fileshare_service["sidecars"][0]["command"] == [
        "/bin/sh",
        "-lc",
        "busybox httpd -f -p 8080 -h /srv/shared",
    ]
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


def test_mutated_world_blue_reference_skips_blindspot_only_detection_targets(
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

    assert report.admitted is True
    defense_trace = reference_bundle.reference_defense_traces[0]
    finding_step = next(
        step for step in defense_trace.steps if step.kind == "submit_finding"
    )
    assert finding_step.target != "svc-email"
    assert report.reference_attack_ok is True
    assert report.necessity_ok is True


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
            if service.startswith("sandbox-"):
                seeded = _code_web_response(world, cmd, self.web_guards)
                if seeded is not None:
                    return seeded
                asset_bridge = _asset_bridge_response(world, cmd)
                if asset_bridge is not None:
                    return asset_bridge
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


def test_no_necessity_profile_skips_auto_live_backend_probe(
    tmp_path: Path, monkeypatch
) -> None:
    world = _build_seeded_world()
    artifacts = EnterpriseSaaSKindRenderer().render(
        world, _synth(world, tmp_path), tmp_path / "rendered"
    )
    which_calls: list[str] = []
    run_calls: list[tuple[object, ...]] = []
    paths = {
        "helm": "/usr/bin/helm",
        "k3d": "/usr/bin/k3d",
        "docker": "/usr/bin/docker",
    }

    def fake_resolve(cmd: str) -> str:
        which_calls.append(cmd)
        return paths[cmd]

    def fake_run(*args, **kwargs):
        del kwargs
        run_calls.append(args)
        return SimpleNamespace(returncode=0, stdout="openrange\n", stderr="")

    monkeypatch.setattr(admit_mod, "resolve_host_binary", fake_resolve)
    monkeypatch.setattr(admit_mod.subprocess, "run", fake_run)

    _bundle, report = LocalAdmissionController(mode="fail_fast").admit(
        world, artifacts, OFFLINE_REFERENCE_BUILD_CONFIG
    )

    assert report.admitted is True
    assert all(stage.name != "kind_live" for stage in report.stages)
    assert which_calls == []
    assert run_calls == []


def test_full_live_profile_requires_cilium_network_policy_backend(
    tmp_path: Path,
) -> None:
    world = _build_seeded_world()
    artifacts = EnterpriseSaaSKindRenderer().render(
        world, _synth(world, tmp_path), tmp_path / "rendered-full-live"
    )

    _bundle, report = LocalAdmissionController(mode="fail_fast").admit(
        world,
        artifacts,
        BuildConfig(validation_profile="full", network_policy_backend="kubernetes"),
    )

    live_stage = next(stage for stage in report.stages if stage.name == "kind_live")

    assert report.admitted is False
    assert live_stage.passed is False
    assert live_stage.checks[0].name == "cilium_required"
    assert "network_policy_backend='cilium'" in live_stage.checks[0].error


def test_k3d_profile_uses_k3d_auto_live_backend(tmp_path: Path, monkeypatch) -> None:
    _world = _build_seeded_world()
    _ = EnterpriseSaaSKindRenderer().render(
        _world, _synth(_world, tmp_path), tmp_path / "rendered-k3d"
    )
    which_calls: list[str] = []
    run_calls: list[tuple[object, ...]] = []
    paths = {
        "helm": "/usr/bin/helm",
        "k3d": "/usr/bin/k3d",
        "docker": "/usr/bin/docker",
    }

    def fake_resolve(cmd: str) -> str:
        which_calls.append(cmd)
        return paths[cmd]

    def fake_run(*args, **kwargs):
        del kwargs
        run_calls.append(args)
        cmd = args[0]
        if cmd[:4] == [paths["k3d"], "cluster", "list", "-o"]:
            return SimpleNamespace(
                returncode=0, stdout='[{"name":"openrange"}]', stderr=""
            )
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(admit_mod, "resolve_host_binary", fake_resolve)
    monkeypatch.setattr(admit_mod.subprocess, "run", fake_run)

    controller = LocalAdmissionController(mode="analysis")
    backend = controller._auto_live_backend(
        BuildConfig(cluster_backend="k3d", validation_profile="graph_plus_live")
    )

    assert backend is not None
    assert backend.__class__.__name__ == "K3dBackend"
    assert which_calls[:3] == ["helm", "k3d", "docker"]
    assert any(
        call[0][:4] == [paths["k3d"], "cluster", "list", "-o"] for call in run_calls
    )


def test_kind_profile_uses_resolved_binary_paths_for_auto_live_backend(
    monkeypatch,
) -> None:
    resolve_calls: list[str] = []
    run_calls: list[tuple[object, ...]] = []

    paths = {
        "helm": "/home/ghost/.local/bin/helm",
        "kind": "/home/ghost/.local/bin/kind",
        "docker": "/usr/bin/docker",
    }

    def fake_resolve(cmd: str) -> str | None:
        resolve_calls.append(cmd)
        return paths.get(cmd)

    def fake_run(*args, **kwargs):
        del kwargs
        run_calls.append(args)
        cmd = args[0]
        if cmd[:3] == [paths["kind"], "get", "clusters"]:
            return SimpleNamespace(returncode=0, stdout="openrange\n", stderr="")
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(admit_mod, "resolve_host_binary", fake_resolve)
    monkeypatch.setattr(admit_mod.subprocess, "run", fake_run)

    controller = LocalAdmissionController(mode="analysis")
    backend = controller._auto_live_backend(BuildConfig(validation_profile="full"))

    assert backend is not None
    assert backend.__class__.__name__ == "KindBackend"
    assert resolve_calls[:3] == ["helm", "kind", "docker"]
    assert any(call[0][:3] == [paths["kind"], "get", "clusters"] for call in run_calls)


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
        world, SimpleNamespace(pods=FakePods(), release_name="or-demo")
    )
    calls_by_target = {
        service.id: (runner, cmd)
        for service, (runner, cmd) in zip(world.services, calls)
    }

    assert report.passed is True
    assert calls_by_target["svc-web"][0] == "sandbox-red"
    assert calls_by_target["svc-email"][0] == "sandbox-red"
    assert calls_by_target["svc-idp"][0] == "sandbox-blue"
    assert calls_by_target["svc-siem"][0] == "sandbox-blue"
    assert calls_by_target["svc-fileshare"][0].startswith("sandbox-green-")
    assert calls_by_target["svc-db"][0].startswith("sandbox-green-")
    assert "svc-web.or-demo-dmz" in calls_by_target["svc-web"][1]
    email_cmd = calls_by_target["svc-email"][1]
    assert "svc-email.or-demo-dmz" in email_cmd
    assert "printf '%b' 'QUIT\\\\r\\\\n'" in email_cmd


def test_live_checks_use_fresh_releases_for_stateful_groups(
    tmp_path: Path, monkeypatch
) -> None:
    world = _build_seeded_world()
    artifacts = EnterpriseSaaSKindRenderer().render(
        world, _synth(world, tmp_path), tmp_path / "rendered-live-groups"
    )
    reference_bundle = build_reference_bundle(world)
    boot_ids: list[str] = []
    teardown_ids: list[str] = []

    class FakePods:
        def __init__(self, discovered_services: set[str]) -> None:
            self.pod_ids = {
                service_id: f"ns/{service_id}-pod" for service_id in discovered_services
            }

        async def is_healthy(self, service: str) -> bool:
            del service
            return True

        async def exec(
            self,
            service: str,
            cmd: str,
            timeout: float = 30.0,
            *,
            container: str | None = None,
        ) -> ExecResult:
            del service, cmd, timeout, container
            return ExecResult(stdout="", stderr="", exit_code=0)

    class FakeBackend:
        def boot(self, *, snapshot_id: str, artifacts_dir: Path):
            del artifacts_dir
            boot_ids.append(snapshot_id)
            return SimpleNamespace(
                release_name=f"or-{snapshot_id}",
                pods=FakePods({service.id for service in world.services}),
            )

        def teardown(self, release) -> None:
            teardown_ids.append(release.release_name)

    def passing_check(name: str) -> ValidatorCheckReport:
        return ValidatorCheckReport(name=name, passed=True, details={}, error="")

    monkeypatch.setattr(
        admit_mod,
        "check_live_service_smoke",
        lambda world, release: passing_check("live_service_smoke"),
    )
    monkeypatch.setattr(
        admit_mod,
        "check_live_db_mtls",
        lambda world, release: passing_check("live_db_mtls"),
    )
    monkeypatch.setattr(
        admit_mod,
        "_live_red_reference_check",
        lambda snapshot, release, backend: passing_check("live_red_reference"),
    )
    monkeypatch.setattr(
        admit_mod,
        "_live_siem_ingest_check",
        lambda release: passing_check("live_siem_ingest"),
    )
    monkeypatch.setattr(
        admit_mod,
        "_live_blue_reference_check",
        lambda snapshot, backend: passing_check("live_blue_reference"),
    )
    monkeypatch.setattr(
        admit_mod,
        "_live_determinism_check",
        lambda snapshot, backend: passing_check("live_determinism"),
    )
    monkeypatch.setattr(
        admit_mod,
        "_live_necessity_check",
        lambda snapshot, release, backend: passing_check("live_necessity"),
    )
    monkeypatch.setattr(
        admit_mod,
        "_live_shortcut_probe_check",
        lambda snapshot, release: passing_check("live_shortcut_probes"),
    )
    monkeypatch.setattr(admit_mod, "uuid4", lambda: SimpleNamespace(hex="debugtag1234"))

    controller = LocalAdmissionController(mode="analysis")
    stage, live_info = controller._run_live_backend_checks(
        world, artifacts, reference_bundle, FakeBackend()
    )

    assert stage.passed is True
    assert boot_ids == [
        f"{world.world_id}-debugtag-live",
        f"{world.world_id}-debugtag-blue",
        f"{world.world_id}-debugtag-determinism",
        f"{world.world_id}-debugtag-necessity",
        f"{world.world_id}-debugtag-shortcuts",
    ]
    assert teardown_ids == [f"or-{snapshot_id}" for snapshot_id in boot_ids]
    assert live_info["live_release"] == f"or-{world.world_id}-debugtag-live"


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


def test_red_reference_uses_concrete_objective_steps(tmp_path: Path):
    world = _build_seeded_world()
    synth = _synth(world, tmp_path)
    artifacts = EnterpriseSaaSKindRenderer().render(world, synth, tmp_path / "rendered")

    reference_bundle, report = LocalAdmissionController(mode="fail_fast").admit(
        world, artifacts, OFFLINE_REFERENCE_BUILD_CONFIG
    )

    assert report.admitted is True
    steps = reference_bundle.reference_attack_traces[0].steps
    actions = [str(step.payload.get("action", "")) for step in steps]

    assert "traverse" not in actions
    assert "satisfy_objective" not in actions
    assert any(
        step.target == "svc-idp"
        and step.kind == "api"
        and step.payload.get("path") == "/idp_admin_cred.txt"
        and step.payload.get("port") == 8080
        and step.payload.get("objective") == "credential_obtained(idp_admin_cred)"
        for step in steps
    )
    assert any(
        step.target == "svc-fileshare"
        and step.kind == "api"
        and step.payload.get("path") == "/finance_docs.txt"
        and step.payload.get("port") == 8080
        and step.payload.get("objective") == "asset_read(finance_docs)"
        for step in steps
    )


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

    assert loaded.snapshot_id == snapshot.snapshot_id
    assert loaded.world_id == world.world_id
    assert loaded.seed == world.seed
    assert loaded.world.world_id == world.world_id
    assert loaded.validator_report.admitted is True
    assert loaded.reference_bundle.reference_attack_traces
    assert Path(loaded.validator_report_path).exists()
    assert "mailboxes" in loaded.identity_seed
