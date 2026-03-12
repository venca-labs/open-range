from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from open_range.cluster import ExecResult
from open_range.admit import LocalAdmissionController
from open_range.code_web import code_web_payload
from open_range.compiler import EnterpriseSaaSManifestCompiler
from open_range.render import EnterpriseSaaSKindRenderer
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
                {"predicate": "asset_read(finance_docs)"},
                {"predicate": "credential_obtained(idp_admin_cred)"},
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


def _build_seeded_world():
    world = EnterpriseSaaSManifestCompiler().compile(_manifest_payload())
    return CatalogWeaknessSeeder().apply(world)


def _synth(world, tmp_path: Path):
    return EnterpriseSaaSWorldSynthesizer().synthesize(world, tmp_path / "synth")


def _code_web_response(world, cmd: str, patched_services: set[str]) -> ExecResult | None:
    weakness = next((weak for weak in world.weaknesses if weak.family == "code_web"), None)
    if weakness is None or weakness.target in patched_services:
        return None
    payload = code_web_payload(world, weakness)
    path = str(payload.get("path", ""))
    if "http://svc-web:80" not in cmd or path not in cmd:
        return None
    return ExecResult(stdout=str(payload.get("expect_contains", "")), stderr="", exit_code=0)


def test_weakness_seeder_is_deterministic():
    world_a = _build_seeded_world()
    world_b = _build_seeded_world()

    assert world_a.weaknesses == world_b.weaknesses
    assert len(world_a.weaknesses) == 2
    assert any(weak.objective_tags for weak in world_a.weaknesses if weak.family == "code_web")


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

    assert Path(artifacts.values_path).exists()
    assert Path(artifacts.kind_config_path).exists()
    assert Path(artifacts.manifest_summary_path).exists()
    assert Path(synth.summary_path).exists()
    assert "svc-web" in artifacts.chart_values["services"]
    assert artifacts.chart_values["services"]["svc-web"]["enabled"] is True
    assert artifacts.chart_values["services"]["svc-web"]["payloads"][0]["mountPath"] == "/var/www/html/index.html"
    assert artifacts.chart_values["global"]["namePrefix"].startswith("enterprise-saas-v1-")
    assert "sandbox-red" in artifacts.chart_values["sandboxes"]
    assert artifacts.chart_values["services"]["svc-db"]["payloads"][0]["mountPath"] == "/docker-entrypoint-initdb.d/01-init.sql"
    assert artifacts.chart_values["services"]["svc-siem"]["command"][-1].endswith("busybox httpd -f -p 9200 -h /srv/http/siem")
    assert any(rule["fromZone"] == "external" and rule["toZone"] == "dmz" for rule in artifacts.chart_values["firewallRules"])
    assert artifacts.pinned_image_digests["svc-web"].startswith("php:8.1-apache@sha256:")


def test_admission_controller_admits_seeded_world(tmp_path: Path):
    world = _build_seeded_world()
    artifacts = EnterpriseSaaSKindRenderer().render(world, _synth(world, tmp_path), tmp_path / "rendered")

    witness_bundle, report = LocalAdmissionController(mode="fail_fast").admit(world, artifacts)

    assert report.admitted is True
    assert report.graph_ok is True
    assert report.red_witness_ok is True
    assert report.blue_signal_points == len({edge.source for edge in world.telemetry_edges})
    assert report.benchmark_tags_covered
    assert report.stages[-1].name == "determinism"
    objective_grounding = next(stage for stage in report.stages if stage.name == "static").checks[3]
    assert objective_grounding.name == "objective_grounding"
    assert objective_grounding.details["graders"]
    red_witness = next(stage for stage in report.stages if stage.name == "red_witness").checks[0]
    assert sorted(red_witness.details["satisfied_predicates"]) == sorted(
        objective.predicate for objective in world.red_objectives if objective.terminal
    )
    assert witness_bundle.red_witnesses
    assert witness_bundle.blue_witnesses


def test_admission_controller_offline_witness_can_ground_pinned_non_code_weakness(tmp_path: Path):
    payload = _manifest_payload()
    payload["security"]["allowed_weakness_families"] = ["secret_exposure"]
    payload["security"]["pinned_weaknesses"] = [
        {"family": "secret_exposure", "kind": "credential_in_share", "target": "asset:idp_admin_cred"},
    ]
    world = CatalogWeaknessSeeder().apply(EnterpriseSaaSManifestCompiler().compile(payload))
    artifacts = EnterpriseSaaSKindRenderer().render(world, _synth(world, tmp_path), tmp_path / "rendered-non-code")

    witness_bundle, report = LocalAdmissionController(mode="fail_fast").admit(world, artifacts)

    assert report.admitted is True
    assert report.red_witness_ok is True
    assert report.necessity_ok is True
    assert len(world.weaknesses) == 1
    assert world.weaknesses[0].family == "secret_exposure"
    assert any(
        step.payload.get("action") == "collect_secret" and step.payload.get("weakness_id") == world.weaknesses[0].id
        for step in witness_bundle.red_witnesses[0].steps
    )


def test_admission_controller_can_run_optional_live_backend(tmp_path: Path):
    world = _build_seeded_world()
    artifacts = EnterpriseSaaSKindRenderer().render(world, _synth(world, tmp_path), tmp_path / "rendered")
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
                present = any("InitialAccess" in line for line in self.logs)
                return ExecResult(stdout="", stderr="", exit_code=0 if present else 1)
            if service.startswith("sandbox-") and ("wget -qO- http://svc-siem:9200/all.log" in cmd):
                return ExecResult(stdout="\n".join(self.logs), stderr="", exit_code=0)
            if service == "sandbox-red":
                seeded = _code_web_response(world, cmd, self.web_guards)
                if seeded is not None:
                    return seeded
            if service == "sandbox-red" and any(target in cmd for target in ("svc-fileshare", "svc-db", "svc-idp")):
                return ExecResult(stdout="", stderr="blocked", exit_code=1)
            return ExecResult(stdout=f"{service}:{cmd}", stderr="", exit_code=0)

    class FakeBackend:
        def boot(self, *, snapshot_id: str, artifacts_dir: Path):
            calls.append(f"boot:{snapshot_id}:{artifacts_dir.name}")
            pod_ids = {service.id: f"ns/{service.id}-pod" for service in world.services}
            pod_ids["sandbox-red"] = "ns/sandbox-red-pod"
            pod_ids["sandbox-blue"] = "ns/sandbox-blue-pod"
            for persona in world.green_personas:
                pod_ids[f"sandbox-green-{persona.id.replace('_', '-').lower()}"] = f"ns/{persona.id}-pod"
            return SimpleNamespace(
                release_name=f"or-{snapshot_id}",
                artifacts_dir=artifacts_dir,
                pods=FakePods(pod_ids),
            )

        def teardown(self, release) -> None:
            calls.append(f"down:{release.release_name}")

    witness_bundle, report = LocalAdmissionController(
        mode="fail_fast",
        live_backend=FakeBackend(),
    ).admit(world, artifacts)

    assert witness_bundle.red_witnesses
    assert report.admitted is True
    assert any(stage.name == "kind_live" for stage in report.stages)
    assert calls[0].startswith("boot:")
    assert calls[-1].startswith("down:")


def test_admission_controller_rejects_world_without_telemetry(tmp_path: Path):
    world = _build_seeded_world()
    broken = world.replace_edges(telemetry=())
    artifacts = EnterpriseSaaSKindRenderer().render(broken, _synth(broken, tmp_path), tmp_path / "rendered")

    _bundle, report = LocalAdmissionController(mode="analysis").admit(broken, artifacts)

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
    leak_path = next(file for file in synth.generated_files if "/svc-web/" in file and file.endswith("index.html"))
    Path(leak_path).write_text(
        Path(leak_path).read_text(encoding="utf-8") + "\nseeded-sensitive-idp_admin_cred\n",
        encoding="utf-8",
    )
    artifacts = EnterpriseSaaSKindRenderer().render(world, synth, tmp_path / "rendered")

    _bundle, report = LocalAdmissionController(mode="analysis").admit(world, artifacts)

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
            weakened_services.append(service.model_copy(update={"telemetry_surfaces": ()}))
        else:
            weakened_services.append(service)
    broken = world.model_copy(update={"services": tuple(weakened_services)})
    artifacts = EnterpriseSaaSKindRenderer().render(broken, _synth(broken, tmp_path), tmp_path / "rendered")

    _bundle, report = LocalAdmissionController(mode="analysis").admit(broken, artifacts)

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
    witness_bundle, report = LocalAdmissionController(mode="fail_fast").admit(world, artifacts)
    store = FileSnapshotStore(tmp_path / "snapshots")

    snapshot = store.create(world, artifacts, witness_bundle, report, synth=synth)
    loaded = store.load(snapshot.snapshot_id)

    assert loaded.snapshot_id == snapshot.snapshot_id
    assert loaded.world_id == world.world_id
    assert loaded.seed == world.seed
    assert loaded.world.world_id == world.world_id
    assert loaded.validator_report.admitted is True
    assert Path(loaded.witness_bundle_path).exists()
    assert Path(loaded.validator_report_path).exists()
    assert "mailboxes" in loaded.identity_seed
