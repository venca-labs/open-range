from __future__ import annotations

from pathlib import Path
import shutil
import subprocess

from open_range._runtime_store import hydrate_runtime_snapshot
import pytest

from open_range.build_config import BuildConfig
from open_range.compiler import EnterpriseSaaSManifestCompiler
from open_range.episode_config import EpisodeConfig
from open_range.manifest import validate_manifest
from open_range.pipeline import BuildPipeline
from open_range.render import EnterpriseSaaSKindRenderer
from open_range.runtime_extensions import (
    RenderExtensions,
    RuntimePayload,
    RuntimePort,
    RuntimeSidecar,
    ServiceRuntimeExtension,
)
from open_range.store import FileSnapshotStore
from open_range.synth import EnterpriseSaaSWorldSynthesizer
from open_range.weaknesses import CatalogWeaknessSeeder
from open_range.world_ir import WorldIR
from tests.support import manifest_payload


def _manifest_payload() -> dict:
    payload = manifest_payload()
    payload["security"]["code_flaw_kinds"] = ["sql_injection", "path_traversal"]
    payload["mutation_bounds"]["allow_patch_old_weaknesses"] = True
    return payload


def test_episode_config_control_flags():
    assert EpisodeConfig(mode="red_only").controls_red is True
    assert EpisodeConfig(mode="red_only").controls_blue is False
    assert EpisodeConfig(mode="blue_only_live").controls_red is False
    assert EpisodeConfig(mode="blue_only_live").controls_blue is True
    assert EpisodeConfig().reward_profile == "terminal_plus_shaping"
    assert EpisodeConfig().prompt_mode == "zero_day"


def test_build_config_threads_through_build_and_admission(tmp_path: Path):
    store = FileSnapshotStore(tmp_path / "snapshots")
    pipeline = BuildPipeline(store=store)
    build_config = BuildConfig(
        workflows_enabled=("helpdesk_ticketing",),
        weakness_families_enabled=("code_web",),
        topology_scale="small",
        validation_profile="graph_only",
        red_reference_count=2,
        blue_reference_count=2,
    )

    candidate = pipeline.build(_manifest_payload(), tmp_path / "rendered", build_config)
    snapshot = pipeline.admit(candidate, split="train")
    runtime_snapshot = hydrate_runtime_snapshot(store, snapshot)

    assert candidate.build_config == build_config
    assert candidate.world.allowed_service_kinds == (
        "web_app",
        "email",
        "idp",
        "fileshare",
        "db",
        "siem",
    )
    assert len(candidate.world.workflows) == 1
    assert len(candidate.world.users) == 4
    assert all(weak.family == "code_web" for weak in candidate.world.weaknesses)
    assert 1 <= len(runtime_snapshot.reference_bundle.reference_attack_traces) <= 2
    assert 1 <= len(runtime_snapshot.reference_bundle.reference_defense_traces) <= 2


def test_build_config_can_filter_services_without_touching_manifest_schema(
    tmp_path: Path,
):
    pipeline = BuildPipeline(store=FileSnapshotStore(tmp_path / "snapshots"))
    candidate = pipeline.build(
        _manifest_payload(),
        tmp_path / "rendered-filtered",
        BuildConfig(
            services_enabled=("web_app", "idp", "siem"), validation_profile="graph_only"
        ),
    )

    assert candidate.world.allowed_service_kinds == ("web_app", "idp", "siem")
    assert candidate.world.security_runtime.tier == 1


def test_build_config_can_enable_security_integration(tmp_path: Path):
    pipeline = BuildPipeline(store=FileSnapshotStore(tmp_path / "snapshots"))
    build_config = BuildConfig(
        validation_profile="graph_only",
        security_integration_enabled=True,
        security_tier=3,
    )

    candidate = pipeline.build(
        _manifest_payload(),
        tmp_path / "rendered-security",
        build_config,
    )

    assert candidate.build_config == build_config
    assert candidate.world.security_runtime.tier == 3
    idp_payload_spec = candidate.world.security_runtime.service_runtime[
        "svc-idp"
    ].payloads[0]
    assert idp_payload_spec.source_path.startswith("security/idp/")
    assert "content" not in idp_payload_spec.model_dump(by_alias=True)
    assert candidate.artifacts.chart_values["security"]["tier"] == 3
    assert any(
        path.endswith("security/security-context.json")
        for path in candidate.artifacts.rendered_files
    )
    idp_service = candidate.artifacts.chart_values["services"]["svc-idp"]
    idp_env = idp_service["env"]
    idp_payloads = idp_service["payloads"]
    db_service = candidate.artifacts.chart_values["services"]["svc-db"]
    db_payloads = db_service["payloads"]
    idp_sidecar = idp_service["sidecars"][0]

    assert any(
        payload["mountPath"] == "/opt/openrange/identity_provider_server.py"
        for payload in idp_payloads
    )
    assert idp_service["command"] == ["/container/tool/run", "--copy-service"]
    assert idp_sidecar["name"] == "idp-helper"
    assert idp_sidecar["command"] == [
        "/bin/sh",
        "/opt/openrange/start_identity_provider.sh",
    ]
    assert idp_sidecar["image"] == idp_service["image"]
    assert "inherit_image_from_service" not in idp_sidecar
    assert "inherit_payloads_from_service" not in idp_sidecar
    assert any(
        payload["mountPath"] == "/opt/openrange/start_identity_provider.sh"
        for payload in idp_sidecar["payloads"]
    )
    assert any(port["port"] == 8443 for port in idp_service["ports"])
    assert any(port["port"] == 636 for port in idp_service["ports"])
    assert idp_env["LDAP_TLS_CRT_FILENAME"] == "ldap.crt"
    assert idp_env["LDAP_TLS_CA_CRT_FILENAME"] == "ca.crt"
    assert idp_env["LDAP_TLS_VERIFY_CLIENT"] == "demand"
    assert any(
        payload["mountPath"] == "/container/service/slapd/assets/certs/ldap.crt"
        for payload in idp_payloads
    )
    assert any(
        payload["mountPath"] == "/etc/openrange/wrapped_dek.json"
        for payload in db_payloads
    )
    assert any(payload["mountPath"] == "/etc/mtls/cert.pem" for payload in db_payloads)
    assert any(
        payload["mountPath"] == "/etc/mysql/conf.d/openrange-mtls.cnf"
        for payload in db_payloads
    )
    mysql_tls_config = next(
        payload["content"]
        for payload in db_service["payloads"]
        if payload["mountPath"] == "/etc/mysql/conf.d/openrange-mtls.cnf"
    )
    assert "require_secure_transport=ON" in mysql_tls_config
    assert "ssl-cert=/etc/mtls/cert.pem" in mysql_tls_config


def test_security_integration_renders_idp_runtime_hooks_with_helm(tmp_path: Path):
    if shutil.which("helm") is None:
        pytest.skip("helm is required for chart rendering checks")

    pipeline = BuildPipeline(store=FileSnapshotStore(tmp_path / "snapshots"))
    candidate = pipeline.build(
        _manifest_payload(),
        tmp_path / "rendered-security-template",
        BuildConfig(
            validation_profile="graph_only",
            security_integration_enabled=True,
            security_tier=3,
        ),
    )

    rendered = subprocess.run(
        [
            "helm",
            "template",
            "or-demo",
            candidate.artifacts.chart_dir,
            "--values",
            candidate.artifacts.values_path,
        ],
        capture_output=True,
        text=True,
        check=True,
    ).stdout

    assert "containerPort: 8443" in rendered
    assert "/opt/openrange/start_identity_provider.sh" in rendered
    assert "name: idp-helper" in rendered


def test_security_runtime_round_trips_through_world_ir_json(tmp_path: Path):
    pipeline = BuildPipeline(store=FileSnapshotStore(tmp_path / "snapshots"))
    candidate = pipeline.build(
        _manifest_payload(),
        tmp_path / "rendered-security-roundtrip",
        BuildConfig(
            validation_profile="graph_only",
            security_integration_enabled=True,
            security_tier=3,
        ),
    )

    round_tripped = WorldIR.model_validate_json(candidate.world.model_dump_json())

    assert round_tripped.security_runtime.tier == 3
    payload = round_tripped.security_runtime.service_runtime["svc-idp"].payloads[0]
    assert payload.key
    assert payload.source_path.startswith("security/idp/")
    assert "content" not in payload.model_dump(by_alias=True)


def test_security_runtime_materialization_is_deterministic(tmp_path: Path):
    pipeline = BuildPipeline(store=FileSnapshotStore(tmp_path / "snapshots"))
    candidate = pipeline.build(
        _manifest_payload(),
        tmp_path / "rendered-security-deterministic",
        BuildConfig(
            validation_profile="graph_only",
            security_integration_enabled=True,
            security_tier=3,
        ),
    )

    renderer = EnterpriseSaaSKindRenderer()
    renderer.render(candidate.world, candidate.synth, tmp_path / "render-a")
    renderer.render(candidate.world, candidate.synth, tmp_path / "render-b")

    for relative_path in (
        "security/encryption/wrapped_dek.json",
        "security/mtls/svc-db/key.pem",
        "security/security-context.json",
    ):
        assert (tmp_path / "render-a" / relative_path).read_text(encoding="utf-8") == (
            tmp_path / "render-b" / relative_path
        ).read_text(encoding="utf-8")


def test_security_runtime_mtls_cert_window_stays_long_lived(tmp_path: Path):
    cryptography = pytest.importorskip("cryptography.x509")

    pipeline = BuildPipeline(store=FileSnapshotStore(tmp_path / "snapshots"))
    pipeline.build(
        _manifest_payload(),
        tmp_path / "rendered-security-window",
        BuildConfig(
            validation_profile="graph_only",
            security_integration_enabled=True,
            security_tier=3,
        ),
    )

    ca_cert = cryptography.load_pem_x509_certificate(
        (
            tmp_path
            / "rendered-security-window"
            / "security"
            / "mtls"
            / "svc-db"
            / "ca.pem"
        ).read_bytes()
    )
    svc_cert = cryptography.load_pem_x509_certificate(
        (
            tmp_path
            / "rendered-security-window"
            / "security"
            / "mtls"
            / "svc-db"
            / "cert.pem"
        ).read_bytes()
    )

    assert ca_cert.not_valid_after_utc.year >= 2033
    assert svc_cert.not_valid_after_utc.year >= 2033


def test_renderer_applies_runtime_extensions_during_render(tmp_path: Path):
    manifest = validate_manifest(_manifest_payload())
    build_config = BuildConfig(validation_profile="graph_only")
    world = CatalogWeaknessSeeder().apply(
        EnterpriseSaaSManifestCompiler().compile(manifest, build_config)
    )
    synth = EnterpriseSaaSWorldSynthesizer().synthesize(world, tmp_path / "synth")
    extensions = RenderExtensions(
        services={
            "svc-idp": ServiceRuntimeExtension(
                payloads=[
                    RuntimePayload(
                        key="runtime-helper.sh",
                        mountPath="/opt/openrange/runtime-helper.sh",
                        content="#!/bin/sh\nexit 0\n",
                    )
                ],
                ports=[RuntimePort(name="runtime-helper", port=8443)],
                sidecars=[
                    RuntimeSidecar(
                        name="runtime-helper",
                        image_source="service",
                        include_service_payloads=True,
                        command=("/bin/sh", "/opt/openrange/runtime-helper.sh"),
                    )
                ],
            )
        },
        values={"security": {"tier": 3}},
        summary_updates={"security_tier": 3},
        rendered_files=(str(tmp_path / "security-context.json"),),
    )

    artifacts = EnterpriseSaaSKindRenderer().render(
        world,
        synth,
        tmp_path / "rendered-with-extensions",
        extensions=extensions,
    )

    idp_service = artifacts.chart_values["services"]["svc-idp"]
    sidecar = idp_service["sidecars"][0]

    assert artifacts.chart_values["security"]["tier"] == 3
    assert any(
        payload["mountPath"] == "/opt/openrange/runtime-helper.sh"
        for payload in idp_service["payloads"]
    )
    assert any(port["port"] == 8443 for port in idp_service["ports"])
    assert sidecar["image"] == idp_service["image"]
    assert any(
        payload["mountPath"] == "/opt/openrange/runtime-helper.sh"
        for payload in sidecar["payloads"]
    )
    assert str(tmp_path / "security-context.json") in artifacts.rendered_files


def test_build_config_can_select_k3d_and_cilium_outputs(tmp_path: Path):
    pipeline = BuildPipeline(store=FileSnapshotStore(tmp_path / "snapshots"))
    candidate = pipeline.build(
        _manifest_payload(),
        tmp_path / "rendered-k3d",
        BuildConfig(
            validation_profile="graph_only",
            cluster_backend="k3d",
            network_policy_backend="cilium",
        ),
    )

    assert Path(candidate.artifacts.kind_config_path).name == "k3d-config.yaml"
    assert candidate.artifacts.chart_values["cilium"]["enabled"] is True
    assert (
        Path(candidate.artifacts.chart_dir) / "templates" / "cilium-policies.yaml"
    ).exists()


def test_build_pipeline_threads_manifest_npc_profiles_into_personas(tmp_path: Path):
    pipeline = BuildPipeline(store=FileSnapshotStore(tmp_path / "snapshots"))
    payload = _manifest_payload()
    payload["npc_profiles"] = {
        "sales": {
            "awareness": 0.15,
            "susceptibility": {"phishing": 0.85, "pretexting": 0.55},
            "routine": ["check_mail", "browse_app"],
        }
    }

    candidate = pipeline.build(
        payload,
        tmp_path / "rendered-npc-profiles",
        BuildConfig(validation_profile="graph_only"),
    )

    sales_personas = [
        persona for persona in candidate.world.green_personas if persona.role == "sales"
    ]

    assert sales_personas
    assert all(persona.awareness == 0.15 for persona in sales_personas)
    assert all(
        persona.susceptibility == {"phishing": 0.85, "pretexting": 0.55}
        for persona in sales_personas
    )
    assert all(
        persona.routine == ("check_mail", "browse_app") for persona in sales_personas
    )


def test_manifest_accepts_standard_attack_objectives_and_rejects_unknown_predicates() -> (
    None
):
    payload = _manifest_payload()
    payload["objectives"]["red"] = [
        {"predicate": "db_access(payroll_db)"},
        {"predicate": "privilege_escalation(idp_admin_cred)"},
    ]
    manifest = validate_manifest(payload)

    assert manifest.objectives.red[0].predicate == "db_access(payroll_db)"
    assert (
        manifest.objectives.red[1].predicate == "privilege_escalation(idp_admin_cred)"
    )

    payload["objectives"]["red"] = [{"predicate": "made_up_objective(finance_docs)"}]
    with pytest.raises(Exception) as exc:
        validate_manifest(payload)
    assert "unsupported objective predicate" in str(exc.value)
