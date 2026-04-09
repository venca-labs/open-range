"""Thin build/admit pipeline for the standalone core."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict
import yaml

from open_range.admit import LocalAdmissionController
from open_range.build_config import BuildConfig, DEFAULT_BUILD_CONFIG
from open_range.cilium_policies import CiliumPolicyGenerator
from open_range.compiler import EnterpriseSaaSManifestCompiler
from open_range.k3d_renderer import K3dRenderer
from open_range.manifest import EnterpriseSaaSManifest, validate_manifest
from open_range.render import EnterpriseSaaSKindRenderer
from open_range.security_integrator import (
    SecurityContext,
    SecurityIntegrator,
    SecurityIntegratorConfig,
)
from open_range.snapshot import KindArtifacts, Snapshot
from open_range.store import FileSnapshotStore, PoolSplit
from open_range.synth import EnterpriseSaaSWorldSynthesizer, SynthArtifacts
from open_range.weaknesses import CatalogWeaknessSeeder
from open_range.world_ir import WorldIR


class CandidateWorld(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    world: WorldIR
    synth: SynthArtifacts
    artifacts: KindArtifacts
    build_config: BuildConfig = DEFAULT_BUILD_CONFIG


class BuildPipeline:
    """Compose compile -> seed -> render -> admit -> store."""

    def __init__(
        self,
        *,
        compiler: EnterpriseSaaSManifestCompiler | None = None,
        seeder: CatalogWeaknessSeeder | None = None,
        synthesizer: EnterpriseSaaSWorldSynthesizer | None = None,
        renderer: EnterpriseSaaSKindRenderer | None = None,
        security_integrator: SecurityIntegrator | None = None,
        admission: LocalAdmissionController | None = None,
        store: FileSnapshotStore | None = None,
    ) -> None:
        self.compiler = compiler or EnterpriseSaaSManifestCompiler()
        self.seeder = seeder or CatalogWeaknessSeeder()
        self.synthesizer = synthesizer or EnterpriseSaaSWorldSynthesizer()
        self.renderer = renderer or EnterpriseSaaSKindRenderer()
        self.security_integrator = security_integrator
        self.admission = admission or LocalAdmissionController(mode="fail_fast")
        self.store = store or FileSnapshotStore()

    def build(
        self,
        source: dict[str, Any] | EnterpriseSaaSManifest | WorldIR,
        outdir: str | Path,
        build_config: BuildConfig = DEFAULT_BUILD_CONFIG,
    ) -> CandidateWorld:
        world = self._prepare_world(source, build_config)
        synth = self.synthesizer.synthesize(world, Path(outdir) / "synth")
        artifacts = self._renderer_for(build_config).render(world, synth, Path(outdir))
        artifacts = self._integrate_security(world, artifacts, build_config)
        artifacts = self._integrate_network_policies(artifacts, build_config)
        return CandidateWorld(
            world=world, synth=synth, artifacts=artifacts, build_config=build_config
        )

    def admit(
        self, candidate: CandidateWorld, *, split: PoolSplit = "train"
    ) -> Snapshot:
        reference_bundle, report = self.admission.admit(
            candidate.world,
            candidate.artifacts,
            candidate.build_config,
        )
        if not report.admitted:
            raise ValueError(
                f"candidate world {candidate.world.world_id} was not admitted"
            )
        return self.store.create(
            candidate.world,
            candidate.artifacts,
            reference_bundle,
            report,
            split=split,
            synth=candidate.synth,
        )

    def admit_child(
        self,
        world: WorldIR,
        outdir: str | Path,
        *,
        split: PoolSplit = "train",
        build_config: BuildConfig = DEFAULT_BUILD_CONFIG,
    ) -> Snapshot:
        return self.admit(self.build(world, outdir, build_config), split=split)

    def _prepare_world(
        self,
        source: dict[str, Any] | EnterpriseSaaSManifest | WorldIR,
        build_config: BuildConfig,
    ) -> WorldIR:
        if isinstance(source, WorldIR):
            return source if source.weaknesses else self.seeder.apply(source)
        parsed = (
            source
            if isinstance(source, EnterpriseSaaSManifest)
            else validate_manifest(source)
        )
        world = self.compiler.compile(parsed, build_config)
        return self.seeder.apply(world)

    def _renderer_for(self, build_config: BuildConfig) -> EnterpriseSaaSKindRenderer:
        if self.renderer is not None and not isinstance(
            self.renderer, EnterpriseSaaSKindRenderer
        ):
            return self.renderer
        if build_config.cluster_backend == "k3d":
            return K3dRenderer(
                agents=build_config.k3d_agents,
                subnet=build_config.k3d_subnet,
            )
        return self.renderer

    def _integrate_security(
        self,
        world: WorldIR,
        artifacts: KindArtifacts,
        build_config: BuildConfig,
    ) -> KindArtifacts:
        if not build_config.security_enabled:
            return artifacts
        integrator = self.security_integrator or SecurityIntegrator(
            SecurityIntegratorConfig(enabled=True)
        )
        context = integrator.integrate(
            world,
            render_dir=Path(artifacts.render_dir),
            tier=build_config.security_tier,
        )
        if not context.generated_files:
            return artifacts
        chart_values = dict(artifacts.chart_values)
        chart_values["services"] = self._integrate_security_payloads(
            world,
            chart_values.get("services", {}),
            Path(artifacts.render_dir),
            context,
        )
        chart_values["security"] = context.model_dump(mode="json")
        return self._sync_artifacts(
            artifacts,
            chart_values=chart_values,
            rendered_files=context.generated_files,
            summary_updates={
                "security_tier": build_config.security_tier,
                "security_integration_enabled": True,
            },
        )

    def _integrate_security_payloads(
        self,
        world: WorldIR,
        services: dict[str, Any],
        render_dir: Path,
        context: SecurityContext,
    ) -> dict[str, Any]:
        next_services = {name: dict(spec) for name, spec in services.items()}
        security_dir = render_dir / "security"

        idp_targets = [
            service.id for service in world.services if service.kind == "idp"
        ]
        if context.identity_provider and idp_targets:
            self._append_payloads(
                next_services,
                idp_targets[0],
                [
                    self._payload_entry(
                        security_dir / "idp" / "config.json",
                        "security-idp-config.json",
                        "/etc/openrange/identity-provider.json",
                    ),
                    self._payload_entry(
                        security_dir / "idp" / "startup.sh",
                        "security-idp-startup.sh",
                        "/opt/openrange/start_identity_provider.sh",
                    ),
                    self._payload_entry(
                        security_dir / "idp" / "identity_provider_server.py",
                        "security-idp-server.py",
                        "/opt/openrange/identity_provider_server.py",
                    ),
                ],
            )
            self._append_port(
                next_services,
                idp_targets[0],
                {
                    "name": "idp-token",
                    "port": int(
                        context.identity_provider.get("token_endpoint_port", 8443)
                    ),
                },
            )

        if context.encryption:
            encryption_payloads = [
                self._payload_entry(
                    security_dir / "encryption" / "config.json",
                    "security-encryption-config.json",
                    "/etc/openrange/encryption-config.json",
                ),
                self._payload_entry(
                    security_dir / "encryption" / "wrapped_dek.json",
                    "security-wrapped-dek.json",
                    "/etc/openrange/wrapped_dek.json",
                ),
            ]
            for service_id in next_services:
                self._append_payloads(next_services, service_id, encryption_payloads)

        mtls_services = context.mtls.get("mtls_services", [])
        for service_id in mtls_services:
            if service_id not in next_services:
                continue
            self._append_payloads(
                next_services,
                service_id,
                [
                    self._payload_entry(
                        security_dir / "mtls" / service_id / "ca.pem",
                        "security-mtls-ca.pem",
                        "/etc/mtls/ca.pem",
                    ),
                    self._payload_entry(
                        security_dir / "mtls" / service_id / "cert.pem",
                        "security-mtls-cert.pem",
                        "/etc/mtls/cert.pem",
                    ),
                    self._payload_entry(
                        security_dir / "mtls" / service_id / "key.pem",
                        "security-mtls-key.pem",
                        "/etc/mtls/key.pem",
                    ),
                ],
            )

        if context.identity_provider and idp_targets:
            self._set_sidecars(
                next_services,
                idp_targets[0],
                [
                    {
                        "name": "idp-helper",
                        "image": next_services[idp_targets[0]].get("image"),
                        "command": [
                            "/bin/sh",
                            "/opt/openrange/start_identity_provider.sh",
                        ],
                        "payloads": list(
                            next_services[idp_targets[0]].get("payloads", [])
                        ),
                    }
                ],
            )

        return next_services

    @staticmethod
    def _append_payloads(
        services: dict[str, Any], service_id: str, payloads: list[dict[str, str] | None]
    ) -> None:
        service = services.get(service_id)
        if not isinstance(service, dict):
            return
        existing = list(service.get("payloads", []))
        for payload in payloads:
            if payload is None:
                continue
            existing.append(payload)
        service["payloads"] = existing

    @staticmethod
    def _append_port(
        services: dict[str, Any], service_id: str, port: dict[str, Any]
    ) -> None:
        service = services.get(service_id)
        if not isinstance(service, dict):
            return
        existing = list(service.get("ports", []))
        if any(item.get("port") == port["port"] for item in existing):
            return
        existing.append(port)
        service["ports"] = existing

    @staticmethod
    def _set_sidecars(
        services: dict[str, Any], service_id: str, sidecars: list[dict[str, Any]]
    ) -> None:
        service = services.get(service_id)
        if not isinstance(service, dict):
            return
        service["sidecars"] = sidecars

    @staticmethod
    def _payload_entry(
        source_path: Path, key: str, mount_path: str
    ) -> dict[str, str] | None:
        if not source_path.exists():
            return None
        return {
            "key": key,
            "mountPath": mount_path,
            "content": source_path.read_text(encoding="utf-8"),
        }

    def _integrate_network_policies(
        self,
        artifacts: KindArtifacts,
        build_config: BuildConfig,
    ) -> KindArtifacts:
        if build_config.network_policy_backend != "cilium":
            return artifacts
        chart_values = dict(artifacts.chart_values)
        generator = CiliumPolicyGenerator(
            name_prefix=chart_values["global"]["namePrefix"]
        )
        policies = generator.generate_zone_policies(
            chart_values["zones"],
            chart_values["firewallRules"],
        )
        cilium_path = Path(artifacts.chart_dir) / "templates" / "cilium-policies.yaml"
        cilium_path.write_text(
            yaml.safe_dump_all(policies, sort_keys=False),
            encoding="utf-8",
        )
        chart_values["cilium"] = {
            "enabled": True,
            "policyCount": len(policies),
        }
        return self._sync_artifacts(
            artifacts,
            chart_values=chart_values,
            rendered_files=[str(cilium_path)],
            summary_updates={
                "network_policy_backend": build_config.network_policy_backend,
            },
        )

    def _sync_artifacts(
        self,
        artifacts: KindArtifacts,
        *,
        chart_values: dict[str, Any],
        rendered_files: list[str] | tuple[str, ...] = (),
        summary_updates: dict[str, Any] | None = None,
    ) -> KindArtifacts:
        values_path = Path(artifacts.values_path)
        values_path.write_text(
            yaml.safe_dump(chart_values, sort_keys=False),
            encoding="utf-8",
        )

        summary_path = Path(artifacts.manifest_summary_path)
        summary = json.loads(summary_path.read_text(encoding="utf-8"))
        summary["values_hash"] = hashlib.sha256(
            json.dumps(chart_values, sort_keys=True, separators=(",", ":")).encode(
                "utf-8"
            )
        ).hexdigest()
        if summary_updates:
            summary.update(summary_updates)
        summary_path.write_text(
            json.dumps(summary, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

        next_files = tuple(dict.fromkeys((*artifacts.rendered_files, *rendered_files)))
        return artifacts.model_copy(
            update={
                "rendered_files": next_files,
                "chart_values": chart_values,
            }
        )


def build(
    source: dict[str, Any] | EnterpriseSaaSManifest | WorldIR,
    outdir: str | Path,
    build_config: BuildConfig = DEFAULT_BUILD_CONFIG,
) -> CandidateWorld:
    """Build a candidate world from a public manifest or mutated WorldIR."""
    return BuildPipeline().build(source, outdir, build_config)


def admit(candidate: CandidateWorld, *, split: PoolSplit = "train") -> Snapshot:
    """Admit a built candidate and persist it as an immutable snapshot."""
    return BuildPipeline().admit(candidate, split=split)


def admit_child(
    world: WorldIR,
    outdir: str | Path,
    *,
    split: PoolSplit = "train",
    build_config: BuildConfig = DEFAULT_BUILD_CONFIG,
) -> Snapshot:
    """Render, admit, and persist a mutated child world."""
    return BuildPipeline().admit_child(
        world, outdir, split=split, build_config=build_config
    )
