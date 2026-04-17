"""Deterministic admission controller."""

from __future__ import annotations

import subprocess

from open_range.admission.checks import BUILTIN_ADMISSION_CHECKS
from open_range.admission.live import run_live_backend_checks
from open_range.admission.models import (
    ReferenceBundle,
    ValidatorCheckReport,
    ValidatorReport,
    ValidatorStageReport,
)
from open_range.admission.plan import admission_stages, profile_requires_live
from open_range.admission.references import build_reference_bundle
from open_range.admission.scoring import report_summary
from open_range.config import DEFAULT_BUILD_CONFIG, BuildConfig
from open_range.contracts.snapshot import KindArtifacts, world_hash
from open_range.contracts.world import WorldIR
from open_range.render.live import KindBackend, LiveBackend, resolve_host_binary
from open_range.render.live_k3d import K3dBackend

_CHECKS_BY_NAME = {spec.name: spec.fn for spec in BUILTIN_ADMISSION_CHECKS}


class LocalAdmissionController:
    """Run deterministic admission in fail-fast or analysis mode."""

    def __init__(
        self,
        mode: str = "fail_fast",
        *,
        live_backend: LiveBackend | None = None,
        auto_live: bool = True,
    ) -> None:
        if mode not in {"fail_fast", "analysis"}:
            raise ValueError("mode must be 'fail_fast' or 'analysis'")
        self.mode = mode
        self.live_backend = live_backend
        self.auto_live = auto_live

    def admit(
        self,
        world: WorldIR,
        artifacts: KindArtifacts,
        build_config: BuildConfig = DEFAULT_BUILD_CONFIG,
    ) -> tuple[ReferenceBundle, ValidatorReport]:
        reference_bundle: ReferenceBundle | None = None
        stages: list[ValidatorStageReport] = []
        continue_running = True
        health_info: dict[str, object] = {"render_dir": artifacts.render_dir}
        live_backend = self.live_backend or self._auto_live_backend(build_config)
        health_info["live_backend_mode"] = (
            "explicit"
            if self.live_backend is not None
            else ("auto" if live_backend is not None else "unavailable")
        )

        for stage in admission_stages(build_config):
            checks: list[ValidatorCheckReport] = []
            for check_name in stage.check_names:
                if not continue_running:
                    break
                if reference_bundle is None and stage.requires_references:
                    reference_bundle = build_reference_bundle(world, build_config)
                result = _CHECKS_BY_NAME[check_name](
                    world,
                    artifacts,
                    reference_bundle,
                )
                checks.append(result)
                if (
                    self.mode == "fail_fast"
                    and not result.passed
                    and not result.advisory
                ):
                    continue_running = False
            stage_passed = all(result.passed or result.advisory for result in checks)
            stages.append(
                ValidatorStageReport(
                    name=stage.name,
                    passed=stage_passed,
                    checks=tuple(checks),
                )
            )
            if self.mode == "fail_fast" and not stage_passed:
                break

        if reference_bundle is None:
            reference_bundle = build_reference_bundle(world, build_config)

        if continue_running and live_backend is not None:
            live_stage, live_info = run_live_backend_checks(
                world,
                artifacts,
                reference_bundle,
                live_backend,
                build_config=build_config,
            )
            stages.append(live_stage)
            health_info.update(live_info)
        elif live_backend is None and profile_requires_live(build_config):
            stages.append(
                ValidatorStageReport(
                    name="kind_live",
                    passed=False,
                    checks=(
                        ValidatorCheckReport(
                            name="live_backend_required",
                            passed=False,
                            details={
                                "validation_profile": build_config.validation_profile,
                                "live_backend_mode": health_info["live_backend_mode"],
                            },
                            error="live Kind validation is required for this admission profile",
                        ),
                    ),
                )
            )

        admitted = all(stage.passed for stage in stages)
        summary_fields = report_summary(
            world=world,
            stages=tuple(stages),
            reference_bundle=reference_bundle,
            health_info=health_info,
        )
        report = ValidatorReport(
            admitted=admitted,
            **summary_fields,
            mode=self.mode,
            world_id=world.world_id,
            world_hash=world_hash(world),
            summary="admitted" if admitted else "rejected",
            build_logs=tuple(artifacts.rendered_files),
            health_info=health_info,
            stages=tuple(stages),
        )
        return reference_bundle, report

    def _auto_live_backend(self, build_config: BuildConfig) -> LiveBackend | None:
        if not self.auto_live:
            return None
        if not profile_requires_live(build_config):
            return None
        if not resolve_host_binary("helm"):
            return None
        if build_config.cluster_backend == "k3d":
            k3d = resolve_host_binary("k3d")
            docker = resolve_host_binary("docker")
            if not (k3d and docker):
                return None
            clusters = subprocess.run(
                [k3d, "cluster", "list", "-o", "json"],
                capture_output=True,
                text=True,
                check=False,
            )
            if clusters.returncode != 0 or '"name":"openrange"' not in clusters.stdout:
                return None
            return K3dBackend(
                kind_cluster="openrange",
                k3d_agents=build_config.k3d_agents,
                k3d_subnet=build_config.k3d_subnet,
            )
        kind = resolve_host_binary("kind")
        docker = resolve_host_binary("docker")
        if not (kind and docker):
            return None
        clusters = subprocess.run(
            [kind, "get", "clusters"],
            capture_output=True,
            text=True,
            check=False,
        )
        if clusters.returncode != 0:
            return None
        if "openrange" not in {
            line.strip() for line in clusters.stdout.splitlines() if line.strip()
        }:
            return None
        return KindBackend()
