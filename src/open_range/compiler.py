"""Deterministic manifest compiler for the fixed `enterprise_saas_v1` family."""

from __future__ import annotations

from typing import Protocol

from open_range.build_config import BuildConfig, DEFAULT_BUILD_CONFIG
from open_range.manifest import (
    EnterpriseSaaSManifest,
    ManifestAsset,
    NPCProfileSpec,
    validate_manifest,
)
from open_range.objectives import objective_tags_for_predicate
from open_range.predicate_expr import predicate_inner
from open_range.world_ir import (
    AssetSpec,
    CredentialSpec,
    EdgeSpec,
    GreenPersona,
    GreenWorkloadSpec,
    GroupSpec,
    HostSpec,
    LineageSpec,
    MutationBoundsSpec,
    ObjectiveSpec,
    ServiceSpec,
    UserSpec,
    WorkflowSpec,
    WorkflowStepSpec,
    WorldIR,
)


class ManifestCompiler(Protocol):
    def compile(
        self,
        manifest: dict | EnterpriseSaaSManifest,
        build_config: BuildConfig = DEFAULT_BUILD_CONFIG,
    ) -> WorldIR: ...


class EnterpriseSaaSManifestCompiler:
    """Compile the strict manifest into a hand-checkable WorldIR."""

    _SERVICE_LAYOUT = {
        "web_app": {
            "host_id": "web-1",
            "service_id": "svc-web",
            "zone": "dmz",
            "exposure": "public",
            "ports": (80, 443),
            "dependencies": ("svc-db", "svc-idp", "svc-fileshare"),
            "telemetry": ("web_access", "web_error"),
        },
        "email": {
            "host_id": "mail-1",
            "service_id": "svc-email",
            "zone": "dmz",
            "exposure": "public",
            "ports": (25, 587, 993),
            "dependencies": ("svc-idp",),
            "telemetry": ("smtp", "imap"),
        },
        "idp": {
            "host_id": "idp-1",
            "service_id": "svc-idp",
            "zone": "management",
            "exposure": "management",
            "ports": (389,),
            "dependencies": (),
            "telemetry": ("auth", "audit"),
        },
        "fileshare": {
            "host_id": "files-1",
            "service_id": "svc-fileshare",
            "zone": "corp",
            "exposure": "corp",
            "ports": (445,),
            "dependencies": ("svc-idp",),
            "telemetry": ("share_access",),
        },
        "db": {
            "host_id": "db-1",
            "service_id": "svc-db",
            "zone": "data",
            "exposure": "data",
            "ports": (3306,),
            "dependencies": (),
            "telemetry": ("query", "slow_query"),
        },
        "siem": {
            "host_id": "siem-1",
            "service_id": "svc-siem",
            "zone": "management",
            "exposure": "management",
            "ports": (514, 9200, 9201),
            "dependencies": (),
            "telemetry": ("ingest", "alert"),
        },
    }

    _ROLE_HOME_SERVICE = {
        "sales": "svc-web",
        "engineer": "svc-web",
        "finance": "svc-fileshare",
        "it_admin": "svc-idp",
    }

    def compile(
        self,
        manifest: dict | EnterpriseSaaSManifest,
        build_config: BuildConfig = DEFAULT_BUILD_CONFIG,
    ) -> WorldIR:
        parsed = (
            manifest
            if isinstance(manifest, EnterpriseSaaSManifest)
            else validate_manifest(manifest)
        )
        if build_config.world_family != parsed.world_family:
            raise ValueError(
                f"build_config.world_family={build_config.world_family!r} does not match manifest world_family={parsed.world_family!r}"
            )
        self._validate_npc_profiles(parsed)
        service_names = self._selected_services(parsed, build_config)
        workflow_names = self._selected_workflows(parsed, build_config)
        allowed_families = self._selected_weakness_families(parsed, build_config)
        allowed_code_flaw_kinds = self._selected_code_flaw_kinds(parsed, build_config)
        allowed_surfaces = set(build_config.observability_surfaces_enabled)

        hosts = []
        services = []
        edges = []

        for service_name in service_names:
            if service_name not in self._SERVICE_LAYOUT:
                raise ValueError(
                    f"unsupported enterprise_saas_v1 service: {service_name}"
                )
            layout = self._SERVICE_LAYOUT[service_name]
            zone = self._resolve_zone(parsed.topology.zones, layout["zone"])
            telemetry = layout["telemetry"]
            if allowed_surfaces:
                telemetry = tuple(
                    surface for surface in telemetry if surface in allowed_surfaces
                )
            hosts.append(
                HostSpec(
                    id=layout["host_id"],
                    zone=zone,
                    exposure=layout["exposure"],
                    services=(layout["service_id"],),
                )
            )
            services.append(
                ServiceSpec(
                    id=layout["service_id"],
                    kind=service_name,
                    host=layout["host_id"],
                    ports=layout["ports"],
                    dependencies=layout["dependencies"],
                    telemetry_surfaces=telemetry,
                )
            )
            for dep in layout["dependencies"]:
                edges.append(
                    EdgeSpec(
                        id=f"net-{layout['service_id']}-to-{dep}",
                        kind="network",
                        source=layout["service_id"],
                        target=dep,
                        label="service_dependency",
                    )
                )
                edges.append(
                    EdgeSpec(
                        id=f"trust-{layout['service_id']}-to-{dep}",
                        kind="trust",
                        source=layout["service_id"],
                        target=dep,
                        label="service_trust",
                    )
                )
            if service_name != "siem" and (not allowed_surfaces or telemetry):
                edges.append(
                    EdgeSpec(
                        id=f"telemetry-{layout['service_id']}-to-siem",
                        kind="telemetry",
                        source=layout["service_id"],
                        target="svc-siem",
                        label="log_ship",
                    )
                )

        users, groups, credentials, personas = self._expand_users(parsed, build_config)
        workflows, workflow_edges = self._compile_workflows(parsed, workflow_names)
        assets = tuple(self._place_asset(asset) for asset in parsed.assets)

        red_objectives = tuple(
            self._compile_objective(
                owner="red",
                index=idx,
                predicate=obj.predicate,
                assets=assets,
            )
            for idx, obj in enumerate(parsed.objectives.red, start=1)
        )
        blue_objectives = tuple(
            self._compile_objective(
                owner="blue",
                index=idx,
                predicate=obj.predicate,
                assets=assets,
            )
            for idx, obj in enumerate(parsed.objectives.blue, start=1)
        )

        return WorldIR(
            world_id=f"{parsed.world_family}-{parsed.seed}",
            seed=parsed.seed,
            business_archetype=parsed.business.archetype,
            allowed_service_kinds=service_names,
            allowed_weakness_families=allowed_families,
            allowed_code_flaw_kinds=allowed_code_flaw_kinds,
            pinned_weaknesses=parsed.security.pinned_weaknesses,
            target_weakness_count=self._target_weakness_budget(parsed, build_config),
            phishing_surface_enabled=parsed.security.phishing_surface_enabled
            and build_config.phishing_surface_enabled,
            target_red_path_depth=parsed.difficulty.target_red_path_depth,
            target_blue_signal_points=parsed.difficulty.target_blue_signal_points,
            zones=parsed.topology.zones,
            hosts=tuple(hosts),
            services=tuple(services),
            users=users,
            groups=groups,
            credentials=credentials,
            assets=assets,
            workflows=workflows,
            edges=tuple(edges) + workflow_edges,
            weaknesses=(),
            red_objectives=red_objectives,
            blue_objectives=blue_objectives,
            green_personas=personas if build_config.green_artifacts_enabled else (),
            green_workload=GreenWorkloadSpec(
                noise_density=parsed.difficulty.target_noise_density,
            ),
            mutation_bounds=MutationBoundsSpec(
                max_new_hosts=parsed.mutation_bounds.max_new_hosts,
                max_new_services=parsed.mutation_bounds.max_new_services,
                max_new_users=parsed.mutation_bounds.max_new_users,
                max_new_weaknesses=parsed.mutation_bounds.max_new_weaknesses,
                allow_patch_old_weaknesses=parsed.mutation_bounds.allow_patch_old_weaknesses,
            ),
            lineage=LineageSpec(seed=parsed.seed),
        )

    @staticmethod
    def _selected_services(
        manifest: EnterpriseSaaSManifest,
        build_config: BuildConfig,
    ) -> tuple[str, ...]:
        services = tuple(manifest.topology.services)
        if build_config.services_enabled:
            enabled = set(build_config.services_enabled)
            services = tuple(service for service in services if service in enabled)
        if not services:
            raise ValueError("build_config removed all services from the world")
        return services

    @staticmethod
    def _selected_workflows(
        manifest: EnterpriseSaaSManifest,
        build_config: BuildConfig,
    ) -> tuple[str, ...]:
        workflows = tuple(manifest.business.workflows)
        if build_config.workflows_enabled:
            enabled = set(build_config.workflows_enabled)
            workflows = tuple(workflow for workflow in workflows if workflow in enabled)
        if not workflows:
            raise ValueError("build_config removed all workflows from the world")
        return workflows

    @staticmethod
    def _selected_weakness_families(
        manifest: EnterpriseSaaSManifest,
        build_config: BuildConfig,
    ) -> tuple:
        families = tuple(manifest.security.allowed_weakness_families)
        if build_config.weakness_families_enabled:
            enabled = set(build_config.weakness_families_enabled)
            families = tuple(family for family in families if family in enabled)
        if not families:
            raise ValueError("build_config removed all enabled weakness families")
        return families

    @staticmethod
    def _selected_code_flaw_kinds(
        manifest: EnterpriseSaaSManifest,
        build_config: BuildConfig,
    ) -> tuple:
        kinds = tuple(manifest.security.code_flaw_kinds)
        if build_config.code_flaw_kinds_enabled:
            enabled = set(build_config.code_flaw_kinds_enabled)
            kinds = tuple(kind for kind in kinds if kind in enabled)
        return kinds

    @staticmethod
    def _compile_objective(
        *,
        owner: str,
        index: int,
        predicate: str,
        assets: tuple[AssetSpec, ...],
    ) -> ObjectiveSpec:
        target = predicate_inner(predicate)
        asset = next((item for item in assets if item.id == target), None)
        objective_tags = objective_tags_for_predicate(
            predicate,
            asset_location=asset.location if asset is not None else "",
            owner_service=asset.owner_service if asset is not None else "",
            target_id=target,
        )
        return ObjectiveSpec(
            id=f"{owner}-{index}",
            owner=owner,
            predicate=predicate,
            objective_tags=objective_tags,
        )

    @staticmethod
    def _target_weakness_budget(
        manifest: EnterpriseSaaSManifest,
        build_config: BuildConfig,
    ) -> int:
        base = 2 if manifest.difficulty.target_red_path_depth <= 8 else 3
        if build_config.topology_scale == "small":
            return max(1, base - 1)
        if build_config.topology_scale == "large":
            return base + 1
        return base

    @staticmethod
    def _resolve_zone(available: tuple[str, ...], preferred: str) -> str:
        if preferred in available:
            return preferred
        if available:
            return available[0]
        raise ValueError("manifest must declare at least one topology zone")

    def _expand_users(
        self,
        manifest: EnterpriseSaaSManifest,
        build_config: BuildConfig,
    ) -> tuple[
        tuple[UserSpec, ...],
        tuple[GroupSpec, ...],
        tuple[CredentialSpec, ...],
        tuple[GreenPersona, ...],
    ]:
        users = []
        groups = []
        credentials = []
        personas = []

        for role, count in manifest.users.roles.items():
            if build_config.topology_scale == "small":
                scaled_count = 1
            elif build_config.topology_scale == "large":
                scaled_count = max(1, count * 2)
            else:
                scaled_count = count
            member_ids = []
            home_service = self._ROLE_HOME_SERVICE.get(role, "svc-web")
            home_host = self._host_for_service(home_service)
            for idx in range(1, scaled_count + 1):
                user_id = f"{role}-{idx:02d}"
                member_ids.append(user_id)
                users.append(
                    UserSpec(
                        id=user_id,
                        role=role,
                        department=role,
                        primary_host=home_host,
                        groups=(f"group-{role}",),
                        email=f"{user_id}@corp.local",
                    )
                )
                credentials.append(
                    CredentialSpec(
                        id=f"cred-{user_id}",
                        subject=user_id,
                        secret_ref=f"secret://idp/{user_id}",
                        scope=("svc-idp", home_service),
                    )
                )
                personas.append(
                    self._persona_for_user(
                        id=user_id,
                        role=role,
                        department=role,
                        home_host=home_host,
                        mailbox=f"{user_id}@corp.local",
                        profile=manifest.npc_profiles.get(role),
                    )
                )
            groups.append(
                GroupSpec(
                    id=f"group-{role}",
                    members=tuple(member_ids),
                    privileges=(home_service,),
                )
            )

        return tuple(users), tuple(groups), tuple(credentials), tuple(personas)

    def _compile_workflows(
        self,
        manifest: EnterpriseSaaSManifest,
        workflow_names: tuple[str, ...],
    ) -> tuple[tuple[WorkflowSpec, ...], tuple[EdgeSpec, ...]]:
        workflows = []
        workflow_edges = []
        for workflow_name in workflow_names:
            steps = self._workflow_steps(workflow_name)
            workflows.append(
                WorkflowSpec(
                    id=f"wf-{workflow_name}",
                    name=workflow_name,
                    steps=steps,
                )
            )
            for idx, step in enumerate(steps, start=1):
                if step.service:
                    workflow_edges.append(
                        EdgeSpec(
                            id=f"workflow-{workflow_name}-{idx}",
                            kind="workflow",
                            source=step.actor_role,
                            target=step.service,
                            label=step.action,
                        )
                    )
                if step.asset:
                    workflow_edges.append(
                        EdgeSpec(
                            id=f"data-{workflow_name}-{idx}",
                            kind="data",
                            source=step.service or step.actor_role,
                            target=step.asset,
                            label=step.action,
                        )
                    )
        return tuple(workflows), tuple(workflow_edges)

    @staticmethod
    def _workflow_steps(workflow_name: str) -> tuple[WorkflowStepSpec, ...]:
        if workflow_name == "helpdesk_ticketing":
            return (
                WorkflowStepSpec(
                    id="open-ticket",
                    actor_role="sales",
                    action="open_ticket",
                    service="svc-web",
                ),
                WorkflowStepSpec(
                    id="mail-update",
                    actor_role="sales",
                    action="send_update",
                    service="svc-email",
                ),
            )
        if workflow_name == "payroll_approval":
            return (
                WorkflowStepSpec(
                    id="view-payroll",
                    actor_role="finance",
                    action="view_payroll",
                    service="svc-web",
                    asset="payroll_db",
                ),
                WorkflowStepSpec(
                    id="approve-payroll",
                    actor_role="finance",
                    action="approve_payroll",
                    service="svc-db",
                    asset="payroll_db",
                ),
            )
        if workflow_name == "document_sharing":
            return (
                WorkflowStepSpec(
                    id="share-doc",
                    actor_role="sales",
                    action="share_document",
                    service="svc-fileshare",
                    asset="finance_docs",
                ),
            )
        if workflow_name == "internal_email":
            return (
                WorkflowStepSpec(
                    id="check-mail",
                    actor_role="sales",
                    action="check_mail",
                    service="svc-email",
                ),
            )
        return (
            WorkflowStepSpec(
                id=f"{workflow_name}-step-1",
                actor_role="sales",
                action=workflow_name,
                service="svc-web",
            ),
        )

    @staticmethod
    def _place_asset(asset: ManifestAsset) -> AssetSpec:
        asset_id = asset.id.lower()
        if "db" in asset_id:
            service = "svc-db"
            location = f"svc-db://main/{asset.id}"
        elif any(token in asset_id for token in ("doc", "file", "share")):
            service = "svc-fileshare"
            location = f"svc-fileshare:/srv/shared/{asset.id}.txt"
        elif any(token in asset_id for token in ("cred", "password", "token", "key")):
            service = "svc-idp"
            location = f"svc-idp://secrets/{asset.id}"
        else:
            service = "svc-web"
            location = f"svc-web:/var/www/html/content/{asset.id}.txt"

        confidentiality = {
            "crown_jewel": "critical",
            "sensitive": "high",
            "operational": "medium",
        }[asset.asset_class]
        return AssetSpec(
            id=asset.id,
            asset_class=asset.asset_class,
            location=location,
            owner_service=service,
            confidentiality=confidentiality,
        )

    @staticmethod
    def _host_for_service(service_id: str) -> str:
        for layout in EnterpriseSaaSManifestCompiler._SERVICE_LAYOUT.values():
            if layout["service_id"] == service_id:
                return layout["host_id"]
        return "web-1"

    @classmethod
    def _validate_npc_profiles(cls, manifest: EnterpriseSaaSManifest) -> None:
        if not manifest.npc_profiles:
            return
        declared_roles = set(manifest.users.roles)
        unknown_roles = sorted(set(manifest.npc_profiles) - declared_roles)
        if not unknown_roles:
            return
        declared = ", ".join(sorted(declared_roles))
        unknown = ", ".join(repr(role) for role in unknown_roles)
        raise ValueError(
            f"npc_profiles references unknown role(s): {unknown}; declared manifest roles: {declared}"
        )

    @classmethod
    def _persona_for_user(
        cls,
        *,
        id: str,
        role: str,
        department: str,
        home_host: str,
        mailbox: str,
        profile: NPCProfileSpec | None,
    ) -> GreenPersona:
        persona = GreenPersona(
            id=id,
            role=role,
            department=department,
            home_host=home_host,
            mailbox=mailbox,
            routine=cls._routine_for_role(role),
        )
        if profile is None:
            return persona
        updates = {"susceptibility": profile.susceptibility}
        if profile.awareness is not None:
            updates["awareness"] = profile.awareness
        if profile.routine is not None:
            updates["routine"] = profile.routine
        return persona.model_copy(update=updates)

    @staticmethod
    def _routine_for_role(role: str) -> tuple[str, ...]:
        if role == "finance":
            return ("check_mail", "open_payroll_dashboard", "access_fileshare")
        if role == "it_admin":
            return ("review_idp", "triage_alerts", "reset_password")
        return ("check_mail", "browse_app", "access_fileshare")
