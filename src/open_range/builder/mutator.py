"""Vuln mutation logic -- swap vulnerabilities between resets.

The Mutator wraps a SnapshotBuilder and adds mutation-specific context:
ensuring vuln diversity, targeting weak areas, and feeding back error
context from failed validations. Each call to ``mutate()`` produces a
snapshot with different vulnerabilities than recent episodes.
"""

from __future__ import annotations

import logging
import random
import re
from copy import deepcopy
from pathlib import PurePosixPath
from typing import Any

from open_range.builder.builder import TemplateOnlyBuilder, render_template_payloads
from open_range.builder.manifest_graph import compile_manifest_topology
from open_range.builder.mutation_policy import PopulationMutationPolicy
from open_range.protocols import (
    BuildContext,
    EvidenceItem,
    ExploitStep,
    FlagSpec,
    GoldenPathStep,
    LineageMetadata,
    MutationOp,
    MutationPlan,
    SnapshotBuilder,
    SnapshotSpec,
    Vulnerability,
)

logger = logging.getLogger(__name__)

_SUPPORTED_MUTATION_OPS = {
    "add_service",
    "add_user",
    "add_dependency_edge",
    "add_trust_edge",
    "seed_vuln",
    "add_benign_noise",
}

_GENERIC_SERVICES = {
    "",
    "sh",
    "bash",
    "ssh",
    "sshd",
    "ssh-client",
    "cron",
    "nmap",
    "curl",
    "hydra",
    "nikto",
    "sqlmap",
}
_LIVE_MUTATION_SUPPORTED_VULNS = {"sqli", "path_traversal"}


class Mutator:
    """Orchestrate vuln mutation across resets.

    Tracks episode history and feeds it into the Builder's context so that
    each reset produces a genuinely different challenge.
    """

    def __init__(
        self,
        builder: SnapshotBuilder,
        max_retries: int = 3,
        policy: PopulationMutationPolicy | None = None,
    ) -> None:
        """Initialize the mutator with a builder and retry limit.

        Args:
            builder: Any SnapshotBuilder implementation.
            max_retries: Maximum build attempts (passed through to builder).
        """
        self.builder = builder
        self.max_retries = max_retries
        self.policy = policy or PopulationMutationPolicy()
        self._history: list[str] = []  # recent vuln classes
        self._attack_surfaces: list[str] = []  # recent injection points
        self._episode_count: int = 0

    async def mutate(
        self,
        manifest: dict,
        context: BuildContext | None = None,
        error: dict[str, Any] | None = None,
        parent_snapshot: SnapshotSpec | None = None,
        parent_snapshot_id: str | None = None,
    ) -> SnapshotSpec:
        """Generate a root or child snapshot, avoiding recent vuln classes.

        Args:
            manifest: Parsed manifest dict.
            context: Optional base context (curriculum stats, etc.).
            error: Error feedback from a failed validation attempt.
            parent_snapshot: Admitted parent snapshot to mutate forward.
            parent_snapshot_id: Persisted ID for *parent_snapshot*.

        Returns:
            A new SnapshotSpec. Root snapshots are compiled from the manifest;
            child snapshots are mutated from the parent.
        """
        if context is None:
            context = BuildContext()

        # Inject episode history into context
        context.previous_vuln_classes = list(self._history[-3:])
        context.recent_attack_surfaces = list(self._attack_surfaces[-5:])
        context.episode_count = self._episode_count

        logger.debug(
            "Mutator: preparing mutation for episode %d (avoiding vulns: %s, surfaces: %s)",
            self._episode_count + 1,
            context.previous_vuln_classes,
            context.recent_attack_surfaces,
        )

        if error is not None:
            logger.warning(
                "Mutator: retrying with error feedback: %s",
                list(error.keys()) if isinstance(error, dict) else error,
            )
            # error field may or may not exist on BuildContext
            try:
                context.error = error  # type: ignore[attr-defined]
            except (AttributeError, ValueError):
                pass  # protocol version without error field

        # Build with diversity enforcement -- retry up to 3 times if the
        # snapshot repeats recent vuln classes or injection points.
        max_diversity_retries = 3
        snapshot: SnapshotSpec | None = None
        last_reason = ""

        for attempt in range(1, max_diversity_retries + 1):
            if parent_snapshot is None:
                candidate = await self.builder.build(manifest, context)
                candidate = self._hydrate_root_snapshot(candidate, manifest)
            else:
                candidate = self._mutate_parent_snapshot(
                    manifest=manifest,
                    parent_snapshot=parent_snapshot,
                    parent_snapshot_id=parent_snapshot_id,
                    context=context,
                )

            passes, reason = self._check_diversity(candidate, manifest)
            if passes:
                snapshot = candidate
                break

            last_reason = reason
            logger.info(
                "Mutator: diversity check failed on attempt %d/%d: %s",
                attempt,
                max_diversity_retries,
                reason,
            )

        if snapshot is None:
            # Exhausted retries -- accept last candidate with a warning
            logger.warning(
                "Mutator: accepting snapshot after %d diversity retries; last failure: %s",
                max_diversity_retries,
                last_reason,
            )
            snapshot = candidate  # type: ignore[possibly-undefined]

        # Update history
        new_classes = [v.type for v in snapshot.truth_graph.vulns]
        self._history.extend(new_classes)
        new_surfaces = [v.injection_point for v in snapshot.truth_graph.vulns]
        self._attack_surfaces.extend(new_surfaces)
        self._episode_count += 1

        logger.info(
            "Mutator: episode %d complete, vuln classes: %s, total history: %d entries",
            self._episode_count,
            new_classes,
            len(self._history),
        )

        return snapshot

    @property
    def episode_count(self) -> int:
        """Number of episodes (mutations) completed so far."""
        return self._episode_count

    @property
    def history(self) -> list[str]:
        """All vuln classes used so far, in order."""
        return list(self._history)

    def _check_diversity(
        self,
        snapshot: SnapshotSpec,
        manifest: dict[str, Any],
    ) -> tuple[bool, str]:
        """Check whether *snapshot* meets vuln diversity constraints.

        Returns:
            ``(passes, reason)`` -- *passes* is ``True`` when the snapshot
            satisfies the diversity rules; *reason* explains why it failed.
        """
        new_classes = [v.type for v in snapshot.truth_graph.vulns]
        new_surfaces = [v.injection_point for v in snapshot.truth_graph.vulns]

        recent_classes = set(self._history[-3:]) if self._history else set()
        recent_surfaces = set(self._attack_surfaces[-5:]) if self._attack_surfaces else set()

        all_families = {str(v) for v in manifest.get("bug_families", []) if v}

        # --- vuln class check ---
        if new_classes and recent_classes:
            new_class_set = set(new_classes)
            if new_class_set and new_class_set.issubset(recent_classes):
                # Only reject if there ARE alternative families we could use
                alternatives = all_families - recent_classes
                if alternatives:
                    return (
                        False,
                        f"All vuln classes {sorted(new_class_set)} repeat recent history "
                        f"{sorted(recent_classes)}; alternatives available: {sorted(alternatives)}",
                    )

        # --- injection point check ---
        if new_surfaces and recent_surfaces:
            new_surface_set = set(new_surfaces)
            if new_surface_set and new_surface_set.issubset(recent_surfaces):
                # Only reject if the manifest has enough families to allow
                # different surfaces (any alternative family would produce a
                # different dynamic injection point)
                alternatives = all_families - set(new_classes)
                if alternatives:
                    return (
                        False,
                        f"All injection points {sorted(new_surface_set)} repeat recent surfaces "
                        f"{sorted(recent_surfaces)}; alternatives available: {sorted(alternatives)}",
                    )

        return (True, "")

    def _hydrate_root_snapshot(
        self,
        snapshot: SnapshotSpec,
        manifest: dict[str, Any],
    ) -> SnapshotSpec:
        root = snapshot.model_copy(deep=True)
        root.topology = compile_manifest_topology(manifest, root.topology)
        root.lineage = LineageMetadata(
            manifest_id=str(manifest.get("name", "")),
            generation_depth=0,
            mutation_summary=["compile_base_snapshot"],
        )
        root.mutation_plan = None
        normalization = root.topology.get("manifest_normalization", {})
        if isinstance(normalization, dict):
            notes = normalization.get("notes", [])
            if isinstance(notes, list):
                for note in notes:
                    logger.info("Mutator: manifest normalization applied: %s", note)
        return root

    def _mutate_parent_snapshot(
        self,
        *,
        manifest: dict[str, Any],
        parent_snapshot: SnapshotSpec,
        parent_snapshot_id: str | None,
        context: BuildContext,
    ) -> SnapshotSpec:
        rng = random.Random(context.seed if context.seed is not None else self._episode_count + 1)
        child = parent_snapshot.model_copy(deep=True)
        child.topology = _ensure_mutable_topology(child.topology, manifest)

        plan = self._plan_mutations(
            manifest=manifest,
            snapshot=child,
            parent_snapshot_id=parent_snapshot_id,
            context=context,
            rng=rng,
        )
        self._validate_plan_legality(manifest, plan)
        self._apply_plan(child, plan, manifest, context)
        child.files = render_template_payloads(child, manifest=manifest)

        lineage = parent_snapshot.lineage.model_copy(deep=True)
        child.lineage = LineageMetadata(
            parent_snapshot_id=parent_snapshot_id or parent_snapshot.lineage.snapshot_id or None,
            root_snapshot_id=lineage.root_snapshot_id or parent_snapshot_id or "",
            manifest_id=lineage.manifest_id or str(manifest.get("name", "")),
            generation_depth=lineage.generation_depth + 1,
            mutation_ids=[op.mutation_id for op in plan.ops],
            mutation_summary=[_mutation_summary(op) for op in plan.ops],
        )
        child.mutation_plan = plan
        return child

    def _plan_mutations(
        self,
        *,
        manifest: dict[str, Any],
        snapshot: SnapshotSpec,
        parent_snapshot_id: str | None,
        context: BuildContext,
        rng: random.Random,
    ) -> MutationPlan:
        ops: list[MutationOp] = []

        structural_candidates = []
        op = self._candidate_add_service(manifest, snapshot, rng)
        if op is not None:
            structural_candidates.append(op)
        op = self._candidate_add_user(manifest, snapshot, context, rng)
        if op is not None:
            structural_candidates.append(op)
        op = self._candidate_add_dependency_edge(manifest, snapshot, rng)
        if op is not None:
            structural_candidates.append(op)
        op = self._candidate_add_trust_edge(manifest, snapshot, rng)
        if op is not None:
            structural_candidates.append(op)

        security_candidates = []
        op = self._candidate_seed_vuln(manifest, snapshot, context, rng)
        if op is not None:
            security_candidates.append(op)
        op = self._candidate_add_benign_noise(snapshot, rng)
        if op is not None:
            security_candidates.append(op)

        ops, policy_score, score_breakdown = self.policy.choose_mutations(
            structural_candidates=structural_candidates,
            security_candidates=security_candidates,
            snapshot=snapshot,
            context=context,
            rng=rng,
        )
        if ops:
            logger.info(
                "Mutator policy %s chose ops=%s score=%.3f breakdown=%s",
                self.policy.name,
                [op.mutation_id for op in ops],
                policy_score,
                score_breakdown,
            )

        if not ops:
            fallback = self._candidate_add_benign_noise(snapshot, rng)
            if fallback is not None:
                ops.append(fallback)

        return MutationPlan(
            parent_snapshot_id=parent_snapshot_id,
            ops=ops,
            predicted_complexity_delta=len(ops),
            predicted_chain_delta=sum(1 for op in ops if op.op_type == "seed_vuln"),
            predicted_novelty=round(0.2 * len({op.op_type for op in ops}), 2),
            policy_name=self.policy.name,
            policy_score=policy_score,
            score_breakdown=score_breakdown,
        )

    def _validate_plan_legality(
        self,
        manifest: dict[str, Any],
        plan: MutationPlan,
    ) -> None:
        manifest_hosts = _manifest_hosts(manifest)
        allowed_bug_families = {str(v) for v in manifest.get("bug_families", []) if str(v)}
        allowed_users = _manifest_users(manifest)
        allowed_principals = _manifest_principals(manifest)
        allowed_services = _manifest_services(manifest)
        allowed_dependency_edges = _manifest_dependency_edges(manifest)
        allowed_trust_edges = _manifest_trust_edges(manifest)

        for op in plan.ops:
            prefix = f"Illegal mutation op {op.mutation_id!r} ({op.op_type})"
            if op.op_type not in _SUPPORTED_MUTATION_OPS:
                raise ValueError(f"{prefix}: unsupported op_type")

            if op.op_type == "add_service":
                host = op.target_selector.get("host", "")
                service = str(op.params.get("service", "")).strip()
                if host not in manifest_hosts:
                    raise ValueError(f"{prefix}: add_service targets unknown host {host!r}")
                if service and service not in allowed_services.get(host, frozenset()):
                    raise ValueError(
                        f"{prefix}: add_service introduces illegal service {service!r} on {host!r}"
                    )

            elif op.op_type == "add_user":
                username = str(op.params.get("username", "")).strip()
                if username and username not in allowed_users:
                    raise ValueError(
                        f"{prefix}: add_user introduces unknown manifest user {username!r}"
                    )

            elif op.op_type == "add_dependency_edge":
                source = op.target_selector.get("source", "")
                target = op.target_selector.get("target", "")
                if (source, target) not in allowed_dependency_edges:
                    raise ValueError(
                        f"{prefix}: add_dependency_edge introduces illegal edge {source!r}->{target!r}"
                    )

            elif op.op_type == "add_trust_edge":
                source = op.target_selector.get("source", "")
                target = op.target_selector.get("target", "")
                edge_type = str(op.params.get("type", "")).strip()
                if source and source not in allowed_principals:
                    raise ValueError(
                        f"{prefix}: add_trust_edge introduces unknown principal {source!r}"
                    )
                if target and target not in allowed_principals:
                    raise ValueError(
                        f"{prefix}: add_trust_edge introduces unknown principal {target!r}"
                    )
                if (source, target, edge_type) not in allowed_trust_edges:
                    raise ValueError(
                        f"{prefix}: add_trust_edge introduces illegal edge "
                        f"{source!r}->{target!r} ({edge_type!r})"
                    )

            elif op.op_type == "seed_vuln":
                host = op.target_selector.get("host", "")
                vuln_type = str(op.params.get("vuln_type", "")).strip()
                required_services = {
                    str(service).strip()
                    for service in op.params.get("required_services", [])
                    if str(service).strip()
                }
                if host not in manifest_hosts:
                    raise ValueError(f"{prefix}: seed_vuln targets unknown host {host!r}")
                if vuln_type and vuln_type not in allowed_bug_families:
                    raise ValueError(
                        f"{prefix}: seed_vuln uses illegal family {vuln_type!r}"
                    )
                if required_services:
                    host_services = allowed_services.get(host, frozenset())
                    if not required_services.intersection(host_services):
                        raise ValueError(
                            f"{prefix}: seed_vuln host {host!r} incompatible with required "
                            f"services {sorted(required_services)}"
                        )

    def _candidate_add_service(
        self,
        manifest: dict[str, Any],
        snapshot: SnapshotSpec,
        rng: random.Random,
    ) -> MutationOp | None:
        topology = snapshot.topology
        host_catalog = topology.get("host_catalog", {})
        host_details = topology.get("host_details", {})
        candidates: list[tuple[str, str]] = []
        if not isinstance(host_catalog, dict) or not isinstance(host_details, dict):
            return None
        for host, raw_catalog in host_catalog.items():
            if not isinstance(raw_catalog, dict):
                continue
            allowed = raw_catalog.get("services", [])
            detail = host_details.get(host, {})
            current = detail.get("services", []) if isinstance(detail, dict) else []
            if not isinstance(allowed, list) or not isinstance(current, list):
                continue
            for service in allowed:
                if service and service not in current:
                    candidates.append((str(host), str(service)))
        if not candidates:
            return None
        host, service = rng.choice(candidates)
        return MutationOp(
            mutation_id=f"mut_add_service_{host}_{service}",
            op_type="add_service",
            target_selector={"host": host},
            params={"service": service},
            expected_effects=[f"service {service} added to {host}"],
            risk_tags=["surface_expansion"],
        )

    def _candidate_add_user(
        self,
        manifest: dict[str, Any],
        snapshot: SnapshotSpec,
        context: BuildContext,
        rng: random.Random,
    ) -> MutationOp | None:
        existing = _existing_usernames(snapshot)
        candidates = [
            raw for raw in manifest.get("users", [])
            if isinstance(raw, dict) and raw.get("username") not in existing
        ]
        if not candidates:
            return None
        user = deepcopy(rng.choice(candidates))
        username = str(user.get("username", "")).strip()
        if not username:
            return None
        password = _predictable_password(username, context.seed)
        return MutationOp(
            mutation_id=f"mut_add_user_{username}",
            op_type="add_user",
            target_selector={"user": username},
            params={
                "username": username,
                "password": password,
                "hosts": deepcopy(user.get("hosts", [])),
                "groups": [str(user.get("department", "") or "users").lower().replace(" ", "_")],
                "email": str(user.get("email", "")),
                "full_name": str(user.get("full_name", "")),
                "department": str(user.get("department", "")),
                "role": str(user.get("role", "")),
            },
            expected_effects=[f"user {username} added to snapshot accounts"],
            risk_tags=["identity_expansion"],
        )

    def _candidate_add_dependency_edge(
        self,
        manifest: dict[str, Any],
        snapshot: SnapshotSpec,
        rng: random.Random,
    ) -> MutationOp | None:
        topology = snapshot.topology
        current = {
            (str(edge.get("source", "")), str(edge.get("target", "")))
            for edge in topology.get("dependency_edges", [])
            if isinstance(edge, dict)
        }
        candidates: list[tuple[str, str]] = []
        for raw in manifest.get("topology", {}).get("hosts", []):
            if not isinstance(raw, dict):
                continue
            source = str(raw.get("name", "")).strip()
            raw_targets = raw.get("connects_to", [])
            if not source or not isinstance(raw_targets, list):
                continue
            for target_raw in raw_targets:
                target = str(target_raw).strip()
                if target and (source, target) not in current:
                    candidates.append((source, target))
        if not candidates:
            return None
        source, target = rng.choice(candidates)
        return MutationOp(
            mutation_id=f"mut_add_dep_{source}_{target}",
            op_type="add_dependency_edge",
            target_selector={"source": source, "target": target},
            params={},
            expected_effects=[f"dependency edge {source}->{target} added"],
            risk_tags=["topology_expansion"],
        )

    def _candidate_add_trust_edge(
        self,
        manifest: dict[str, Any],
        snapshot: SnapshotSpec,
        rng: random.Random,
    ) -> MutationOp | None:
        topology = snapshot.topology
        current = {
            (
                str(edge.get("source", "")),
                str(edge.get("target", "")),
                str(edge.get("type", "")),
            )
            for edge in topology.get("trust_edges", [])
            if isinstance(edge, dict)
        }
        candidates: list[dict[str, str]] = []
        for raw in manifest.get("trust_relationships", []):
            if not isinstance(raw, dict):
                continue
            source = str(raw.get("source") or raw.get("from") or "").strip()
            target = str(raw.get("target") or raw.get("to") or "").strip()
            edge_type = str(raw.get("type", "")).strip()
            if source and target and (source, target, edge_type) not in current:
                candidates.append(
                    {
                        "source": source,
                        "target": target,
                        "type": edge_type,
                        "context": str(raw.get("context") or raw.get("description") or ""),
                    }
                )
        if not candidates:
            return None
        choice = rng.choice(candidates)
        return MutationOp(
            mutation_id=f"mut_add_trust_{choice['source']}_{choice['target']}_{choice['type']}",
            op_type="add_trust_edge",
            target_selector={"source": choice["source"], "target": choice["target"]},
            params={"type": choice["type"], "context": choice["context"]},
            expected_effects=[f"trust edge {choice['source']}->{choice['target']} added"],
            risk_tags=["trust_expansion"],
        )

    def _candidate_seed_vuln(
        self,
        manifest: dict[str, Any],
        snapshot: SnapshotSpec,
        context: BuildContext,
        rng: random.Random,
    ) -> MutationOp | None:
        allowed = [str(v) for v in manifest.get("bug_families", []) if v]
        if not allowed:
            return None
        existing = {v.type for v in snapshot.truth_graph.vulns}
        templates = self._compatible_vuln_templates(snapshot, context)
        if not templates:
            return None

        preferred_types = [v for v in context.weak_areas if v in allowed and v not in existing]
        remaining_types = [v for v in allowed if v not in existing]
        candidate_types = preferred_types or remaining_types or allowed

        compatible = [
            template
            for template in templates
            if str(template.get("type", "")) in candidate_types
        ]
        if not compatible:
            return None

        template = rng.choice(compatible)
        vuln_type = str(template.get("type", "")).strip()
        host = str(template.get("host", "")).strip()
        service = str(template.get("service", "")).strip()
        required_services = sorted(self._template_required_services(snapshot, template))
        return MutationOp(
            mutation_id=f"mut_seed_vuln_{vuln_type}_{host}_{len(snapshot.truth_graph.vulns)+1}",
            op_type="seed_vuln",
            target_selector={"host": host},
            params={
                "vuln_type": vuln_type,
                "service": service,
                "template_id": str(template.get("id", vuln_type)),
                "required_services": required_services,
            },
            expected_effects=[f"new {vuln_type} foothold on {host}"],
            risk_tags=["security_condition"],
        )

    def _candidate_add_benign_noise(
        self,
        snapshot: SnapshotSpec,
        rng: random.Random,
    ) -> MutationOp | None:
        locations = [item.location for item in snapshot.evidence_spec if item.location]
        location = rng.choice(locations) if locations else "siem:background.log"
        return MutationOp(
            mutation_id=f"mut_add_noise_{len(snapshot.evidence_spec)+1}",
            op_type="add_benign_noise",
            target_selector={"location": location},
            params={"location": location},
            expected_effects=[f"benign evidence noise added at {location}"],
            risk_tags=["observability_noise"],
        )

    def _apply_plan(
        self,
        snapshot: SnapshotSpec,
        plan: MutationPlan,
        manifest: dict[str, Any],
        context: BuildContext,
    ) -> None:
        topology = snapshot.topology
        host_details = topology.setdefault("host_details", {})
        dependency_edges = topology.setdefault("dependency_edges", [])
        trust_edges = topology.setdefault("trust_edges", [])
        principal_catalog = topology.setdefault("principal_catalog", {})
        users = topology.setdefault("users", [])

        if not isinstance(host_details, dict):
            host_details = {}
            topology["host_details"] = host_details
        if not isinstance(dependency_edges, list):
            dependency_edges = []
            topology["dependency_edges"] = dependency_edges
        if not isinstance(trust_edges, list):
            trust_edges = []
            topology["trust_edges"] = trust_edges
        if not isinstance(principal_catalog, dict):
            principal_catalog = {}
            topology["principal_catalog"] = principal_catalog
        if not isinstance(users, list):
            users = []
            topology["users"] = users

        for op in plan.ops:
            if op.op_type not in _SUPPORTED_MUTATION_OPS:
                raise ValueError(f"Unsupported mutation op {op.op_type!r}")

            if op.op_type == "add_service":
                host = op.target_selector["host"]
                detail = host_details.setdefault(host, {"services": [], "connects_to": []})
                services = detail.setdefault("services", [])
                service = str(op.params.get("service", "")).strip()
                if service and service not in services:
                    services.append(service)

            elif op.op_type == "add_user":
                username = str(op.params.get("username", ""))
                user_record = {
                    "username": username,
                    "password": str(op.params.get("password", "")),
                    "groups": deepcopy(op.params.get("groups", [])),
                    "hosts": deepcopy(op.params.get("hosts", [])),
                    "email": str(op.params.get("email", "")),
                    "full_name": str(op.params.get("full_name", "")),
                    "department": str(op.params.get("department", "")),
                    "role": str(op.params.get("role", "")),
                }
                users.append(user_record)
                principal_catalog[username] = {
                    "username": username,
                    "kind": "user",
                    "is_login_account": True,
                    "hosts": deepcopy(op.params.get("hosts", [])),
                    "department": str(op.params.get("department", "")),
                    "role": str(op.params.get("role", "")),
                    "email": str(op.params.get("email", "")),
                    "full_name": str(op.params.get("full_name", "")),
                }

            elif op.op_type == "add_dependency_edge":
                dependency_edges.append(
                    {
                        "source": op.target_selector["source"],
                        "target": op.target_selector["target"],
                    }
                )

            elif op.op_type == "add_trust_edge":
                trust_edges.append(
                    {
                        "source": op.target_selector["source"],
                        "target": op.target_selector["target"],
                        "type": str(op.params.get("type", "")),
                        "context": str(op.params.get("context", "")),
                    }
                )

            elif op.op_type == "seed_vuln":
                template = self._resolve_vuln_template(op)
                instantiated = _instantiate_seed_vuln_from_template(
                    template=template,
                    host=op.target_selector["host"],
                    index=len(snapshot.truth_graph.vulns) + 1,
                    step_offset=len(snapshot.golden_path),
                )
                snapshot.truth_graph.vulns.append(instantiated["vuln"])
                snapshot.truth_graph.exploit_chain.append(instantiated["exploit_step"])
                snapshot.flags.append(instantiated["flag"])
                snapshot.golden_path.extend(instantiated["golden_path"])
                snapshot.evidence_spec.extend(instantiated["evidence"])
                _append_task_path(snapshot, instantiated["flag"], instantiated["milestone"])
                op.params.update(
                    {
                        "service": instantiated["vuln"].service,
                        "instantiated_vuln_id": instantiated["vuln"].id,
                        "instantiated_flag_id": instantiated["flag"].id,
                        "instantiated_flag_value": instantiated["flag"].value,
                        "instantiated_flag_host": instantiated["flag"].host,
                        "instantiated_exploit_command": instantiated["exploit_step"].command,
                    }
                )

            elif op.op_type == "add_benign_noise":
                location = str(op.params.get("location", "siem:background.log"))
                snapshot.evidence_spec.append(
                    EvidenceItem(
                        type="log_entry",
                        location=location,
                        pattern=(
                            f"Benign background activity {context.episode_count + len(snapshot.evidence_spec)}"
                        ),
                    )
                )

        snapshot.topology = topology

    def _compatible_vuln_templates(
        self,
        snapshot: SnapshotSpec,
        context: BuildContext,
    ) -> list[dict[str, Any]]:
        templates = []
        live_only = "prefer_live_admission_compatible_vulns" in context.narrative_hints
        for template in self._vuln_pool():
            if not isinstance(template, dict):
                continue
            vuln_type = str(template.get("type", "")).strip()
            host = str(template.get("host", "")).strip()
            if not vuln_type or not host:
                continue
            if live_only and vuln_type not in _LIVE_MUTATION_SUPPORTED_VULNS:
                continue
            if not self._template_has_task_path(template):
                continue
            if host not in _existing_hosts(snapshot):
                continue
            required_services = self._template_required_services(snapshot, template)
            host_services = _host_services(snapshot.topology, host)
            if required_services and not required_services.intersection(host_services):
                continue
            templates.append(template)
        return templates

    def _template_required_services(
        self,
        snapshot: SnapshotSpec,
        template: dict[str, Any],
    ) -> set[str]:
        template_host = str(template.get("host", "")).strip()
        host_services = _host_services(snapshot.topology, template_host)
        if host_services:
            return host_services

        service_text = str(template.get("service", "")).strip().lower()
        if not service_text:
            return set()
        parts = {
            token
            for token in re.split(r"[^a-z0-9_-]+", service_text)
            if token and token not in _GENERIC_SERVICES
        }
        return parts

    def _template_has_task_path(self, template: dict[str, Any]) -> bool:
        raw_steps = template.get("golden_path_steps", [])
        if not isinstance(raw_steps, list) or not raw_steps:
            return False
        flag_value = str(template.get("flag_value", "")).strip()
        if not flag_value:
            return False
        return any(
            isinstance(step, dict)
            and flag_value in str(step.get("cmd", ""))
            and str(step.get("cmd", "")).strip().startswith("submit_flag ")
            for step in raw_steps
        )

    def _resolve_vuln_template(self, op: MutationOp) -> dict[str, Any]:
        template_id = str(op.params.get("template_id", "")).strip()
        vuln_type = str(op.params.get("vuln_type", "")).strip()
        host = str(op.target_selector.get("host", "")).strip()
        for template in self._vuln_pool():
            if not isinstance(template, dict):
                continue
            if template_id and str(template.get("id", "")).strip() == template_id:
                return template
        for template in self._vuln_pool():
            if not isinstance(template, dict):
                continue
            if (
                str(template.get("type", "")).strip() == vuln_type
                and str(template.get("host", "")).strip() == host
            ):
                return template
        raise ValueError(
            f"No vulnerability template found for mutation op {op.mutation_id!r}"
        )

    def _vuln_pool(self) -> list[dict[str, Any]]:
        raw_pool = getattr(self.builder, "vuln_pool", None)
        if isinstance(raw_pool, list) and raw_pool:
            return raw_pool
        return TemplateOnlyBuilder().vuln_pool


def _manifest_hosts(manifest: dict[str, Any]) -> set[str]:
    hosts: set[str] = set()
    for raw in manifest.get("topology", {}).get("hosts", []):
        if not isinstance(raw, dict):
            continue
        name = str(raw.get("name", "")).strip()
        if name:
            hosts.add(name)
    return hosts


def _manifest_users(manifest: dict[str, Any]) -> set[str]:
    users: set[str] = set()
    for raw in manifest.get("users", []):
        if not isinstance(raw, dict):
            continue
        username = str(raw.get("username", "")).strip()
        if username:
            users.add(username)
    return users


def _manifest_principals(manifest: dict[str, Any]) -> set[str]:
    principals = set(_manifest_users(manifest))
    for raw in manifest.get("trust_relationships", []):
        if not isinstance(raw, dict):
            continue
        source = str(raw.get("source") or raw.get("from") or "").strip()
        target = str(raw.get("target") or raw.get("to") or "").strip()
        if source:
            principals.add(source)
        if target:
            principals.add(target)
    return principals


def _manifest_services(manifest: dict[str, Any]) -> dict[str, frozenset[str]]:
    services: dict[str, frozenset[str]] = {}
    for raw in manifest.get("topology", {}).get("hosts", []):
        if not isinstance(raw, dict):
            continue
        host = str(raw.get("name", "")).strip()
        if not host:
            continue
        raw_services = raw.get("services", [])
        if not isinstance(raw_services, list):
            raw_services = []
        services[host] = frozenset(str(service).strip() for service in raw_services if str(service).strip())
    return services


def _manifest_dependency_edges(manifest: dict[str, Any]) -> set[tuple[str, str]]:
    edges: set[tuple[str, str]] = set()
    for raw in manifest.get("topology", {}).get("hosts", []):
        if not isinstance(raw, dict):
            continue
        source = str(raw.get("name", "")).strip()
        raw_targets = raw.get("connects_to", [])
        if not source or not isinstance(raw_targets, list):
            continue
        for raw_target in raw_targets:
            target = str(raw_target).strip()
            if target:
                edges.add((source, target))
    return edges


def _manifest_trust_edges(manifest: dict[str, Any]) -> set[tuple[str, str, str]]:
    edges: set[tuple[str, str, str]] = set()
    for raw in manifest.get("trust_relationships", []):
        if not isinstance(raw, dict):
            continue
        source = str(raw.get("source") or raw.get("from") or "").strip()
        target = str(raw.get("target") or raw.get("to") or "").strip()
        edge_type = str(raw.get("type", "")).strip()
        if source and target:
            edges.add((source, target, edge_type))
    return edges


def _ensure_mutable_topology(
    topology: dict[str, Any],
    manifest: dict[str, Any],
) -> dict[str, Any]:
    return compile_manifest_topology(manifest, topology)


def _existing_hosts(snapshot: SnapshotSpec) -> set[str]:
    hosts: set[str] = set()
    for raw in snapshot.topology.get("hosts", []):
        if isinstance(raw, dict):
            name = str(raw.get("name", "")).strip()
            if name:
                hosts.add(name)
        else:
            name = str(raw).strip()
            if name:
                hosts.add(name)
    return hosts


def _existing_usernames(snapshot: SnapshotSpec) -> set[str]:
    usernames: set[str] = set()
    for raw in snapshot.topology.get("users", []):
        if not isinstance(raw, dict):
            continue
        username = str(raw.get("username", "")).strip()
        if username:
            usernames.add(username)
    return usernames


def _predictable_password(username: str, seed: int | None) -> str:
    suffix = 2025 if seed is None else 2025 + (seed % 3)
    base = username.split("@", 1)[0] or "Welcome"
    return f"{base.capitalize()}!{suffix}"


def _mutation_summary(op: MutationOp) -> str:
    if op.op_type == "add_service":
        return f"add service {op.params.get('service', '')} to {op.target_selector.get('host', '')}"
    if op.op_type == "add_user":
        return f"add user {op.params.get('username', '')}"
    if op.op_type == "add_dependency_edge":
        return (
            f"add dependency {op.target_selector.get('source', '')}->"
            f"{op.target_selector.get('target', '')}"
        )
    if op.op_type == "add_trust_edge":
        return (
            f"add trust {op.target_selector.get('source', '')}->"
            f"{op.target_selector.get('target', '')}"
        )
    if op.op_type == "seed_vuln":
        return (
            f"seed {op.params.get('vuln_type', '')} on "
            f"{op.target_selector.get('host', '')}"
        )
    if op.op_type == "add_benign_noise":
        return f"add benign noise at {op.params.get('location', '')}"
    return op.op_type


def _host_services(topology: dict[str, Any], host: str) -> set[str]:
    services: set[str] = set()
    host_details = topology.get("host_details", {})
    host_catalog = topology.get("host_catalog", {})
    for raw_map in (host_details, host_catalog):
        if not isinstance(raw_map, dict):
            continue
        raw_detail = raw_map.get(host, {})
        if not isinstance(raw_detail, dict):
            continue
        raw_services = raw_detail.get("services", [])
        if not isinstance(raw_services, list):
            continue
        for raw_service in raw_services:
            service = str(raw_service).strip().lower()
            if service and service not in _GENERIC_SERVICES:
                services.add(service)
    return services


def _instantiate_seed_vuln_from_template(
    *,
    template: dict[str, Any],
    host: str,
    index: int,
    step_offset: int,
) -> dict[str, Any]:
    vuln_type = str(template.get("type", "")).strip()
    template_host = str(template.get("host", host)).strip() or host
    raw_steps = template.get("golden_path_steps", [])
    if not isinstance(raw_steps, list) or not raw_steps:
        raise ValueError(f"Template {template.get('id', vuln_type)!r} has no golden path")

    flag_id = f"flag{index}"
    template_flag_value = str(template.get("flag_value", f"FLAG{{{vuln_type}}}")).strip()
    flag_value = _mutation_flag_value(template_flag_value, vuln_type, index)
    template_flag_path = str(template.get("flag_path", f"/var/flags/flag{index}.txt")).strip()
    flag_path = _mutation_flag_path(template_flag_path, index)
    service = str(template.get("service", "")).strip()
    vuln_id = f"{vuln_type}_{index}"
    exploit_command = _template_exploit_command(raw_steps)

    vuln = Vulnerability(
        id=vuln_id,
        type=vuln_type,
        host=host,
        service=service,
        injection_point=_rewrite_template_text(
            exploit_command,
            template_host=template_host,
            target_host=host,
            template_flag_value=template_flag_value,
            flag_value=flag_value,
            template_flag_path=template_flag_path,
            flag_path=flag_path,
        ),
        vulnerable_code=template.get("vulnerable_code", ""),
        root_cause=str(template.get("root_cause", "")),
        blast_radius=str(template.get("blast_radius", "")),
        remediation=str(template.get("remediation", "")),
    )
    exploit_step = ExploitStep(
        vuln_id=vuln_id,
        command=vuln.injection_point,
        description=f"Exploit {vuln_type} on {host}",
    )
    flag = FlagSpec(
        id=flag_id,
        value=flag_value,
        path=flag_path,
        host=host,
    )

    golden_path: list[GoldenPathStep] = []
    for raw_step in raw_steps:
        if not isinstance(raw_step, dict):
            continue
        command = _rewrite_template_text(
            str(raw_step.get("cmd", "")),
            template_host=template_host,
            target_host=host,
            template_flag_value=template_flag_value,
            flag_value=flag_value,
            template_flag_path=template_flag_path,
            flag_path=flag_path,
        )
        expect = _rewrite_template_text(
            str(raw_step.get("expect_stdout", "")),
            template_host=template_host,
            target_host=host,
            template_flag_value=template_flag_value,
            flag_value=flag_value,
            template_flag_path=template_flag_path,
            flag_path=flag_path,
        )
        golden_path.append(
            GoldenPathStep(
                step=step_offset + len(golden_path) + 1,
                command=command,
                expect_in_stdout=expect,
                host=str(raw_step.get("host", "attacker") or "attacker"),
                description=str(raw_step.get("description", "")),
            )
        )

    evidence = [
        EvidenceItem(
            type="log_entry",
            location=f"{host}:/var/log/app/access.log",
            pattern=f"{vuln_type} exploitation on {host}",
        ),
        EvidenceItem(
            type="alert",
            location="siem:/var/log/siem/consolidated/all.log",
            pattern=f"{vuln_type} alert for {host}",
        ),
    ]
    return {
        "vuln": vuln,
        "exploit_step": exploit_step,
        "flag": flag,
        "golden_path": golden_path,
        "evidence": evidence,
        "milestone": f"Capture {flag.id} by exploiting {vuln_type} on {host}",
    }


def _append_task_path(snapshot: SnapshotSpec, flag: FlagSpec, milestone: str) -> None:
    if milestone and milestone not in snapshot.task.milestones:
        snapshot.task.milestones.append(milestone)
    condition = {"type": "flag", "value": flag.value}
    if condition not in snapshot.task.success_conditions:
        snapshot.task.success_conditions.append(condition)


def _mutation_flag_value(template_value: str, vuln_type: str, index: int) -> str:
    if template_value.startswith("FLAG{") and template_value.endswith("}"):
        inner = template_value[5:-1]
    else:
        inner = f"{vuln_type}_{index}"
    return f"FLAG{{{inner}_mut{index}}}"


def _mutation_flag_path(template_path: str, index: int) -> str:
    if template_path.startswith("db:"):
        return template_path
    path = PurePosixPath(template_path or f"/var/flags/flag{index}.txt")
    stem = path.stem or f"flag{index}"
    suffix = path.suffix
    renamed = path.with_name(f"{stem}_mut{index}{suffix}")
    return renamed.as_posix()


def _template_exploit_command(raw_steps: list[Any]) -> str:
    non_submit = [
        str(raw.get("cmd", "")).strip()
        for raw in raw_steps
        if isinstance(raw, dict) and not str(raw.get("cmd", "")).strip().startswith("submit_flag ")
    ]
    if non_submit:
        return non_submit[-1]
    return ""


def _rewrite_template_text(
    text: str,
    *,
    template_host: str,
    target_host: str,
    template_flag_value: str,
    flag_value: str,
    template_flag_path: str,
    flag_path: str,
) -> str:
    updated = text.replace(template_flag_value, flag_value)
    if template_flag_path and flag_path and template_flag_path != flag_path:
        updated = updated.replace(template_flag_path, flag_path)
        updated = updated.replace(
            PurePosixPath(template_flag_path).name,
            PurePosixPath(flag_path).name,
        )
    if template_host and target_host and template_host != target_host:
        replacements = {
            f"http://{template_host}/": f"http://{target_host}/",
            f"http://{template_host}": f"http://{target_host}",
            f"ldap://{template_host}": f"ldap://{target_host}",
            f"//{template_host}/": f"//{target_host}/",
            f"-h {template_host} ": f"-h {target_host} ",
            f"@{template_host} ": f"@{target_host} ",
            f"@{template_host}'": f"@{target_host}'",
            f"@{template_host}\"": f"@{target_host}\"",
        }
        for old, new in replacements.items():
            updated = updated.replace(old, new)
    return updated
