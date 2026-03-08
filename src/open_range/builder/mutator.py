"""Vuln mutation logic -- swap vulnerabilities between resets.

The Mutator wraps a SnapshotBuilder and adds mutation-specific context:
ensuring vuln diversity, targeting weak areas, and feeding back error
context from failed validations. Each call to ``mutate()`` produces a
snapshot with different vulnerabilities than recent episodes.
"""

from __future__ import annotations

import logging
import random
from copy import deepcopy
from typing import Any

from open_range.builder.builder import render_template_payloads
from open_range.protocols import (
    BuildContext,
    EvidenceItem,
    ExploitStep,
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

_INJECTION_POINTS = {
    "sqli": "/legacy/search.php?q=",
    "idor": "/api/users/{id}",
    "path_traversal": "/download?file=",
    "command_injection": "/admin/diagnostics?host=",
    "ssrf": "/fetch?url=",
    "weak_creds": "ssh svc_app@host",
    "broken_auth": "/admin/login",
    "xss": "/search?q=",
}


class Mutator:
    """Orchestrate vuln mutation across resets.

    Tracks episode history and feeds it into the Builder's context so that
    each reset produces a genuinely different challenge.
    """

    def __init__(
        self,
        builder: SnapshotBuilder,
        max_retries: int = 3,
    ) -> None:
        """Initialize the mutator with a builder and retry limit.

        Args:
            builder: Any SnapshotBuilder implementation.
            max_retries: Maximum build attempts (passed through to builder).
        """
        self.builder = builder
        self.max_retries = max_retries
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

        if parent_snapshot is None:
            snapshot = await self.builder.build(manifest, context)
            snapshot = self._hydrate_root_snapshot(snapshot, manifest)
        else:
            snapshot = self._mutate_parent_snapshot(
                manifest=manifest,
                parent_snapshot=parent_snapshot,
                parent_snapshot_id=parent_snapshot_id,
                context=context,
            )

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

    def _hydrate_root_snapshot(
        self,
        snapshot: SnapshotSpec,
        manifest: dict[str, Any],
    ) -> SnapshotSpec:
        root = snapshot.model_copy(deep=True)
        topology = dict(root.topology)
        company = manifest.get("company", {}) if isinstance(manifest.get("company"), dict) else {}
        topology.setdefault("domain", company.get("domain", "acmecorp.local"))
        topology.setdefault("org_name", company.get("name", "AcmeCorp"))
        topology.setdefault("manifest_name", manifest.get("name", ""))
        topology.setdefault("difficulty", deepcopy(manifest.get("difficulty", {})))
        topology.setdefault("host_catalog", _build_host_catalog(manifest))
        topology.setdefault("host_details", {})
        topology.setdefault("dependency_edges", [])
        topology.setdefault("trust_edges", [])
        root.topology = topology
        root.lineage = LineageMetadata(
            manifest_id=str(manifest.get("name", "")),
            generation_depth=0,
            mutation_summary=["compile_base_snapshot"],
        )
        root.mutation_plan = None
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
        used_ids: set[str] = set()

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

        if structural_candidates:
            chosen = rng.choice(structural_candidates)
            ops.append(chosen)
            used_ids.add(chosen.mutation_id)

        security_candidates = []
        op = self._candidate_seed_vuln(manifest, snapshot, context, rng)
        if op is not None:
            security_candidates.append(op)
        op = self._candidate_add_benign_noise(snapshot, rng)
        if op is not None:
            security_candidates.append(op)

        if security_candidates:
            chosen = rng.choice(security_candidates)
            if chosen.mutation_id not in used_ids:
                ops.append(chosen)

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
        preferred = [v for v in context.weak_areas if v in allowed and v not in existing]
        remaining = [v for v in allowed if v not in existing]
        choices = preferred or remaining or allowed
        vuln_type = rng.choice(choices)

        host_catalog = snapshot.topology.get("host_catalog", {})
        host_candidates = list(host_catalog.keys()) if isinstance(host_catalog, dict) else []
        if not host_candidates:
            host_candidates = list(_existing_hosts(snapshot))
        if not host_candidates:
            return None
        host = str(rng.choice(host_candidates))
        service = ""
        if isinstance(host_catalog, dict):
            raw_catalog = host_catalog.get(host, {})
            if isinstance(raw_catalog, dict):
                raw_services = raw_catalog.get("services", [])
                if isinstance(raw_services, list) and raw_services:
                    service = str(raw_services[0])

        return MutationOp(
            mutation_id=f"mut_seed_vuln_{vuln_type}_{host}_{len(snapshot.truth_graph.vulns)+1}",
            op_type="seed_vuln",
            target_selector={"host": host},
            params={"vuln_type": vuln_type, "service": service},
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
                users.append(
                    {
                        "username": str(op.params.get("username", "")),
                        "password": str(op.params.get("password", "")),
                        "groups": deepcopy(op.params.get("groups", [])),
                        "hosts": deepcopy(op.params.get("hosts", [])),
                        "email": str(op.params.get("email", "")),
                        "full_name": str(op.params.get("full_name", "")),
                        "department": str(op.params.get("department", "")),
                        "role": str(op.params.get("role", "")),
                    }
                )

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
                vuln_type = str(op.params.get("vuln_type", "")).strip()
                host = op.target_selector["host"]
                service = str(op.params.get("service", "")).strip()
                vuln_id = f"{vuln_type}_{len(snapshot.truth_graph.vulns) + 1}"
                snapshot.truth_graph.vulns.append(
                    Vulnerability(
                        id=vuln_id,
                        type=vuln_type,
                        host=host,
                        service=service,
                        injection_point=_INJECTION_POINTS.get(vuln_type, f"/debug/{vuln_type}"),
                        vulnerable_code=f"// mutation-added {vuln_type} surface on {host}",
                        root_cause=f"Mutation introduced {vuln_type} on {host}",
                        blast_radius=f"Additional foothold on {host}",
                        remediation=f"Remove the {vuln_type} issue and review dependent trust paths",
                    )
                )
                snapshot.truth_graph.exploit_chain.append(
                    ExploitStep(
                        vuln_id=vuln_id,
                        command=f"probe {host} for {vuln_type}",
                        description=f"Use the new {vuln_type} foothold on {host}",
                    )
                )
                snapshot.evidence_spec.append(
                    EvidenceItem(
                        type="log_entry",
                        location=f"{host}:app.log",
                        pattern=f"Mutation-added {vuln_type} activity on {host}",
                    )
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


def _build_host_catalog(manifest: dict[str, Any]) -> dict[str, dict[str, Any]]:
    catalog: dict[str, dict[str, Any]] = {}
    for raw in manifest.get("topology", {}).get("hosts", []):
        if not isinstance(raw, dict):
            continue
        name = str(raw.get("name", "")).strip()
        if not name:
            continue
        catalog[name] = {
            "zone": str(raw.get("zone", "")),
            "services": deepcopy(raw.get("services", [])),
            "connects_to": deepcopy(raw.get("connects_to", [])),
        }
    return catalog


def _ensure_mutable_topology(
    topology: dict[str, Any],
    manifest: dict[str, Any],
) -> dict[str, Any]:
    updated = dict(topology)
    updated.setdefault("manifest_name", manifest.get("name", ""))
    updated.setdefault("difficulty", deepcopy(manifest.get("difficulty", {})))
    updated.setdefault("host_catalog", _build_host_catalog(manifest))
    updated.setdefault("host_details", {})
    updated.setdefault("dependency_edges", [])
    updated.setdefault("trust_edges", [])
    return updated


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
