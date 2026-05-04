"""Admitted snapshot and lineage records."""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from hashlib import sha256
from types import MappingProxyType
from typing import TYPE_CHECKING, cast

from openrange.core.admission import AdmissionReport
from openrange.core.errors import AdmissionError, StoreError
from openrange.core.graph import CheckScript, RuntimeBundle, WorldGraph
from openrange.core.manifest import Manifest
from openrange.core.pack import (
    Entrypoint,
    Task,
    Verifier,
    verifier_from_source,
)

if TYPE_CHECKING:
    from openrange.core.builder import BuildState


@dataclass(frozen=True, slots=True)
class LineageNode:
    id: str
    parent_id: str | None
    manifest: Mapping[str, object]
    pack: Mapping[str, object]
    prompt: str
    builder_summary: str
    touched_files: tuple[str, ...]
    curriculum: Mapping[str, object] | None = None

    def as_dict(self) -> dict[str, object]:
        return {
            "id": self.id,
            "parent_id": self.parent_id,
            "manifest": dict(self.manifest),
            "pack": dict(self.pack),
            "prompt": self.prompt,
            "builder_summary": self.builder_summary,
            "touched_files": list(self.touched_files),
            "curriculum": None if self.curriculum is None else dict(self.curriculum),
        }

    @classmethod
    def from_mapping(cls, data: Mapping[str, object]) -> LineageNode:
        node_id = data.get("id")
        parent_id = data.get("parent_id")
        manifest = data.get("manifest")
        pack = data.get("pack")
        prompt = data.get("prompt")
        summary = data.get("builder_summary")
        touched_files = data.get("touched_files")
        curriculum = data.get("curriculum")
        if not isinstance(node_id, str):
            raise StoreError("stored lineage id is invalid")
        if parent_id is not None and not isinstance(parent_id, str):
            raise StoreError("stored lineage parent is invalid")
        if not isinstance(manifest, Mapping) or not isinstance(pack, Mapping):
            raise StoreError("stored lineage inputs are invalid")
        if not isinstance(prompt, str) or not isinstance(summary, str):
            raise StoreError("stored lineage text is invalid")
        if not isinstance(touched_files, list) or not all(
            isinstance(item, str) for item in touched_files
        ):
            raise StoreError("stored lineage touched files are invalid")
        if curriculum is not None and not isinstance(curriculum, Mapping):
            raise StoreError("stored lineage curriculum is invalid")
        return cls(
            node_id,
            parent_id,
            MappingProxyType(dict(manifest)),
            MappingProxyType(dict(pack)),
            prompt,
            summary,
            tuple(touched_files),
            None if curriculum is None else MappingProxyType(dict(curriculum)),
        )


@dataclass(frozen=True, slots=True)
class Snapshot:
    """Admitted, frozen world.

    Stores both the canonical pipeline shape (``world_graph``, ``runtime``,
    ``feasibility_checks``, ``episode_checks``, ``admission_probe``) and
    the legacy projection (``world``, ``artifacts``, ``verifier_sources``,
    ``generated``) used by older snapshot consumers. The legacy fields
    are derived from the canonical ones at freeze time.
    """

    id: str
    manifest: Manifest
    world: Mapping[str, object]
    tasks: tuple[Task, ...]
    verifier_sources: Mapping[str, str]
    generated: Mapping[str, object]
    artifacts: Mapping[str, str]
    admission: AdmissionReport
    lineage: tuple[LineageNode, ...]
    # Canonical pipeline shape (Phase audit-fix #4):
    world_graph: WorldGraph = field(default_factory=WorldGraph)
    runtime: RuntimeBundle = field(default_factory=RuntimeBundle)
    feasibility_checks: tuple[CheckScript, ...] = ()
    episode_checks: tuple[CheckScript, ...] = ()
    admission_probe: Mapping[str, object] = field(default_factory=dict)

    def get_tasks(self) -> tuple[Task, ...]:
        return self.tasks

    def task(self, task_id: str) -> Task:
        for task in self.tasks:
            if task.id == task_id:
                return task
        raise KeyError(f"unknown task {task_id!r}")

    def verifier(self, task_id: str) -> Verifier:
        """Resolve the verifier callable for a task from its stored source."""
        task = self.task(task_id)
        try:
            source = self.verifier_sources[task.verifier_id]
        except KeyError as exc:
            raise StoreError(
                f"task {task_id!r} references unknown verifier {task.verifier_id!r}",
            ) from exc
        return verifier_from_source(source)

    def as_dict(self) -> dict[str, object]:
        return {
            "id": self.id,
            "manifest": self.manifest.as_dict(),
            "world": dict(self.world),
            "tasks": [task.as_dict() for task in self.tasks],
            "verifier_sources": dict(self.verifier_sources),
            "generated": dict(self.generated),
            "artifacts": dict(self.artifacts),
            "admission": self.admission.as_dict(),
            "lineage": [node.as_dict() for node in self.lineage],
            "world_graph": self.world_graph.as_dict(),
            "runtime": self.runtime.as_dict(),
            "feasibility_checks": [c.as_dict() for c in self.feasibility_checks],
            "episode_checks": [c.as_dict() for c in self.episode_checks],
            "admission_probe": dict(self.admission_probe),
        }

    @classmethod
    def from_mapping(cls, data: Mapping[str, object]) -> Snapshot:
        snapshot_id = data.get("id")
        manifest = data.get("manifest")
        world = data.get("world")
        tasks = data.get("tasks")
        verifier_sources = data.get("verifier_sources")
        generated = data.get("generated")
        artifacts = data.get("artifacts", {})
        admission = data.get("admission")
        lineage = data.get("lineage")
        if not isinstance(snapshot_id, str):
            raise StoreError("stored snapshot id is invalid")
        if not isinstance(manifest, Mapping) or not isinstance(world, Mapping):
            raise StoreError("stored snapshot manifest/world is invalid")
        if not isinstance(tasks, list):
            raise StoreError("stored tasks are invalid")
        if not isinstance(verifier_sources, Mapping):
            raise StoreError("stored verifier sources are invalid")
        if not isinstance(generated, Mapping):
            raise StoreError("stored generated artifacts are invalid")
        if not isinstance(artifacts, Mapping):
            raise StoreError("stored artifacts are invalid")
        if not isinstance(admission, Mapping) or not isinstance(lineage, list):
            raise StoreError("stored snapshot admission/lineage is invalid")
        if not all(isinstance(row, Mapping) for row in lineage):
            raise StoreError("stored lineage row is invalid")
        parsed_verifier_sources = {
            str(key): str(value) for key, value in verifier_sources.items()
        }
        parsed_tasks = tuple(task_from_mapping(row) for row in tasks)
        parsed_artifacts = {str(key): str(value) for key, value in artifacts.items()}
        # New canonical fields — present on snapshots written after the
        # audit-fix; defaulted to empty for older snapshots so loading
        # legacy JSON keeps working.
        graph_data = data.get("world_graph", {})
        runtime_data = data.get("runtime", {})
        feasibility_data = data.get("feasibility_checks", [])
        episode_data = data.get("episode_checks", [])
        probe_data = data.get("admission_probe", {})
        if not isinstance(graph_data, Mapping):
            raise StoreError("stored world_graph is invalid")
        if not isinstance(runtime_data, Mapping):
            raise StoreError("stored runtime is invalid")
        if not isinstance(feasibility_data, list):
            raise StoreError("stored feasibility_checks is invalid")
        if not isinstance(episode_data, list):
            raise StoreError("stored episode_checks is invalid")
        if not isinstance(probe_data, Mapping):
            raise StoreError("stored admission_probe is invalid")
        return cls(
            snapshot_id,
            Manifest.from_mapping(cast(Mapping[str, object], manifest)),
            MappingProxyType(dict(world)),
            parsed_tasks,
            MappingProxyType(parsed_verifier_sources),
            MappingProxyType(cast(Mapping[str, object], json_safe(generated))),
            MappingProxyType(parsed_artifacts),
            AdmissionReport.from_mapping(cast(Mapping[str, object], admission)),
            tuple(
                LineageNode.from_mapping(cast(Mapping[str, object], row))
                for row in lineage
            ),
            world_graph=WorldGraph.from_mapping(graph_data),
            runtime=RuntimeBundle.from_mapping(runtime_data),
            feasibility_checks=tuple(
                CheckScript.from_mapping(c) for c in feasibility_data
            ),
            episode_checks=tuple(
                CheckScript.from_mapping(c) for c in episode_data
            ),
            admission_probe=MappingProxyType(dict(probe_data)),
        )


def task_from_mapping(data: object) -> Task:
    """Deserialize a Task from its stored mapping form.

    Verifier resolution is the caller's responsibility (look up the
    source by ``verifier_id`` in the snapshot's ``verifier_sources``).
    """
    if not isinstance(data, Mapping):
        raise StoreError("stored task is invalid")
    task_id = data.get("id")
    instruction = data.get("instruction")
    entrypoints = data.get("entrypoints")
    verifier_id = data.get("verifier_id")
    if not isinstance(task_id, str) or not isinstance(instruction, str):
        raise StoreError("stored task id/instruction is invalid")
    if not isinstance(entrypoints, list) or not isinstance(verifier_id, str):
        raise StoreError("stored task entrypoints/verifier are invalid")
    if not all(isinstance(item, Mapping) for item in entrypoints):
        raise StoreError("stored entrypoint row is invalid")
    return Task(
        task_id,
        instruction,
        tuple(
            Entrypoint.from_mapping(cast(Mapping[str, object], item))
            for item in entrypoints
        ),
        verifier_id,
    )


def snapshot_hash(
    manifest: Manifest,
    *,
    world: Mapping[str, object],
    tasks: tuple[Task, ...],
    verifier_sources: Mapping[str, str],
    generated: Mapping[str, object],
    artifacts: Mapping[str, str],
    pack_version: str,
    parent_id: str | None,
) -> str:
    payload = {
        "manifest": manifest.as_dict(),
        "world": world,
        "tasks": [task.as_dict() for task in tasks],
        "verifier_sources": verifier_sources,
        "generated": generated,
        "artifacts": artifacts,
        "pack_version": pack_version,
        "parent_id": parent_id,
    }
    return sha256(stable_json(payload).encode()).hexdigest()[:16]


def stable_json(value: object) -> str:
    return json.dumps(json_safe(value), sort_keys=True, separators=(",", ":"))


def json_safe(value: object) -> object:
    if isinstance(value, Mapping):
        return {str(key): json_safe(item) for key, item in value.items()}
    if isinstance(value, tuple | list):
        return [json_safe(item) for item in value]
    return value


def freeze(state: BuildState) -> Snapshot:
    """Freeze a fully-admitted BuildState into a Snapshot."""
    if (
        state.world_graph is None
        or state.runtime is None
        or state.admission is None
    ):
        raise AdmissionError("cannot freeze snapshot before admission")
    parent_id = None if state.context.previous is None else state.context.previous.id
    world_dict = _world_dict_from_state(state)
    artifacts = state.runtime.files()
    verifier_sources = MappingProxyType(
        {check.id: check.source for check in state.episode_checks},
    )
    generated = _generated_view(state, world_dict, artifacts)
    summary = state.summary or f"Built {state.pack.id} world from pack source"
    touched = state.touched_files or tuple(sorted(artifacts))
    snapshot_id = snapshot_hash(
        state.manifest,
        world=world_dict,
        tasks=state.tasks,
        verifier_sources=verifier_sources,
        generated=generated,
        artifacts=artifacts,
        pack_version=state.pack.version,
        parent_id=parent_id,
    )
    lineage = LineageNode(
        snapshot_id,
        parent_id,
        state.manifest.as_dict(),
        state.pack.as_dict(),
        state.context.prompt,
        summary,
        touched,
        state.context.curriculum,
    )
    previous_lineage = (
        () if state.context.previous is None else state.context.previous.lineage
    )
    return Snapshot(
        snapshot_id,
        state.manifest,
        MappingProxyType(dict(world_dict)),
        state.tasks,
        verifier_sources,
        MappingProxyType(generated),
        artifacts,
        state.admission,
        (*previous_lineage, lineage),
        world_graph=state.world_graph,
        runtime=state.runtime,
        feasibility_checks=state.feasibility_checks,
        episode_checks=state.episode_checks,
        admission_probe=MappingProxyType(dict(state.admission_probe or {})),
    )


def _world_dict_from_state(state: BuildState) -> Mapping[str, object]:
    """Project the world graph back to a flat dict for snapshot.world.

    Delegates to ``pack.project_world`` so multi-node-type packs (cyber
    v1 surfacing the flag) get their pack-defined projection rather
    than the v0 default of "first node attrs".
    """
    if state.world_graph is None:
        return {}
    return MappingProxyType(dict(state.pack.project_world(state.world_graph)))


def _generated_view(
    state: BuildState,
    world: Mapping[str, object],
    artifacts: Mapping[str, str],
) -> Mapping[str, object]:
    """Build the legacy GeneratedArtifacts shape from new state fields."""
    pack_runtime: Mapping[str, object] = {}
    if state.runtime is not None and state.pack.dir is not None:
        try:
            descriptor = json.loads(
                (state.pack.dir / "pack.json").read_text(encoding="utf-8"),
            )
            if isinstance(descriptor, Mapping):
                rt = descriptor.get("runtime", {})
                if isinstance(rt, Mapping):
                    pack_runtime = MappingProxyType(dict(rt))
        except OSError:
            pack_runtime = MappingProxyType({})
    verifiers = [
        {"id": check.id, "task_id": check.task_id, "source": check.source}
        for check in state.episode_checks
    ]
    admission_rows: list[Mapping[str, object]] = []
    if state.admission_probe is not None:
        for check in state.feasibility_checks:
            admission_rows.append(
                {
                    "task_id": check.task_id,
                    "source": check.source,
                    "final_state": dict(state.admission_probe),
                },
            )
    return {
        "world": {
            "world": dict(world),
            "artifacts": dict(artifacts),
            "runtime": dict(pack_runtime),
        },
        "tasks": [task.as_dict() for task in state.tasks],
        "verifiers": verifiers,
        "admission": admission_rows,
    }
