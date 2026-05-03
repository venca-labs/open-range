"""Synchronous build orchestration."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field, replace
from pathlib import Path
from types import MappingProxyType
from typing import TYPE_CHECKING

from openrange.core.admission import (
    AdmissionFailure,
    AdmissionReport,
    AdmissionResult,
    BuildFailed,
    admit,
    report_from_result,
)
from openrange.core.builder_protocol import Builder
from openrange.core.errors import AdmissionError, ManifestError, PackError
from openrange.core.graph import (
    CheckScript,
    RuntimeBundle,
    WorldGraph,
)
from openrange.core.manifest import Manifest
from openrange.core.pack import (
    PACKS,
    Pack,
    PackRegistry,
    Task,
    verifier_from_source,
)
from openrange.core.snapshot import Snapshot, freeze

if TYPE_CHECKING:
    from openrange.llm import LLMBackend

BuildEventSink = Callable[[str, Mapping[str, object]], object]


@dataclass(frozen=True, slots=True)
class BuildContext:
    prompt: str = ""
    llm: LLMBackend | None = None
    curriculum: Mapping[str, object] | None = None
    previous: Snapshot | None = None
    feedback: tuple[str, ...] = ()
    event_sink: BuildEventSink | None = None


@dataclass(frozen=True, slots=True)
class BuildState:
    """Accumulator threaded through the build pipeline.

    Each pipeline stage takes a BuildState and returns a new one with one
    more field populated, via ``dataclasses.replace``. Not a base class:
    domain-specific data belongs on Pack and Builder, not here.
    """

    manifest: Manifest
    pack: Pack
    builder: Builder
    context: BuildContext
    world_graph: WorldGraph | None = None
    runtime: RuntimeBundle | None = None
    tasks: tuple[Task, ...] = ()
    feasibility_checks: tuple[CheckScript, ...] = ()
    episode_checks: tuple[CheckScript, ...] = ()
    admission_probe: Mapping[str, object] | None = None
    admission: AdmissionReport | None = None
    summary: str = ""
    touched_files: tuple[str, ...] = field(default_factory=tuple)


def build(
    manifest: str | Path | Mapping[str, object] | Manifest,
    *,
    prompt: str = "",
    llm: LLMBackend | None = None,
    event_sink: BuildEventSink | None = None,
    registry: PackRegistry | None = None,
    max_repairs: int = 3,
) -> Snapshot:
    if max_repairs < 1:
        raise ManifestError("max_repairs must be at least 1")
    return _orchestrate(
        Manifest.load(manifest),
        BuildContext(prompt=prompt, llm=llm, event_sink=event_sink),
        _resolve_registry(registry),
        max_repairs,
    )


def evolve(
    snapshot: Snapshot,
    curriculum: Mapping[str, object],
    *,
    prompt: str = "",
    llm: LLMBackend | None = None,
    event_sink: BuildEventSink | None = None,
    registry: PackRegistry | None = None,
    max_repairs: int = 3,
) -> Snapshot:
    if max_repairs < 1:
        raise ManifestError("max_repairs must be at least 1")
    if not isinstance(curriculum, Mapping):
        raise ManifestError("curriculum must be a mapping")
    return _orchestrate(
        snapshot.manifest,
        BuildContext(
            prompt=prompt,
            llm=llm,
            curriculum=MappingProxyType(dict(curriculum)),
            previous=snapshot,
            event_sink=event_sink,
        ),
        _resolve_registry(registry),
        max_repairs,
    )


def _orchestrate(
    manifest: Manifest,
    context: BuildContext,
    registry: PackRegistry,
    max_repairs: int,
) -> Snapshot:
    emit_build_event(
        context,
        "build_started",
        pack_id=manifest.pack.id,
        mode=manifest.mode,
        prompt_present=bool(context.prompt),
        evolved=context.previous is not None,
    )
    try:
        pack = resolve_pack(manifest, registry)
        emit_build_event(
            context,
            "pack_resolved",
            pack_id=pack.id,
            pack_version=pack.version,
            pack_dir=str(pack.dir),
        )
        builder = _resolve_builder(pack, context)
        state = BuildState(
            manifest=manifest,
            pack=pack,
            builder=builder,
            context=context,
        )
        state = _build_with_repair(state, max_repairs=max_repairs)
        snapshot = freeze(state)
        emit_build_event(
            context,
            "snapshot_created",
            snapshot_id=snapshot.id,
            task_count=len(state.tasks),
            touched_files=list(state.touched_files or sorted(snapshot.artifacts)),
        )
        return snapshot
    except Exception as exc:
        emit_build_event(
            context,
            "build_failed",
            error_type=type(exc).__name__,
            error=str(exc),
        )
        raise


def _resolve_registry(registry: PackRegistry | None) -> PackRegistry:
    if registry is None:
        import openrange.packs as _packs  # noqa: F401

        return PACKS
    return registry


def resolve_pack(manifest: Manifest, registry: PackRegistry) -> Pack:
    source = manifest.pack.source
    if source.kind == "builtin":
        return registry.resolve(manifest.pack.id)
    if source.kind == "path":
        if source.uri is None:
            raise PackError("'pack.source.uri' is required for path packs")
        path = Path(source.uri).expanduser().resolve()
        return _instantiate_path_pack(manifest.pack.id, path)
    raise PackError(f"unsupported pack source {source.kind!r}")


def _instantiate_path_pack(pack_id: str, path: Path) -> Pack:
    """Resolve a path-loaded pack to its concrete Pack subclass.

    Phase 7 replaces this lookup with an entry-point-based plugin registry.
    """
    if pack_id == "cyber.webapp.offense":
        from openrange.packs import CyberWebappOffensePack

        pack = CyberWebappOffensePack(path)
        if pack.id != pack_id:
            raise PackError("manifest pack id does not match pack source")
        return pack
    raise PackError(f"unsupported pack id for path source: {pack_id!r}")


def _resolve_builder(pack: Pack, context: BuildContext) -> Builder:
    builder = pack.default_builder(context)
    if builder is None:
        raise PackError(f"pack {pack.id!r} has no default builder")
    return builder


def _build_with_repair(state: BuildState, *, max_repairs: int) -> BuildState:
    last_result = AdmissionResult(accepted=False)
    for attempt in range(1, max_repairs + 1):
        emit_build_event(state.context, "attempt_started", attempt=attempt)
        try:
            attempt_state = _generate_pipeline(state)
            attempt_state = _run_admission_probe(attempt_state)
            emit_build_event(state.context, "admission_started", attempt=attempt)
            result = admit(attempt_state)
        except AdmissionError as exc:
            attempt_state = state
            result = AdmissionResult(
                accepted=False,
                failures=(
                    AdmissionFailure(reason=str(exc), stage="generation"),
                ),
            )
        last_result = result
        if result.accepted:
            emit_build_event(
                state.context,
                "admission_passed",
                attempt=attempt,
                checks=list(result.checks),
            )
            return replace(
                attempt_state,
                admission=report_from_result(result),
            )
        emit_build_event(
            state.context,
            "admission_failed",
            attempt=attempt,
            failures=[
                {
                    "reason": failure.reason,
                    "stage": failure.stage,
                    "task_id": failure.task_id,
                }
                for failure in result.failures
            ],
        )
        state = state.builder.repair(attempt_state, result.failures)
        state = replace(
            state,
            context=replace(
                state.context,
                feedback=(
                    *state.context.feedback,
                    *(
                        admission_feedback(attempt, failure)
                        for failure in result.failures
                    ),
                ),
            ),
        )
    raise BuildFailed(last_result, attempts=max_repairs)


def _generate_pipeline(state: BuildState) -> BuildState:
    state = state.builder.generate_world_graph(state)
    state = _realize(state)
    state = state.builder.generate_tasks(state)
    state = state.builder.generate_feasibility_checks(state)
    state = state.builder.generate_episode_checks(state)
    state = _attach_verifiers(state)
    return state


def _realize(state: BuildState) -> BuildState:
    if state.world_graph is None:
        raise PackError("world_graph must be set before realize")
    bundle = state.pack.realize(state.world_graph, state.manifest)
    return replace(state, runtime=bundle)


def _attach_verifiers(state: BuildState) -> BuildState:
    """Bind episode-check verifier callables to their Task objects."""
    if not state.tasks or not state.episode_checks:
        return state
    by_id = {check.id: check for check in state.episode_checks}
    bound: list[Task] = []
    for task in state.tasks:
        check = by_id.get(task.verifier_id)
        if check is None:
            raise PackError(
                f"task {task.id!r} has no episode check {task.verifier_id!r}",
            )
        verifier = verifier_from_source(check.source)
        bound.append(
            Task(
                id=task.id,
                instruction=task.instruction,
                entrypoints=task.entrypoints,
                verifier_id=task.verifier_id,
                verify=verifier,
            ),
        )
    return replace(state, tasks=tuple(bound))


def _run_admission_probe(state: BuildState) -> BuildState:
    """Execute feasibility checks against the realized world.

    The probe captures runtime state that the episode-check verifiers run
    against during admission. Delegated to the runtime backing for the
    task's entrypoint kind, so Core stays domain-agnostic.
    """
    if not state.feasibility_checks or state.runtime is None or not state.tasks:
        return state
    import tempfile

    from openrange.core.runtime_backing import RUNTIME_BACKINGS, BackingContext

    task = state.tasks[0]
    feasibility = state.feasibility_checks[0]
    entrypoint = task.entrypoints[0]
    backing = RUNTIME_BACKINGS.require(entrypoint.kind)

    emit_build_event(state.context, "admission_probe_started", task_id=task.id)
    with tempfile.TemporaryDirectory() as tmp:
        running = backing.start(
            entrypoint,
            state.runtime.files(),
            _world_dict_from_state(state),
            BackingContext(episode_id=f"probe-{task.id}", workdir=Path(tmp)),
        )
        try:
            probe = dict(backing.run_check(running, feasibility.source))
        except Exception as exc:
            raise AdmissionError(
                "feasibility check failed against realized world",
            ) from exc
        finally:
            backing.stop(running)
    # Augment probe with the world snapshot, matching the legacy shape
    # episode verifiers expect.
    world_key = _final_state_key_for_world(entrypoint)
    if world_key is not None:
        probe[world_key] = _world_dict_from_state(state)
    emit_build_event(
        state.context,
        "admission_probe_generated",
        task_id=task.id,
    )
    return replace(state, admission_probe=MappingProxyType(probe))


def _world_dict_from_state(state: BuildState) -> dict[str, object]:
    if state.world_graph is None or not state.world_graph.nodes:
        return {}
    return dict(state.world_graph.nodes[0].attrs)


def _final_state_key_for_world(entrypoint: object) -> str | None:
    metadata = getattr(entrypoint, "metadata", {})
    final_state = metadata.get("final_state") if isinstance(metadata, Mapping) else None
    if not isinstance(final_state, Mapping):
        return None
    for name, spec in final_state.items():
        if isinstance(spec, Mapping) and spec.get("kind") == "world":
            return str(name)
    return None


def admission_feedback(attempt: int, failure: AdmissionFailure) -> str:
    return f"attempt {attempt} failed admission ({failure.stage}): {failure.reason}"


def emit_build_event(
    context: BuildContext,
    step: str,
    **data: object,
) -> None:
    if context.event_sink is None:
        return
    context.event_sink(step, MappingProxyType(dict(data)))
