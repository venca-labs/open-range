"""Core-plumbing tests against the v1 cyber pack.

Tests focus on what's domain-agnostic: manifest validation, snapshot
serialization, task / entrypoint shape validation, registry
discovery, custom builder routing, admit() failure modes. End-to-end
v1 build/episode behavior lives in ``test_v1_episode.py`` and
``test_v1_snapshot_round_trip.py``.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import replace as _replace
from pathlib import Path
from typing import Any, cast

import pytest

import openrange as OR
from openrange.core import (
    BuildContext,
    Manifest,
    ManifestError,
    PackRef,
    PackRegistry,
    PackSource,
    Snapshot,
    SnapshotStore,
    StoreError,
    admit,
    build,
    evolve,
    stable_json,
    task_from_mapping,
)

V1_MANIFEST: dict[str, object] = {
    "world": {"goal": "find the admin flag"},
    "pack": {"id": "cyber.webapp.offense.v1", "source": {"kind": "builtin"}},
}


# ---------------------------------------------------------------------------
# Manifest validation
# ---------------------------------------------------------------------------


def test_manifest_loads_yaml_and_rejects_invalid_shapes(tmp_path: Path) -> None:
    path = tmp_path / "manifest.yaml"
    path.write_text(
        """
world:
  goal: exploit webapp
pack:
  id: cyber.webapp.offense.v1
mode: emulation
npc:
  - id: helper
""",
        encoding="utf-8",
    )

    manifest = Manifest.load(path)

    assert Manifest.load(manifest) is manifest
    assert manifest.mode == "emulation"
    assert manifest.npc == ({"id": "helper"},)
    assert manifest.as_dict()["pack"] == {
        "id": "cyber.webapp.offense.v1",
        "source": {"kind": "builtin"},
        "options": {},
    }

    bad_yaml = tmp_path / "bad.yaml"
    bad_yaml.write_text("[]", encoding="utf-8")
    bad_inputs = [
        bad_yaml,
        {},
        {"world": [], "pack": {"id": "cyber.webapp.offense.v1"}},
        {"world": {}, "pack": []},
        {"world": {}, "pack": {"id": ""}},
        {"world": {}, "pack": {"id": "cyber.webapp.offense.v1", "source": []}},
        {
            "world": {},
            "pack": {"id": "cyber.webapp.offense.v1", "source": {"kind": "bad"}},
        },
        {
            "world": {},
            "pack": {"id": "cyber.webapp.offense.v1", "source": {"uri": 3}},
        },
        {"world": {}, "pack": {"id": "cyber.webapp.offense.v1", "options": []}},
        {"world": {}, "pack": {"id": "cyber.webapp.offense.v1"}, "mode": "fast"},
        {"world": {}, "pack": {"id": "cyber.webapp.offense.v1"}, "npc": [1]},
    ]
    for bad in bad_inputs:
        with pytest.raises(ManifestError):
            Manifest.load(cast(Any, bad))


# ---------------------------------------------------------------------------
# Pack source / registry shapes
# ---------------------------------------------------------------------------


def test_pack_source_ref_round_trip() -> None:
    source = PackSource("git", "https://example.test/pack.git")
    ref = PackRef.from_mapping(
        {
            "id": "cyber.webapp.offense.v1",
            "source": source.as_dict(),
            "options": {"flavor": "small"},
        },
    )
    assert ref.source.kind == "git"
    assert ref.options["flavor"] == "small"
    rebuilt = PackRef.from_mapping(ref.as_dict())
    assert rebuilt == ref


def test_v1_pack_resolves_from_global_registry() -> None:
    pack = OR.PACKS.resolve("cyber.webapp.offense.v1")
    assert pack.id == "cyber.webapp.offense.v1"
    assert pack.version


# ---------------------------------------------------------------------------
# Snapshot serialization
# ---------------------------------------------------------------------------


def test_store_rejects_missing_or_invalid_snapshots(tmp_path: Path) -> None:
    store = SnapshotStore(tmp_path)

    with pytest.raises(StoreError, match="not found"):
        store.load("missing")

    bad_path = tmp_path / "bad.json"
    bad_path.write_text("{", encoding="utf-8")
    with pytest.raises(StoreError, match="not valid JSON"):
        store.load("bad")

    non_mapping = tmp_path / "list.json"
    non_mapping.write_text("[]", encoding="utf-8")
    with pytest.raises(StoreError, match="must be a mapping"):
        store.load("list")


def test_snapshot_from_mapping_rejects_invalid_shapes() -> None:
    valid = build(V1_MANIFEST).as_dict()
    lineage = cast(list[dict[str, object]], valid["lineage"])
    assert Snapshot.from_mapping(valid).id == valid["id"]
    invalid_cases: list[Mapping[str, object]] = [
        {"id": 1},
        {**valid, "manifest": []},
        {**valid, "tasks": {}},
        {**valid, "verifier_sources": []},
        {**valid, "generated": []},
        {**valid, "artifacts": []},
        {**valid, "admission": []},
        {**valid, "lineage": {}},
        {**valid, "lineage": [1]},
        {**valid, "tasks": [1]},
        {**valid, "tasks": [{"id": 1}]},
        {
            **valid,
            "tasks": [
                {
                    "id": "task",
                    "instruction": "do",
                    "entrypoints": {},
                    "verifier_id": "admin_flag_found",
                },
            ],
        },
        {**valid, "admission": {"passed": "yes"}},
        {**valid, "admission": {"passed": True, "checks": [1]}},
        {
            **valid,
            "admission": {
                "passed": True,
                "checks": [],
                "verifier_results": [],
            },
        },
        {
            **valid,
            "admission": {
                "passed": True,
                "checks": [],
                "verifier_results": {},
                "errors": [1],
            },
        },
        {**valid, "lineage": [{"id": 1}]},
        {**valid, "lineage": [{**lineage[0], "parent_id": 1}]},
        {**valid, "lineage": [{**lineage[0], "manifest": []}]},
        {**valid, "lineage": [{**lineage[0], "prompt": 1}]},
        {**valid, "lineage": [{**lineage[0], "touched_files": [1]}]},
        {**valid, "lineage": [{**lineage[0], "curriculum": []}]},
    ]
    for invalid in invalid_cases:
        with pytest.raises(StoreError):
            Snapshot.from_mapping(cast(Mapping[str, object], invalid))


def test_task_and_entrypoint_from_mapping_validation() -> None:
    with pytest.raises(StoreError, match="stored task"):
        task_from_mapping([])  # type: ignore[arg-type]
    with pytest.raises(StoreError, match="stored entrypoint"):
        task_from_mapping(
            {
                "id": "task",
                "instruction": "do",
                "entrypoints": [1],
                "verifier_id": "admin_flag_found",
            },
        )
    with pytest.raises(StoreError, match="stored entrypoint"):
        task_from_mapping(
            {
                "id": "task",
                "instruction": "do",
                "entrypoints": [{"kind": 1}],
                "verifier_id": "admin_flag_found",
            },
        )
    with pytest.raises(StoreError, match="metadata"):
        task_from_mapping(
            {
                "id": "task",
                "instruction": "do",
                "entrypoints": [
                    {"kind": "state", "target": "x", "metadata": []},
                ],
                "verifier_id": "admin_flag_found",
            },
        )


def test_verifier_source_validation() -> None:
    with pytest.raises(StoreError, match="verifier source is invalid"):
        OR.verifier_from_source("raise RuntimeError('bad')")
    with pytest.raises(StoreError, match="define verify"):
        OR.verifier_from_source("x = 1")
    verifier = OR.verifier_from_source("def verify(state):\n    return []\n")
    with pytest.raises(StoreError, match="invalid result"):
        verifier({})
    with pytest.raises(StoreError, match="admission source is invalid"):
        OR.admission_state_from_source("raise RuntimeError('bad')")
    with pytest.raises(StoreError, match="define admission_state"):
        OR.admission_state_from_source("x = 1")
    admission_state = OR.admission_state_from_source(
        "def admission_state(world):\n    return []\n",
    )
    with pytest.raises(StoreError, match="invalid final state"):
        admission_state({})


# ---------------------------------------------------------------------------
# Build / evolve flow
# ---------------------------------------------------------------------------


def test_build_admits_v1_snapshot_with_lineage() -> None:
    snapshot = build(V1_MANIFEST)
    assert snapshot.manifest.pack.id == "cyber.webapp.offense.v1"
    assert snapshot.admission.passed is True
    assert len(snapshot.lineage) == 1
    assert snapshot.lineage[0].parent_id is None
    assert "app.py" in snapshot.artifacts


def test_evolve_creates_child_lineage() -> None:
    parent = build(V1_MANIFEST)
    child = evolve(parent, curriculum={"patch": []})
    assert len(child.lineage) == 2
    assert child.lineage[-1].parent_id == parent.id
    assert child.id != parent.id


def test_build_max_repairs_must_be_positive() -> None:
    with pytest.raises(ManifestError, match="max_repairs"):
        build(V1_MANIFEST, max_repairs=0)


# ---------------------------------------------------------------------------
# admit() failure modes
# ---------------------------------------------------------------------------


class _NoopBuilder:
    """Builder stub for tests that exercise admit() in isolation."""

    def generate_world_graph(self, state: OR.BuildState) -> OR.BuildState:
        return state

    def generate_tasks(self, state: OR.BuildState) -> OR.BuildState:
        return state

    def generate_feasibility_checks(self, state: OR.BuildState) -> OR.BuildState:
        return state

    def generate_episode_checks(self, state: OR.BuildState) -> OR.BuildState:
        return state

    def repair(
        self,
        state: OR.BuildState,
        failures: tuple[Any, ...],
    ) -> OR.BuildState:
        return state


def test_admit_returns_structured_failures() -> None:
    good = build(V1_MANIFEST)
    pack = OR.PACKS.resolve("cyber.webapp.offense.v1")
    base_state = OR.BuildState(
        manifest=good.manifest,
        pack=pack,
        builder=cast(Any, _NoopBuilder()),
        context=BuildContext(),
    )

    empty_world_result = admit(
        _replace(
            base_state,
            world_graph=OR.WorldGraph(),
            tasks=good.tasks,
            admission_probe={},
        ),
    )
    assert empty_world_result.accepted is False
    assert any("world is empty" in f.reason for f in empty_world_result.failures)
    assert all(f.stage == "world" for f in empty_world_result.failures)

    no_tasks_result = admit(
        _replace(
            base_state,
            world_graph=good.world_graph,
            tasks=(),
            admission_probe={},
        ),
    )
    assert no_tasks_result.accepted is False
    assert any("no tasks generated" in f.reason for f in no_tasks_result.failures)

    episode_check = OR.CheckScript(
        id=good.tasks[0].verifier_id,
        task_id=good.tasks[0].id,
        kind="episode",
        source=good.verifier_sources[good.tasks[0].verifier_id],
    )
    bad_verifier_result = admit(
        _replace(
            base_state,
            world_graph=good.world_graph,
            tasks=good.tasks,
            episode_checks=(episode_check,),
            admission_probe={
                "result": {"flag": "wrong"},
                "world": {"flag": "expected"},
                "requests": [],
            },
        ),
    )
    assert bad_verifier_result.accepted is False
    assert all(f.stage == "verifier" for f in bad_verifier_result.failures)
    assert all(f.task_id == good.tasks[0].id for f in bad_verifier_result.failures)
    assert bad_verifier_result.failures[0].details


# ---------------------------------------------------------------------------
# Registry discovery via entry points
# ---------------------------------------------------------------------------


class _TrivialPack(OR.Pack):
    """Minimal Pack stub for entry-point registration tests."""

    id = "external.test_pack"
    version = "0.0.0"

    def __init__(self, dir: Path | None = None) -> None:
        del dir
        self.dir = None

    @property
    def ontology(self) -> OR.WorldSchema:
        return OR.WorldSchema()

    def realize(self, graph: OR.WorldGraph, manifest: Manifest) -> OR.RuntimeBundle:
        del graph, manifest
        return OR.RuntimeBundle()


def test_pack_registry_discovers_via_entry_points(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from openrange.core.pack import PACK_ENTRY_POINT_GROUP

    fake_ep = type(
        "FakeEntryPoint",
        (),
        {
            "name": "external.test_pack",
            "value": "test:_TrivialPack",
            "load": lambda self: _TrivialPack,
        },
    )()

    def fake_entry_points(*, group: str) -> list[object]:
        if group == PACK_ENTRY_POINT_GROUP:
            return [fake_ep]
        return []

    monkeypatch.setattr("importlib.metadata.entry_points", fake_entry_points)

    registry = PackRegistry()
    assert registry.ids() == ()
    registry.discover()
    assert "external.test_pack" in registry.ids()
    assert isinstance(registry.resolve("external.test_pack"), _TrivialPack)


def test_builder_registry_discovers_via_entry_points(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from openrange.core.builder_protocol import (
        BUILDER_ENTRY_POINT_GROUP,
        Builder,
        BuilderRegistry,
    )

    construction_log: list[str] = []

    class _ExternalBuilder(Builder):
        def generate_world_graph(self, state: OR.BuildState) -> OR.BuildState:
            return state

        def generate_tasks(self, state: OR.BuildState) -> OR.BuildState:
            return state

        def generate_feasibility_checks(
            self,
            state: OR.BuildState,
        ) -> OR.BuildState:
            return state

        def generate_episode_checks(self, state: OR.BuildState) -> OR.BuildState:
            return state

    def factory(context: OR.BuildContext) -> Builder:
        construction_log.append(f"prompt={context.prompt!r}")
        return _ExternalBuilder()

    fake_ep = type(
        "FakeEntryPoint",
        (),
        {
            "name": "external.builder",
            "value": "test:factory",
            "load": lambda self: factory,
        },
    )()

    def fake_entry_points(*, group: str) -> list[object]:
        if group == BUILDER_ENTRY_POINT_GROUP:
            return [fake_ep]
        return []

    monkeypatch.setattr("importlib.metadata.entry_points", fake_entry_points)

    registry = BuilderRegistry()
    assert registry.ids() == ()
    registry.discover()
    assert "external.builder" in registry.ids()

    builder = registry.resolve("external.builder", BuildContext(prompt="hello"))
    assert isinstance(builder, _ExternalBuilder)
    assert construction_log == ["prompt='hello'"]


# ---------------------------------------------------------------------------
# Custom builder routing
# ---------------------------------------------------------------------------


def test_manifest_builder_routes_through_BUILDERS() -> None:
    """``manifest.builder`` opts into a registered factory over the pack default."""
    from openrange.core.builder_protocol import BUILDERS, Builder

    invoked: list[str] = []

    class _SentinelError(Exception):
        pass

    class _ManifestBuilder(Builder):
        def generate_world_graph(self, state: OR.BuildState) -> OR.BuildState:
            invoked.append("world")
            raise _SentinelError("custom builder reached")

        def generate_tasks(self, state: OR.BuildState) -> OR.BuildState:
            return state

        def generate_feasibility_checks(
            self,
            state: OR.BuildState,
        ) -> OR.BuildState:
            return state

        def generate_episode_checks(self, state: OR.BuildState) -> OR.BuildState:
            return state

    BUILDERS.register("test.manifest_builder", lambda ctx: _ManifestBuilder())
    try:
        manifest = {**V1_MANIFEST, "builder": "test.manifest_builder"}
        with pytest.raises(_SentinelError, match="custom builder reached"):
            build(manifest, max_repairs=1)
    finally:
        BUILDERS._factories.pop("test.manifest_builder", None)  # noqa: SLF001

    assert invoked == ["world"]


def test_custom_builder_repair_receives_structured_failures() -> None:
    """``Builder.repair`` is called with ``tuple[AdmissionFailure, ...]``."""
    from openrange.core.admission import AdmissionFailure, BuildFailed
    from openrange.core.builder_protocol import Builder

    captured_failures: list[tuple[AdmissionFailure, ...]] = []

    class _NoTasksBuilder(Builder):
        def generate_world_graph(self, state: OR.BuildState) -> OR.BuildState:
            graph = OR.WorldGraph(
                nodes=(OR.Node("placeholder", "host", {}),),
            )
            return _replace(state, world_graph=graph)

        def generate_tasks(self, state: OR.BuildState) -> OR.BuildState:
            # Forced failure: admit() will reject for "no tasks generated".
            return state

        def generate_feasibility_checks(self, state: OR.BuildState) -> OR.BuildState:
            return state

        def generate_episode_checks(self, state: OR.BuildState) -> OR.BuildState:
            return state

        def repair(
            self,
            state: OR.BuildState,
            failures: tuple[AdmissionFailure, ...],
        ) -> OR.BuildState:
            captured_failures.append(failures)
            return state

    class _NoOpPack(OR.Pack):
        id = "test.repair_pack"
        version = "0.0.0"

        def __init__(self, dir: Path | None = None) -> None:
            del dir
            self.dir = None

        @property
        def ontology(self) -> OR.WorldSchema:
            return OR.WorldSchema()

        def realize(
            self,
            graph: OR.WorldGraph,
            manifest: Manifest,
        ) -> OR.RuntimeBundle:
            del graph, manifest
            return OR.RuntimeBundle()

        def default_builder(self, context: BuildContext) -> Builder | None:
            del context
            return _NoTasksBuilder()

    custom_registry = OR.PackRegistry()
    custom_registry.register(_NoOpPack())

    manifest = {
        "world": {},
        "pack": {"id": "test.repair_pack", "source": {"kind": "builtin"}},
    }
    with pytest.raises(BuildFailed) as exc_info:
        build(manifest, registry=custom_registry, max_repairs=2)

    assert exc_info.value.attempts == 2
    assert len(captured_failures) >= 1
    for failures in captured_failures:
        assert failures
        assert all(isinstance(f, AdmissionFailure) for f in failures)


# ---------------------------------------------------------------------------
# Public API surface sanity
# ---------------------------------------------------------------------------


def test_stable_json_is_sorted() -> None:
    assert stable_json({"b": 1, "a": 2}) == '{"a":2,"b":1}'


def test_public_api_exports_smoke() -> None:
    """Top-level ``openrange`` package surfaces the names users actually use."""
    assert OR.PACKS.resolve("cyber.webapp.offense.v1").id == "cyber.webapp.offense.v1"
    assert OR.ActorTurn("task", "actor", "agent", "target", {}).actor_kind == "agent"
    assert OR.OpenRangeRun.__name__ == "OpenRangeRun"
    assert OR.RunConfig(Path("runs")).root == Path("runs")
    snapshot = build(V1_MANIFEST)
    assert json.loads(json.dumps(snapshot.as_dict()))["id"] == snapshot.id
