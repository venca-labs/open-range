from __future__ import annotations

import json
import textwrap
from collections.abc import Mapping
from pathlib import Path
from typing import Any, cast

import pytest

import openrange as OR
from openrange.core import (
    AdmissionError,
    BuildContext,
    Manifest,
    ManifestError,
    PackError,
    PackRef,
    PackRegistry,
    PackSource,
    Snapshot,
    SnapshotStore,
    StoreError,
    admit,
    build,
    evolve,
    json_safe,
    stable_json,
    task_from_mapping,
)

MANIFEST = {
    "world": {"goal": "find the admin flag", "title": "Ops Portal"},
    "pack": {"id": "cyber.webapp.offense", "source": {"kind": "builtin"}},
    "npc": [{"id": "mentor", "kind": "scripted"}],
}


def test_builder_admits_snapshot_task_verifier_artifacts_and_lineage(
    tmp_path: Path,
) -> None:
    snapshot = build(
        MANIFEST,
        prompt="make it small",
        llm=builder_llm(tmp_path),
    )

    assert snapshot.manifest.pack.id == "cyber.webapp.offense"
    assert str(snapshot.lineage[0].pack["dir"]).endswith(
        "src/openrange/packs/cyber_webapp_offense",
    )
    assert snapshot.world["title"] == "Ops Portal"
    assert snapshot.world["flag"] == "ORANGE{webapp_admin_flag}"
    assert snapshot.artifacts["app.py"].startswith("from __future__")
    assert "pack.json" in snapshot.artifacts
    assert snapshot.admission.passed is True
    assert snapshot.admission.checks == (
        "world_present",
        "tasks_present",
        "verifier_probes",
    )
    task = snapshot.get_tasks()[0]
    entrypoint = task.entrypoints[0]
    generated_world = cast(Mapping[str, object], snapshot.generated["world"])
    generated_tasks = cast(list[Mapping[str, object]], snapshot.generated["tasks"])
    generated_verifiers = cast(
        list[Mapping[str, object]],
        snapshot.generated["verifiers"],
    )
    generated_admission_rows = cast(
        list[Mapping[str, object]],
        snapshot.generated["admission"],
    )
    generated_admission = generated_admission_rows[0]
    generated_final_state = cast(
        Mapping[str, object],
        generated_admission["final_state"],
    )
    assert task.id == "find_admin_flag"
    assert entrypoint.kind == "http"
    assert entrypoint.target == "webapp"
    assert entrypoint.metadata == {
        "artifact": "app.py",
        "argv": [
            "--host",
            "127.0.0.1",
            "--port",
            "0",
            "--flag",
            {"world": "flag"},
            "--log",
            {"run": "request_log"},
        ],
        "final_state": {
            "requests": {"kind": "request_log", "path": "requests.jsonl"},
            "result": {"kind": "json_file", "path": "result.json"},
            "world": {"kind": "world"},
        },
        "mode": "simulation",
        "request_log": "requests.jsonl",
        "result_schema": {
            "properties": {
                "flag": {"type": "string", "world_field": "flag"},
            },
            "required": ["flag"],
            "type": "object",
        },
        "result_file": "result.json",
        "task_file": "OPENRANGE_TASK.json",
    }
    assert task.instruction == generated_tasks[0]["instruction"]
    assert "def verify(state):" in snapshot.verifier_sources["admin_flag_found"]
    assert generated_world["world"] == snapshot.world
    assert generated_world["runtime"] == {
        "kind": "python.http",
        "app": "app.py",
    }
    assert generated_tasks[0] == task.as_dict()
    assert generated_verifiers[0] == {
        "id": task.verifier_id,
        "task_id": task.id,
        "source": snapshot.verifier_sources[task.verifier_id],
    }
    verifier_source = str(generated_verifiers[0]["source"])
    assert "app.py" not in verifier_source
    assert "pack_files" not in verifier_source
    assert "openrange.core" not in verifier_source
    assert generated_admission["task_id"] == task.id
    admission_source = str(generated_admission["source"])
    assert "def admission_state(interface):" in admission_source
    assert "http_get" in admission_source
    assert "import " not in admission_source
    assert "world.get" not in admission_source
    assert "app.py" not in admission_source
    assert "pack_files" not in admission_source
    assert "openrange.core" not in admission_source
    assert generated_final_state == {
        "result": {"flag": "ORANGE{webapp_admin_flag}"},
        "world": dict(snapshot.world),
        "requests": [],
    }
    assert task.verify(generated_final_state)["passed"]
    assert task.interface == task.entrypoints
    assert (
        task.verify(
            {
                "result": {"flag": "ORANGE{webapp_admin_flag}"},
                "world": {"flag": "ORANGE{webapp_admin_flag}"},
                "requests": (),
            },
        )["passed"]
        is True
    )
    assert (
        task.verify(
            {
                "result": {"flag": "wrong"},
                "world": {"flag": "ORANGE{webapp_admin_flag}"},
                "requests": (),
            },
        )["passed"]
        is False
    )
    assert snapshot.lineage[0].prompt == "make it small"
    assert snapshot.lineage[0].pack["id"] == "cyber.webapp.offense"
    serialized = json.dumps(snapshot.as_dict()).lower()
    assert "build_hook" not in serialized
    assert "seed_block" not in serialized
    assert "__openrange_seed" not in serialized
    assert snapshot.task(task.id) is task
    with pytest.raises(KeyError, match="unknown task"):
        snapshot.task("missing")


def test_builder_emits_dashboard_safe_steps_without_flag_leak(
    tmp_path: Path,
) -> None:
    events: list[tuple[str, Mapping[str, object]]] = []

    def record(step: str, data: Mapping[str, object]) -> None:
        events.append((step, dict(data)))

    snapshot = build(MANIFEST, llm=builder_llm(tmp_path), event_sink=record)
    steps = [step for step, _ in events]
    world_step = next(data for step, data in events if step == "world_generated")
    snapshot_step = next(data for step, data in events if step == "snapshot_created")
    world = cast(Mapping[str, object], world_step["world"])

    assert steps == [
        "build_started",
        "pack_resolved",
        "attempt_started",
        "world_generation_started",
        "world_generated",
        "task_generation_started",
        "task_generated",
        "verifier_generation_started",
        "verifier_generated",
        "admission_probe_started",
        "admission_probe_generated",
        "admission_started",
        "admission_passed",
        "snapshot_created",
    ]
    assert world["has_flag"] is True
    assert "flag" not in world
    assert snapshot_step["snapshot_id"] == snapshot.id
    assert "ORANGE{" not in json.dumps(json_safe(events))


def test_evolve_creates_child_lineage_and_changes_world(tmp_path: Path) -> None:
    llm = builder_llm(tmp_path)
    original = build(MANIFEST, llm=llm)
    evolved = evolve(
        original,
        {"edit": "harder"},
        prompt="make it harder",
        llm=llm,
    )

    assert evolved.id != original.id
    assert evolved.world["difficulty"] == "hard"
    assert evolved.world["previous_snapshot"] == original.id
    assert len(evolved.lineage) == 2
    assert evolved.lineage[1].parent_id == original.id
    assert evolved.lineage[1].curriculum == {"edit": "harder"}


def test_snapshot_store_round_trips_admitted_snapshot(tmp_path: Path) -> None:
    snapshot = build(MANIFEST, llm=builder_llm(tmp_path))
    store = SnapshotStore(tmp_path)

    path = store.save(snapshot)
    loaded = store.load(snapshot.id, OR.PACKS.resolve("cyber.webapp.offense"))

    assert path == tmp_path / f"{snapshot.id}.json"
    assert loaded.id == snapshot.id
    assert loaded.manifest.as_dict() == snapshot.manifest.as_dict()
    assert loaded.generated == snapshot.generated
    assert loaded.artifacts == snapshot.artifacts
    assert (
        loaded.tasks[0].verify(
            {
                "result": {"flag": "ORANGE{webapp_admin_flag}"},
                "world": {"flag": "ORANGE{webapp_admin_flag}"},
                "requests": (),
            },
        )["passed"]
        is True
    )


def test_manifest_loads_yaml_and_rejects_invalid_shapes(tmp_path: Path) -> None:
    path = tmp_path / "manifest.yaml"
    path.write_text(
        """
world:
  goal: exploit webapp
pack:
  id: cyber.webapp.offense
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
        "id": "cyber.webapp.offense",
        "source": {"kind": "builtin"},
        "options": {},
    }

    bad_yaml = tmp_path / "bad.yaml"
    bad_yaml.write_text("[]", encoding="utf-8")
    bad_inputs = [
        bad_yaml,
        {},
        {"world": [], "pack": {"id": "cyber.webapp.offense"}},
        {"world": {}, "pack": []},
        {"world": {}, "pack": {"id": ""}},
        {"world": {}, "pack": {"id": "cyber.webapp.offense", "source": []}},
        {
            "world": {},
            "pack": {"id": "cyber.webapp.offense", "source": {"kind": "bad"}},
        },
        {
            "world": {},
            "pack": {"id": "cyber.webapp.offense", "source": {"uri": 3}},
        },
        {"world": {}, "pack": {"id": "cyber.webapp.offense", "options": []}},
        {"world": {}, "pack": {"id": "cyber.webapp.offense"}, "mode": "fast"},
        {"world": {}, "pack": {"id": "cyber.webapp.offense"}, "npc": [1]},
    ]
    for bad in bad_inputs:
        with pytest.raises(ManifestError):
            Manifest.load(cast(Any, bad))


def test_pack_source_ref_registry_and_errors(tmp_path: Path) -> None:
    source = PackSource("git", "https://example.test/pack.git")
    ref = PackRef.from_mapping(
        {
            "id": "cyber.webapp.offense",
            "source": source.as_dict(),
            "options": {"scenario": "small"},
        },
    )
    registry = PackRegistry()

    assert ref.as_dict() == {
        "id": "cyber.webapp.offense",
        "source": {"kind": "git", "uri": "https://example.test/pack.git"},
        "options": {"scenario": "small"},
    }
    assert registry.ids() == ()
    with pytest.raises(PackError, match="unknown pack"):
        registry.resolve("missing")
    pack = OR.PACKS.resolve("cyber.webapp.offense")
    registry.register(pack)
    assert registry.ids() == ("cyber.webapp.offense",)
    assert registry.resolve("cyber.webapp.offense").as_dict() == pack.as_dict()
    snapshot = build(MANIFEST, llm=builder_llm(tmp_path))
    with pytest.raises(ManifestError, match="curriculum"):
        evolve(snapshot, cast(Any, []), registry=registry)
    with pytest.raises(PackError, match="source"):
        build(
            {"world": {}, "pack": {"id": pack.id, "source": {"kind": "git"}}},
            registry=registry,
        )
    with pytest.raises(PackError, match="required"):
        build(
            {"world": {}, "pack": {"id": pack.id, "source": {"kind": "path"}}},
            registry=registry,
        )

    copied = tmp_path / "copied-pack"
    copy_pack(pack.dir, copied)
    path_manifest = {
        "world": {"goal": "path pack"},
        "pack": {
            "id": "cyber.webapp.offense",
            "source": {"kind": "path", "uri": str(copied)},
        },
    }
    assert (
        build(
            path_manifest,
            llm=builder_llm(tmp_path),
            registry=registry,
        ).world["service"]
        == "webapp"
    )
    bad_descriptor = json.loads((copied / "pack.json").read_text(encoding="utf-8"))
    bad_descriptor["id"] = "other.pack"
    (copied / "pack.json").write_text(json.dumps(bad_descriptor), encoding="utf-8")
    with pytest.raises(PackError, match="does not match"):
        build(path_manifest, llm=builder_llm(tmp_path), registry=registry)


def test_pack_descriptor_validation(tmp_path: Path) -> None:
    """Constructing CyberWebappOffensePack validates its pack.json."""
    from openrange.packs import CyberWebappOffensePack

    pack = OR.PACKS.resolve("cyber.webapp.offense")
    rebuilt = CyberWebappOffensePack(pack.dir)
    assert rebuilt.id == "cyber.webapp.offense"
    assert rebuilt.version == pack.version

    invalid = tmp_path / "invalid"
    invalid.mkdir()
    (invalid / "pack.json").write_text("{", encoding="utf-8")
    with pytest.raises(json.JSONDecodeError):
        CyberWebappOffensePack(invalid)

    pid = "cyber.webapp.offense"
    for name, descriptor, expected_msg in [
        ("list", [], "JSON object"),
        ("missing_version", {"id": pid}, "version"),
        ("bad_runtime", {"id": pid, "version": "v", "runtime": []}, "runtime"),
        (
            "bad_runtime_app",
            {"id": pid, "version": "v", "runtime": {"app": 1}},
            "runtime app",
        ),
        (
            "wrong_id",
            {"id": "other.pack", "version": "v", "runtime": {"app": "app.py"}},
            "does not match",
        ),
    ]:
        pack_dir = tmp_path / name
        pack_dir.mkdir()
        (pack_dir / "pack.json").write_text(json.dumps(descriptor), encoding="utf-8")
        with pytest.raises(PackError, match=expected_msg):
            CyberWebappOffensePack(pack_dir)


def test_admission_rejects_empty_world_missing_tasks_and_failed_probe(
    tmp_path: Path,
) -> None:
    from dataclasses import replace as _replace

    good = build(MANIFEST, llm=builder_llm(tmp_path))
    pack = OR.PACKS.resolve("cyber.webapp.offense")
    base_state = OR.BuildState(
        manifest=good.manifest,
        pack=pack,
        builder=_NoopBuilder(),
        context=BuildContext(),
    )
    nonempty_graph = OR.WorldGraph(
        nodes=(OR.Node("webapp", "webapp", dict(good.world)),),
    )

    with pytest.raises(AdmissionError, match="world is empty"):
        admit(
            _replace(
                base_state,
                world_graph=OR.WorldGraph(),
                tasks=good.tasks,
                admission_probe={},
            ),
        )
    with pytest.raises(AdmissionError, match="no tasks generated"):
        admit(
            _replace(
                base_state,
                world_graph=nonempty_graph,
                tasks=(),
                admission_probe={},
            ),
        )
    with pytest.raises(AdmissionError, match="verifier did not pass"):
        admit(
            _replace(
                base_state,
                world_graph=nonempty_graph,
                tasks=good.tasks,
                admission_probe={
                    "result": {"flag": "wrong"},
                    "world": {"flag": "expected"},
                    "requests": [],
                },
            ),
        )


def test_store_rejects_missing_or_invalid_snapshots(tmp_path: Path) -> None:
    store = SnapshotStore(tmp_path)
    pack = OR.PACKS.resolve("cyber.webapp.offense")

    with pytest.raises(StoreError, match="not found"):
        store.load("missing", pack)

    bad_path = tmp_path / "bad.json"
    bad_path.write_text("{", encoding="utf-8")
    with pytest.raises(StoreError, match="not valid JSON"):
        store.load("bad", pack)

    non_mapping = tmp_path / "list.json"
    non_mapping.write_text("[]", encoding="utf-8")
    with pytest.raises(StoreError, match="must be a mapping"):
        store.load("list", pack)


def test_snapshot_from_mapping_rejects_invalid_shapes(tmp_path: Path) -> None:
    valid = build(MANIFEST, llm=builder_llm(tmp_path)).as_dict()
    lineage = cast(list[dict[str, object]], valid["lineage"])
    assert Snapshot.from_mapping(valid, generated_verifiers(tmp_path)).id == valid["id"]
    invalid_cases = [
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
        {
            **valid,
            "tasks": [
                {
                    "id": "task",
                    "instruction": "do",
                    "entrypoints": [],
                    "verifier_id": "missing",
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


def test_task_and_entrypoint_from_mapping_validation(tmp_path: Path) -> None:
    verifiers = generated_verifiers(tmp_path)
    with pytest.raises(StoreError, match="stored task"):
        task_from_mapping([], verifiers)
    with pytest.raises(StoreError, match="stored entrypoint"):
        task_from_mapping(
            {
                "id": "task",
                "instruction": "do",
                "entrypoints": [1],
                "verifier_id": "admin_flag_found",
            },
            verifiers,
        )
    with pytest.raises(StoreError, match="stored entrypoint"):
        task_from_mapping(
            {
                "id": "task",
                "instruction": "do",
                "entrypoints": [{"kind": 1}],
                "verifier_id": "admin_flag_found",
            },
            verifiers,
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
            verifiers,
        )


def test_builder_generation_error_paths(tmp_path: Path) -> None:
    with pytest.raises(ManifestError, match="max_repairs"):
        build(MANIFEST, llm=OR.CodexBackend(), max_repairs=0)
    failed_events: list[tuple[str, Mapping[str, object]]] = []
    with pytest.raises(PackError, match="complete"):
        build(
            MANIFEST,
            llm=object(),
            event_sink=lambda step, data: failed_events.append((step, data)),
        )
    assert failed_events[-1][0] == "build_failed"
    assert failed_events[-1][1]["error_type"] == "PackError"
    bad_verifier = executable(
        tmp_path,
        "bad_verifier_backend.py",
        """
        import json
        import sys
        from pathlib import Path

        output_path = Path(sys.argv[sys.argv.index("--output-last-message") + 1])
        prompt = json.loads(sys.stdin.read().split("\\n\\n", 1)[1])
        if "task" in prompt:
            output_path.write_text(
                json.dumps(
                    {
                        "verifier_source": "x = 1",
                        "admission_source": (
                            "def admission_state(interface):\\n    return {}\\n"
                        ),
                    },
                ),
                encoding="utf-8",
            )
        else:
            output_path.write_text(
                json.dumps(
                    {
                        "service": "webapp",
                        "title": "Ops Portal",
                        "flag": "ORANGE{webapp_admin_flag}",
                    },
                ),
                encoding="utf-8",
            )
        """,
    )
    with pytest.raises(AdmissionError, match="verifier source"):
        build(
            MANIFEST,
            llm=OR.CodexBackend(command=bad_verifier, model="local", timeout=5),
            max_repairs=1,
        )


def test_builder_retries_admission_with_feedback_to_llm(tmp_path: Path) -> None:
    command = executable(
        tmp_path,
        "feedback_backend.py",
        """
        import json
        import sys
        from pathlib import Path

        output_path = Path(sys.argv[sys.argv.index("--output-last-message") + 1])
        prompt = json.loads(sys.stdin.read().split("\\n\\n", 1)[1])
        if "task" in prompt:
            output_path.write_text(
                json.dumps(
                    {
                        "verifier_source": (
                            "def verify(state):\\n"
                            "    result = state.get('result', {})\\n"
                            "    world = state.get('world', {})\\n"
                            "    passed = result.get('flag') == world.get('flag')\\n"
                            "    passed = passed and world.get('flag') != ''\\n"
                            "    return {'passed': passed, "
                            "'score': 1.0 if passed else 0.0}\\n"
                        ),
                        "admission_source": (
                            "def admission_state(interface):\\n"
                            "    robots = interface['http_get']("
                            "'/robots.txt').decode()\\n"
                            "    path = ''\\n"
                            "    for line in robots.splitlines():\\n"
                            "        if line.startswith('Disallow:'):\\n"
                            "            path = line.split(':', 1)[1].strip()\\n"
                            "    data = interface['http_get_json'](path)\\n"
                            "    return {'result': {'flag': data['flag']}, "
                            "'requests': []}\\n"
                        ),
                    },
                ),
                encoding="utf-8",
            )
            raise SystemExit
        feedback = prompt["feedback"]
        with Path(__file__).with_name("attempts.jsonl").open(
            "a",
            encoding="utf-8",
        ) as handle:
            handle.write(json.dumps(len(feedback)) + "\\n")
        output_path.write_text(
            json.dumps(
                {
                    "service": "generated-webapp",
                    "title": "generated",
                    "flag": "" if not feedback else "ORANGE{fixed_by_feedback}",
                },
            ),
            encoding="utf-8",
        )
        """,
    )

    snapshot = build(
        MANIFEST,
        llm=OR.CodexBackend(command=command, model="local", timeout=5),
        max_repairs=2,
    )

    attempts = [
        json.loads(line)
        for line in (tmp_path / "attempts.jsonl")
        .read_text(
            encoding="utf-8",
        )
        .splitlines()
    ]
    assert attempts == [0, 1]
    assert snapshot.world["flag"] == "ORANGE{fixed_by_feedback}"
    assert snapshot.admission.passed is True


def test_builder_stops_feedback_after_max_tries(tmp_path: Path) -> None:
    pack = OR.PACKS.resolve("cyber.webapp.offense")
    copied = tmp_path / "bad-pack"
    copy_pack(pack.dir, copied)
    app = copied / "app.py"
    app.write_text(
        app.read_text(encoding="utf-8").replace(
            'json.dumps({"role": "admin", "flag": self.server.flag})',
            'json.dumps({"role": "admin"})',
        ),
        encoding="utf-8",
    )

    with pytest.raises(AdmissionError, match="after 1 tries"):
        build(
            {
                "world": {"goal": "path pack"},
                "pack": {
                    "id": "cyber.webapp.offense",
                    "source": {"kind": "path", "uri": str(copied)},
                },
            },
            llm=builder_llm(tmp_path),
            max_repairs=1,
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


def test_stable_json_is_sorted_and_public_api_exports(tmp_path: Path) -> None:
    assert stable_json({"b": 1, "a": 2}) == '{"a":2,"b":1}'
    assert OR.PACKS.resolve("cyber.webapp.offense").id == "cyber.webapp.offense"
    assert OR.ActorTurn("task", "actor", "agent", "target", {}).actor_kind == "agent"
    assert OR.PACKS.resolve("cyber.webapp.offense").version
    assert OR.CODEX_DEFAULT_MODEL == "gpt-5.3-codex-spark"
    assert OR.OpenRangeRun.__name__ == "OpenRangeRun"
    assert OR.RunConfig(Path("runs")).root == Path("runs")
    assert json.loads(
        json.dumps(build(MANIFEST, llm=builder_llm(tmp_path)).as_dict()),
    )["id"]


def copy_pack(source: Path, target: Path) -> None:
    target.mkdir()
    for path in source.iterdir():
        if path.is_file():
            (target / path.name).write_text(path.read_text(encoding="utf-8"))


def executable(tmp_path: Path, name: str, body: str) -> Path:
    path = tmp_path / name
    path.write_text(
        "#!/usr/bin/env python3\n" + textwrap.dedent(body),
        encoding="utf-8",
    )
    path.chmod(0o755)
    return path


def builder_llm(tmp_path: Path) -> OR.CodexBackend:
    command = executable(
        tmp_path,
        "builder_backend.py",
        """
        import json
        import sys
        from pathlib import Path

        output_path = Path(sys.argv[sys.argv.index("--output-last-message") + 1])
        prompt = json.loads(sys.stdin.read().split("\\n\\n", 1)[1])
        if "task" in prompt:
            output = {
                "verifier_source": (
                    "def verify(state):\\n"
                    "    result = state.get('result', {})\\n"
                    "    world = state.get('world', {})\\n"
                    "    submitted = result.get('flag')\\n"
                    "    expected = world.get('flag')\\n"
                    "    passed = submitted == expected and expected is not None\\n"
                    "    passed = passed and expected != ''\\n"
                    "    return {\\n"
                    "        'passed': passed,\\n"
                    "        'score': 1.0 if passed else 0.0,\\n"
                    "        'reason': 'admin flag submitted' if passed "
                    "else 'admin flag missing',\\n"
                    "    }\\n"
                ),
                "admission_source": (
                    "def admission_state(interface):\\n"
                    "    robots = interface['http_get']("
                    "'/robots.txt').decode()\\n"
                    "    path = ''\\n"
                    "    for line in robots.splitlines():\\n"
                    "        if line.startswith('Disallow:'):\\n"
                    "            path = line.split(':', 1)[1].strip()\\n"
                    "    data = interface['http_get_json'](path)\\n"
                    "    return {'result': {'flag': data['flag']}, "
                    "'requests': []}\\n"
                ),
            }
        else:
            manifest = prompt["manifest"]
            world = manifest["world"]
            output = {
                "service": world.get("service", "webapp"),
                "title": world.get("title", "OpenRange Web Portal"),
                "flag": world.get("flag", "ORANGE{webapp_admin_flag}"),
            }
        output_path.write_text(json.dumps(output), encoding="utf-8")
        """,
    )
    return OR.CodexBackend(command=command, model="local", timeout=5)


def generated_verifiers(tmp_path: Path) -> Mapping[str, OR.Verifier]:
    snapshot = build(MANIFEST, llm=builder_llm(tmp_path))
    return {
        verifier_id: OR.verifier_from_source(source)
        for verifier_id, source in snapshot.verifier_sources.items()
    }


class _NoopBuilder:
    """Builder stub used by tests that exercise admit() in isolation."""

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
        failures: tuple[str, ...],
    ) -> OR.BuildState:
        return state
