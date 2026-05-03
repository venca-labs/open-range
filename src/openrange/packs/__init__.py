"""Bundled pack registry and built-in pack implementations."""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from types import MappingProxyType
from typing import TYPE_CHECKING

from openrange.core.builder_protocol import Builder
from openrange.core.errors import PackError
from openrange.core.graph import (
    NodeType,
    RuntimeArtifact,
    RuntimeBundle,
    WorldGraph,
    WorldSchema,
)
from openrange.core.manifest import Manifest
from openrange.core.pack import PACKS, Entrypoint, Pack

if TYPE_CHECKING:
    from openrange.core.builder import BuildState

CYBER_WEBAPP_ONTOLOGY = WorldSchema(
    node_types=(
        NodeType(
            name="webapp",
            attrs_schema=MappingProxyType(
                {
                    "service": str,
                    "title": str,
                    "flag": str,
                    "mode": str,
                    "difficulty": str,
                    "npc_count": int,
                },
            ),
        ),
    ),
)


class CyberWebappOffensePack(Pack):
    """Single-host vulnerable HTTP webapp scenarios.

    Phase 2 ontology: one ``webapp`` node carrying the LLM-populated
    parameters (service, title, flag, plus build-derived mode/difficulty/
    npc_count). The realizer copies the static pack source files
    (``app.py``, ``pack.json``) into runtime artifacts and builds the
    HTTP entrypoint the runtime binds to. Future iterations will enrich
    the ontology and have realize() generate ``app.py`` from the graph.
    """

    id = "cyber.webapp.offense"

    def __init__(self, dir: Path) -> None:
        self.dir = dir
        descriptor_path = dir / "pack.json"
        descriptor = json.loads(descriptor_path.read_text(encoding="utf-8"))
        if not isinstance(descriptor, Mapping):
            raise PackError("pack descriptor must be a JSON object")
        descriptor_id = descriptor.get("id")
        if descriptor_id is not None and descriptor_id != self.id:
            raise PackError("manifest pack id does not match pack source")
        version = descriptor.get("version")
        runtime = descriptor.get("runtime", {})
        if not isinstance(version, str):
            raise PackError("pack descriptor version must be a string")
        if not isinstance(runtime, Mapping):
            raise PackError("pack descriptor runtime must be an object")
        app = runtime.get("app")
        if not isinstance(app, str):
            raise PackError("pack runtime app must be a string")
        self.version = version
        self._runtime_app = app
        self._files = MappingProxyType(_read_pack_files(dir))

    @property
    def ontology(self) -> WorldSchema:
        return CYBER_WEBAPP_ONTOLOGY

    def default_builder(self) -> type[Builder] | None:
        from openrange.packs.cyber_offense_builder import CyberOffenseBuilder

        return CyberOffenseBuilder

    def run_feasibility_check(self, state: BuildState) -> Mapping[str, object]:
        from openrange.packs.cyber_offense_builder import run_admission_probe

        return run_admission_probe(state)

    def realize(self, graph: WorldGraph, manifest: Manifest) -> RuntimeBundle:
        webapp_nodes = graph.nodes_of("webapp")
        if not webapp_nodes:
            raise PackError("cyber.webapp.offense graph must include a webapp node")
        if len(webapp_nodes) > 1:
            raise PackError("cyber.webapp.offense expects exactly one webapp node")

        artifacts = tuple(
            RuntimeArtifact(
                id=path,
                kind="file",
                metadata=MappingProxyType({"path": path, "content": content}),
            )
            for path, content in self._files.items()
        )
        service = str(webapp_nodes[0].attrs.get("service", "webapp"))
        entrypoint = self._http_entrypoint(manifest, service=service)
        return RuntimeBundle(artifacts=artifacts, entrypoints=(entrypoint,))

    def _http_entrypoint(self, manifest: Manifest, *, service: str) -> Entrypoint:
        task_file = "OPENRANGE_TASK.json"
        result_file = "result.json"
        request_log = "requests.jsonl"
        return Entrypoint(
            "http",
            service,
            MappingProxyType(
                {
                    "mode": manifest.mode,
                    "artifact": self._runtime_app,
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
                    "request_log": request_log,
                    "result_schema": {
                        "type": "object",
                        "required": ["flag"],
                        "properties": {
                            "flag": {"type": "string", "world_field": "flag"},
                        },
                    },
                    "result_file": result_file,
                    "task_file": task_file,
                    "final_state": {
                        "result": {"kind": "json_file", "path": result_file},
                        "world": {"kind": "world"},
                        "requests": {"kind": "request_log", "path": request_log},
                    },
                },
            ),
        )


def _read_pack_files(pack_dir: Path) -> dict[str, str]:
    files: dict[str, str] = {}
    for path in sorted(pack_dir.rglob("*")):
        if path.is_file() and "__pycache__" not in path.parts:
            files[path.relative_to(pack_dir).as_posix()] = path.read_text(
                encoding="utf-8",
            )
    return files


def register_builtin_pack(pack: Pack) -> None:
    PACKS.register(pack)


register_builtin_pack(
    CyberWebappOffensePack(Path(__file__).parent / "cyber_webapp_offense"),
)
