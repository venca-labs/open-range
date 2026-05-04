"""HTTP entrypoint metadata for the v1 codegen-realized runtime.

The realized ``app.py`` runs as a single Python subprocess via the
built-in ``HTTPBacking``. This module owns the metadata schema the
backing reads to spawn the process: argv template, request log,
result/task file paths, final-state collection spec.
"""

from __future__ import annotations

from types import MappingProxyType

from openrange import Entrypoint, Manifest


def http_entrypoint(manifest: Manifest) -> Entrypoint:
    """Build the HTTP ``Entrypoint`` for a realized v1 app.

    The argv carries ``--host``/``--port``/``--log`` only — the flag
    is baked into the generated ``app.py`` source by codegen, not
    passed at runtime.
    """
    task_file = "OPENRANGE_TASK.json"
    result_file = "result.json"
    request_log = "requests.jsonl"
    return Entrypoint(
        "http",
        "web",
        MappingProxyType(
            {
                "mode": manifest.mode,
                "artifact": "app.py",
                "argv": [
                    "--host",
                    "127.0.0.1",
                    "--port",
                    "0",
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
