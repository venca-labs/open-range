"""Built-in runtime backings.

``HTTPBacking`` handles ``Entrypoint(kind="http", ...)``: spawns the
subprocess described by the entrypoint's ``argv`` template, parses its
stdout for the ``{"host", "port"}`` line, and exposes the HTTP interface
(``base_url``, ``http_get``, ``http_get_json``) to checks.

This is what was previously hardcoded inside the cyber pack's runtime
helpers; promoted to a generic backing so any pack with an HTTP
entrypoint reuses it.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, cast
from urllib.request import urlopen

from openrange.core.runtime_backing import (
    RUNTIME_BACKINGS,
    BackingContext,
    RunningArtifact,
    RuntimeBacking,
)
from openrange.core.runtime_helpers import (
    materialize_artifacts,
    read_base_url,
    start_runtime_process,
    stop_process,
)

if TYPE_CHECKING:
    import subprocess

    from openrange.core.pack import Entrypoint


class HTTPBacking(RuntimeBacking):
    """Runs an HTTP service via subprocess + reads its bind address from stdout.

    Entrypoint metadata schema (consumed by ``start``):
        - ``artifact``: relative path to the script under ``ctx.workdir``
        - ``argv``: list of strings or ``{"world": key}`` / ``{"run": "request_log"}``
                    placeholders. Resolved against the world dict and the
                    backing-allocated request-log path.
        - ``request_log``: relative path under ``ctx.workdir`` for the server's
                           request-log file.
    """

    kind = "http"

    def start(
        self,
        entrypoint: Entrypoint,
        artifacts: Mapping[str, str],
        world: Mapping[str, Any],
        ctx: BackingContext,
    ) -> RunningArtifact:
        app_root = ctx.workdir / "pack"
        materialize_artifacts(artifacts, app_root)
        request_log = ctx.workdir / str(entrypoint.metadata["request_log"])
        process = start_runtime_process(
            app_root / str(entrypoint.metadata["artifact"]),
            entrypoint,
            world,
            request_log,
        )
        base_url = read_base_url(process)
        return RunningArtifact(
            id=f"http-{ctx.episode_id}",
            kind=self.kind,
            handle=process,
            metadata={
                "base_url": base_url,
                "request_log": str(request_log),
                "workdir": str(ctx.workdir),
            },
        )

    def stop(self, instance: RunningArtifact) -> None:
        stop_process(cast("subprocess.Popen[str]", instance.handle))

    def interface(self, instance: RunningArtifact) -> Mapping[str, Any]:
        base_url = str(instance.metadata["base_url"])

        def http_get(path: object) -> bytes:
            return cast(bytes, urlopen(base_url + str(path), timeout=5).read())

        def http_get_json(path: object) -> object:
            return json.loads(http_get(path).decode())

        return {
            "base_url": base_url,
            "http_get": http_get,
            "http_get_json": http_get_json,
        }


def _register_builtin_backings() -> None:
    RUNTIME_BACKINGS.register(HTTPBacking())


_register_builtin_backings()
