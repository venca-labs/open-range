"""Codegen-based realizer for the v1 cyber webapp offense pack.

Walks a v1-ontology ``WorldGraph`` and produces a single ``app.py``
that hosts every service in one Python process. Each ``service``
becomes a path namespace (``/svc/<name>/...``); the public ``web``
service also mounts at ``/`` for convenience. Each ``endpoint``
becomes a route. Each ``vulnerability`` with an ``affects`` edge to
an endpoint has its template body inlined as that endpoint's handler.

Pipeline:

  1. ``seeding.project_seed`` — graph → seed dicts (flag, accounts,
     secrets, records) baked into ``app.py``
  2. ``handlers.build_handlers_and_routes`` — graph → handler funcs
     and route table, with vuln templates inlined per endpoint
  3. Render the Jinja template under ``templates/app.py.j2``
  4. ``entrypoint.http_entrypoint`` — build the ``Entrypoint`` the
     ``HTTPBacking`` consumes

Multi-process / docker-compose isolation is C4. Until then, every
service is reachable on the same single Python process — vulns fire
end-to-end, but network-level service isolation is simulated, not
real.
"""

from __future__ import annotations

from pathlib import Path
from types import MappingProxyType

from jinja2 import Environment, FileSystemLoader, StrictUndefined, select_autoescape

from cyber_webapp.codegen.discovery import build_discovery
from cyber_webapp.codegen.entrypoint import http_entrypoint
from cyber_webapp.codegen.handlers import (
    build_handlers_and_routes,
)
from cyber_webapp.codegen.seeding import project_seed
from openrange.core.graph import RuntimeArtifact, RuntimeBundle, WorldGraph
from openrange.core.manifest import Manifest

_TEMPLATES_DIR = Path(__file__).parent / "templates"


def realize_graph(graph: WorldGraph, manifest: Manifest) -> RuntimeBundle:
    """Render ``graph`` into a single-file RuntimeBundle for HTTPBacking.

    The bundle has one ``RuntimeArtifact`` of kind ``"file"`` with path
    ``"app.py"`` and one ``Entrypoint`` of kind ``"http"`` targeting
    the public web service.
    """
    seed = project_seed(graph)
    handlers, routes = build_handlers_and_routes(graph)
    discovery = build_discovery(graph)

    template = _jinja_env().get_template("app.py.j2")
    source = template.render(
        flag=seed["flag"],
        accounts=seed["accounts"],
        secrets=seed["secrets"],
        records=seed["records"],
        handlers=handlers,
        routes=routes,
        discovery=discovery,
    )

    artifact = RuntimeArtifact(
        id="app.py",
        kind="file",
        metadata=MappingProxyType({"path": "app.py", "content": source}),
    )
    return RuntimeBundle(
        artifacts=(artifact,),
        entrypoints=(http_entrypoint(manifest),),
    )


def _jinja_env() -> Environment:
    return Environment(
        loader=FileSystemLoader(str(_TEMPLATES_DIR)),
        undefined=StrictUndefined,
        autoescape=select_autoescape(disabled_extensions=("py",), default=False),
        keep_trailing_newline=True,
    )
