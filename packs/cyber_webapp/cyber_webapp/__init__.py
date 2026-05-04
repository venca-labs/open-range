"""Cyber webapp pack — procedural builder + codegen realize.

This package IS the pack. It owns:
  - ``ontology.py`` — typed graph language (10 node types, 12 edge
    types, 3 constraints)
  - ``priors.py`` — default sampling distributions
  - ``sampling.py`` — fresh-graph sampler against the ontology
  - ``mutation.py`` — curriculum-driven mutations of an existing graph
  - ``checks.py`` — admission probe + verifier source rendering
  - ``builder.py`` — ``ProceduralBuilder`` orchestrating the four-stage
    Builder protocol over the modules above
  - ``codegen/`` — ``realize_graph(graph, manifest)`` that turns a
    world graph into a runnable ``app.py`` + ``Entrypoint`` for the
    built-in HTTP runtime backing
  - ``vulnerabilities/`` — shared vuln catalog used by codegen

The pack class itself is small — ontology / priors / realize / default
builder are wired here and exported via the ``openrange.packs``
entry-point group declared in this package's pyproject.toml.
"""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from types import MappingProxyType
from typing import TYPE_CHECKING

from cyber_webapp.ontology import ONTOLOGY
from cyber_webapp.priors import PRIORS
from openrange import Builder, Manifest, Pack, RuntimeBundle, WorldGraph, WorldSchema

if TYPE_CHECKING:
    from openrange import BuildContext


class CyberWebappPack(Pack):
    """Cyber webapp pack — procedural + codegen.

    Ships no on-disk source; everything is generated at build time
    from the graph. ``dir`` is therefore ``None``.
    """

    id = "cyber.webapp"
    version = "v1"

    def __init__(self, dir: Path | None = None) -> None:
        del dir
        self.dir = None

    @property
    def ontology(self) -> WorldSchema:
        return ONTOLOGY

    def default_builder(self, context: BuildContext) -> Builder | None:
        from cyber_webapp.builder import ProceduralBuilder

        seed = 0
        if context.curriculum is not None:
            seed_value = context.curriculum.get("seed", 0)
            if isinstance(seed_value, int):
                seed = seed_value
        return ProceduralBuilder(seed=seed)

    def realize(self, graph: WorldGraph, manifest: Manifest) -> RuntimeBundle:
        from cyber_webapp.codegen import realize_graph

        return realize_graph(graph, manifest)

    def generation_priors(self) -> Mapping[str, object]:
        return PRIORS

    def project_world(self, graph: WorldGraph) -> Mapping[str, object]:
        """Project the graph back to a flat world dict.

        Surfaces the flag value so verifiers can compare against the
        agent's submitted result. Other multi-node attrs are
        intentionally omitted — the verifier only cares about the
        flag; richer projections (service map, account index) come
        when verifiers need them.
        """
        for node in graph.nodes:
            if node.type == "secret" and node.attrs.get("kind") == "flag":
                return MappingProxyType(
                    {"flag": str(node.attrs.get("value_ref", ""))},
                )
        return MappingProxyType({})


__all__ = ["CyberWebappPack"]
