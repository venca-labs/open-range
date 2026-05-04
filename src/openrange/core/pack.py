"""Pack contracts and generated task artifacts."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from typing import TYPE_CHECKING, cast

from openrange.core.errors import PackError, StoreError

if TYPE_CHECKING:
    from openrange.core.builder import BuildContext
    from openrange.core.builder_protocol import Builder
    from openrange.core.graph import RuntimeBundle, WorldGraph, WorldSchema
    from openrange.core.manifest import Manifest

VerifierResult = Mapping[str, object]
Verifier = Callable[[Mapping[str, object]], VerifierResult]
AdmissionState = Callable[[Mapping[str, object]], Mapping[str, object]]


def verifier_from_source(source: str) -> Verifier:
    namespace: dict[str, object] = {}
    try:
        exec(source, {"__builtins__": {}}, namespace)
    except Exception as exc:
        raise StoreError("stored verifier source is invalid") from exc
    verify = namespace.get("verify")
    if not callable(verify):
        raise StoreError("stored verifier source must define verify()")

    def run(state: Mapping[str, object]) -> VerifierResult:
        result = cast(Verifier, verify)(state)
        if not isinstance(result, Mapping):
            raise StoreError("verifier returned invalid result")
        return MappingProxyType(dict(result))

    return run


def admission_state_from_source(source: str) -> AdmissionState:
    namespace: dict[str, object] = {}
    try:
        exec(source, {"__builtins__": {}}, namespace)
    except Exception as exc:
        raise StoreError("stored admission source is invalid") from exc
    admission_state = namespace.get("admission_state")
    if not callable(admission_state):
        raise StoreError("stored admission source must define admission_state()")

    def run(interface: Mapping[str, object]) -> Mapping[str, object]:
        state = cast(AdmissionState, admission_state)(interface)
        if not isinstance(state, Mapping):
            raise StoreError("admission source returned invalid final state")
        return MappingProxyType(dict(state))

    return run


@dataclass(frozen=True, slots=True)
class Entrypoint:
    kind: str
    target: str
    metadata: Mapping[str, object] = field(default_factory=dict)

    def as_dict(self) -> dict[str, object]:
        return {
            "kind": self.kind,
            "target": self.target,
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_mapping(cls, data: Mapping[str, object]) -> Entrypoint:
        kind = data.get("kind")
        target = data.get("target")
        metadata = data.get("metadata", {})
        if not isinstance(kind, str) or not isinstance(target, str):
            raise StoreError("stored entrypoint is invalid")
        if not isinstance(metadata, Mapping):
            raise StoreError("stored entrypoint metadata is invalid")
        return cls(kind, target, MappingProxyType(dict(metadata)))


@dataclass(frozen=True, slots=True)
class Task:
    """Pure-data description of one task an agent can attempt.

    The verifier callable is not stored here — it's resolved from the
    snapshot's ``verifier_sources`` by ``verifier_id`` when needed. This
    keeps Task serializable and lets multiple tasks reference the same
    verifier source without duplication.
    """

    id: str
    instruction: str
    entrypoints: tuple[Entrypoint, ...]
    verifier_id: str

    @property
    def interface(self) -> tuple[Entrypoint, ...]:
        return self.entrypoints

    def as_dict(self) -> dict[str, object]:
        return {
            "id": self.id,
            "instruction": self.instruction,
            "entrypoints": [entrypoint.as_dict() for entrypoint in self.entrypoints],
            "verifier_id": self.verifier_id,
        }


class Pack(ABC):
    """Domain SDK contract.

    A Pack ships an ontology, a realizer that turns conforming graphs into
    runtime artifacts, and optional verifier helpers, generation priors,
    and a default builder. Core does not interpret pack-internal data —
    the ``ontology`` and ``realize()`` are the only seams Core requires.

    Subclasses must set ``id`` and ``version`` as class attributes (or
    properties) and implement ``ontology`` and ``realize()``. Filesystem-
    backed packs may also expose ``dir`` so the runtime can locate
    on-disk assets.
    """

    id: str = ""
    version: str = ""
    dir: Path | None = None

    def __init__(self, dir: Path | None = None) -> None:
        """Default constructor: filesystem-backed packs may pass a custom dir.

        Subclasses are free to override with their own signature, but the
        ``dir: Path | None = None`` convention is what path-pack loading
        relies on. Non-filesystem packs typically just leave ``dir = None``
        and ignore this argument.
        """
        if dir is not None:
            self.dir = dir

    @property
    @abstractmethod
    def ontology(self) -> WorldSchema: ...

    @abstractmethod
    def realize(self, graph: WorldGraph, manifest: Manifest) -> RuntimeBundle: ...

    def verifier_helpers(self) -> Mapping[str, Callable[..., object]]:
        return MappingProxyType({})

    def default_builder(self, context: BuildContext) -> Builder | None:
        """Construct the pack's default Builder for a given build context.

        Returns ``None`` if the pack ships no default; the user must then
        supply their own Builder. Packs are free to inspect ``context``
        (LLM, prompt, curriculum, feedback) when constructing.
        """
        return None

    def generation_priors(self) -> Mapping[str, object]:
        return MappingProxyType({})

    def runtime_backings(self) -> tuple[object, ...]:
        """Per-pack runtime backings for artifact kinds the pack introduces.

        Returns RuntimeBacking instances. Default: empty (rely on built-ins).
        Typed as ``tuple[object, ...]`` to avoid a hard import cycle between
        ``pack`` and ``runtime_backing``.
        """
        return ()

    def project_world(self, graph: WorldGraph) -> Mapping[str, object]:
        """Project the graph back to the flat ``world`` dict the runtime expects.

        Used by core to populate ``argv``-from-world placeholders and the
        verifier's ``state['world']`` view. Default: the attrs of the
        first node (matches the cyber-pack v0 single-node convention).
        Multi-node ontologies override to project the relevant attrs
        (e.g. flag value, service URLs) into a flat mapping.
        """
        return dict(graph.first_node_attrs())

    def as_dict(self) -> dict[str, object]:
        return {
            "id": self.id,
            "version": self.version,
            "dir": None if self.dir is None else str(self.dir),
        }


PACK_ENTRY_POINT_GROUP = "openrange.packs"


class PackRegistry:
    """Registry of Pack instances by id.

    Packs can be registered explicitly via ``register()`` or, on the
    global ``PACKS`` instance, discovered via Python entry points in
    the ``openrange.packs`` group. Entry-point values must resolve to a
    callable returning a Pack instance (typically the Pack class itself
    with a parameterless default constructor).

    ``autodiscover=False`` (the default) gives a clean slate suitable
    for tests. The global ``PACKS = PackRegistry(autodiscover=True)``
    pulls in installed packs on first access.
    """

    def __init__(self, *, autodiscover: bool = False) -> None:
        self._packs: dict[str, Pack] = {}
        self._autodiscover = autodiscover
        self._discovered = False

    def register(self, pack: Pack) -> None:
        self._packs[pack.id] = pack

    def resolve(self, pack_id: str) -> Pack:
        self._ensure_discovered()
        try:
            return self._packs[pack_id]
        except KeyError as exc:
            raise PackError(f"unknown pack {pack_id!r}") from exc

    def resolve_class(self, pack_id: str) -> type[Pack]:
        """Return the Pack subclass for ``pack_id``.

        Used by path-loaded packs to construct an instance pointing at a
        custom directory. Raises ``PackError`` if no pack is registered
        for that id.
        """
        return type(self.resolve(pack_id))

    def ids(self) -> tuple[str, ...]:
        self._ensure_discovered()
        return tuple(sorted(self._packs))

    def discover(self) -> None:
        """Force entry-point discovery (idempotent on the same registry)."""
        self._ensure_discovered(force=True)

    def _ensure_discovered(self, *, force: bool = False) -> None:
        if not self._autodiscover and not force:
            return
        if self._discovered and not force:
            return
        self._discovered = True
        from openrange.core._registry import iter_entry_points

        for name, value in iter_entry_points(
            PACK_ENTRY_POINT_GROUP,
            error_cls=PackError,
            kind="pack",
        ):
            if name in self._packs and not force:
                continue
            pack = value() if callable(value) else value
            if not isinstance(pack, Pack):
                raise PackError(
                    f"entry point {name!r} did not return a Pack",
                )
            if pack.id != name:
                raise PackError(
                    f"entry point name {name!r} does not match pack.id {pack.id!r}",
                )
            self._packs[pack.id] = pack


PACKS = PackRegistry(autodiscover=True)
