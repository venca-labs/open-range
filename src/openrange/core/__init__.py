"""OpenRange core public API."""

# Side-effect: registers built-in backings (HTTP) into RUNTIME_BACKINGS.
import openrange.core.backings as _backings  # noqa: F401, E402
from openrange.core.admission import (
    AdmissionFailure,
    AdmissionReport,
    AdmissionResult,
    BuildFailed,
    admit,
)
from openrange.core.builder import (
    BuildContext,
    BuildState,
    build,
    evolve,
)
from openrange.core.builder_protocol import (
    BUILDERS,
    Builder,
    BuilderError,
    BuilderRegistry,
)
from openrange.core.curriculum import (
    CurriculumPolicy,
    Direction,
    Mutation,
    auto_evolve,
    direction_from_reports,
)
from openrange.core.errors import (
    AdmissionError,
    ManifestError,
    OpenRangeError,
    PackError,
    StoreError,
)
from openrange.core.graph import (
    CheckScript,
    Edge,
    EdgeType,
    GraphConstraint,
    Node,
    NodeType,
    Ref,
    RuntimeArtifact,
    RuntimeBundle,
    ValidationError,
    WorldGraph,
    WorldSchema,
)
from openrange.core.manifest import (
    Manifest,
    PackRef,
    PackSource,
)
from openrange.core.pack import (
    PACKS,
    Entrypoint,
    Pack,
    PackRegistry,
    Task,
    admission_state_from_source,
    verifier_from_source,
)
from openrange.core.snapshot import (
    LineageNode,
    Snapshot,
    stable_json,
    task_from_mapping,
)
from openrange.core.store import SnapshotStore
from openrange.core.turn import ActorTurn

__all__ = [
    "PACKS",
    "ActorTurn",
    "AdmissionError",
    "AdmissionFailure",
    "AdmissionReport",
    "AdmissionResult",
    "BUILDERS",
    "BuildContext",
    "BuildFailed",
    "BuildState",
    "Builder",
    "BuilderError",
    "BuilderRegistry",
    "CheckScript",
    "CurriculumPolicy",
    "Direction",
    "Edge",
    "EdgeType",
    "Entrypoint",
    "GraphConstraint",
    "LineageNode",
    "Manifest",
    "ManifestError",
    "Mutation",
    "Node",
    "NodeType",
    "OpenRangeError",
    "Pack",
    "PackError",
    "PackRef",
    "PackRegistry",
    "PackSource",
    "Ref",
    "RuntimeArtifact",
    "RuntimeBundle",
    "Snapshot",
    "SnapshotStore",
    "StoreError",
    "Task",
    "ValidationError",
    "WorldGraph",
    "WorldSchema",
    "admission_state_from_source",
    "admit",
    "auto_evolve",
    "build",
    "direction_from_reports",
    "evolve",
    "stable_json",
    "task_from_mapping",
    "verifier_from_source",
]
