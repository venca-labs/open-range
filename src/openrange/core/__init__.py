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
    PackSourceKind,
    WorldMode,
)
from openrange.core.pack import (
    PACKS,
    AdmissionState,
    Entrypoint,
    Pack,
    PackRegistry,
    Task,
    Verifier,
    VerifierResult,
    admission_state_from_source,
    verifier_from_source,
)
from openrange.core.snapshot import (
    LineageNode,
    Snapshot,
    json_safe,
    snapshot_hash,
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
    "AdmissionState",
    "BUILDERS",
    "BuildContext",
    "BuildFailed",
    "BuildState",
    "Builder",
    "BuilderError",
    "BuilderRegistry",
    "CheckScript",
    "Edge",
    "EdgeType",
    "Entrypoint",
    "GraphConstraint",
    "LineageNode",
    "Manifest",
    "ManifestError",
    "Node",
    "NodeType",
    "OpenRangeError",
    "Pack",
    "PackError",
    "PackRef",
    "PackRegistry",
    "PackSource",
    "PackSourceKind",
    "Ref",
    "RuntimeArtifact",
    "RuntimeBundle",
    "Snapshot",
    "SnapshotStore",
    "StoreError",
    "Task",
    "ValidationError",
    "Verifier",
    "VerifierResult",
    "WorldGraph",
    "WorldMode",
    "WorldSchema",
    "admission_state_from_source",
    "admit",
    "build",
    "evolve",
    "json_safe",
    "snapshot_hash",
    "stable_json",
    "task_from_mapping",
    "verifier_from_source",
]
