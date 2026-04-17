"""OpenRange public package surface."""

from open_range.admission import (
    ProbeSpec,
    ReferenceAction,
    ReferenceBundle,
    ReferenceTrace,
    ValidatorCheckReport,
    ValidatorReport,
    ValidatorStageReport,
)
from open_range.admission.controller import (
    AdmissionController,
    LocalAdmissionController,
)
from open_range.compiler import EnterpriseSaaSManifestCompiler
from open_range.config import (
    DEFAULT_BUILD_CONFIG,
    DEFAULT_EPISODE_CONFIG,
    OFFLINE_BUILD_CONFIG,
    OFFLINE_REFERENCE_BUILD_CONFIG,
    BuildConfig,
    EpisodeConfig,
)
from open_range.contracts.runtime import (
    Action,
    Decision,
    EpisodeScore,
    EpisodeState,
    Observation,
    RuntimeEvent,
    ServiceHealth,
)
from open_range.contracts.snapshot import Snapshot, world_hash
from open_range.contracts.world import WorldIR
from open_range.manifest import (
    EnterpriseSaaSManifest,
    manifest_schema,
    validate_manifest,
)
from open_range.objectives import ObjectiveGraderSpec, StandardAttackObjective
from open_range.render.live import ExecResult
from open_range.resources import (
    bundled_docs_dir,
    bundled_manifest_dir,
    bundled_manifest_names,
    bundled_manifest_path,
    bundled_schema_dir,
    load_bundled_doc,
    load_bundled_manifest,
    load_bundled_manifest_registry,
    load_bundled_schema,
    resource_root,
)
from open_range.service import OpenRange
from open_range.store import (
    BuildPipeline,
    CandidateWorld,
    FileSnapshotStore,
    admit,
    admit_child,
    build,
)
from open_range.training.curriculum import FrontierMutationPolicy, PopulationStats
from open_range.training.data import (
    TraceDatasetReport,
    TraceDecisionRow,
    TraceLineage,
)
from open_range.training.trace_exports import render_action_text
from open_range.training.tracegen import TraceDatasetGenerator, generate_trace_dataset

__all__ = [
    "Action",
    "AdmissionController",
    "BuildConfig",
    "BuildPipeline",
    "CandidateWorld",
    "DEFAULT_BUILD_CONFIG",
    "DEFAULT_EPISODE_CONFIG",
    "Decision",
    "EnterpriseSaaSManifest",
    "EnterpriseSaaSManifestCompiler",
    "EpisodeConfig",
    "EpisodeScore",
    "EpisodeState",
    "ExecResult",
    "FileSnapshotStore",
    "FrontierMutationPolicy",
    "LocalAdmissionController",
    "ObjectiveGraderSpec",
    "OFFLINE_BUILD_CONFIG",
    "OFFLINE_REFERENCE_BUILD_CONFIG",
    "Observation",
    "OpenRange",
    "PopulationStats",
    "ProbeSpec",
    "ReferenceAction",
    "ReferenceBundle",
    "ReferenceTrace",
    "RuntimeEvent",
    "ServiceHealth",
    "Snapshot",
    "StandardAttackObjective",
    "TraceDatasetGenerator",
    "TraceDatasetReport",
    "TraceDecisionRow",
    "TraceLineage",
    "ValidatorCheckReport",
    "ValidatorReport",
    "ValidatorStageReport",
    "WorldIR",
    "admit",
    "admit_child",
    "build",
    "bundled_docs_dir",
    "bundled_manifest_dir",
    "bundled_manifest_names",
    "bundled_manifest_path",
    "bundled_schema_dir",
    "generate_trace_dataset",
    "load_bundled_doc",
    "load_bundled_manifest",
    "load_bundled_manifest_registry",
    "load_bundled_schema",
    "manifest_schema",
    "render_action_text",
    "resource_root",
    "validate_manifest",
    "world_hash",
]
