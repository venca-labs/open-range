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
from open_range.admit import AdmissionController, LocalAdmissionController
from open_range.build_config import (
    DEFAULT_BUILD_CONFIG,
    OFFLINE_BUILD_CONFIG,
    OFFLINE_REFERENCE_BUILD_CONFIG,
    BuildConfig,
)
from open_range.cluster import ExecResult
from open_range.compiler import EnterpriseSaaSManifestCompiler
from open_range.curriculum import FrontierMutationPolicy, PopulationStats
from open_range.episode_config import DEFAULT_EPISODE_CONFIG, EpisodeConfig
from open_range.manifest import (
    EnterpriseSaaSManifest,
    manifest_schema,
    validate_manifest,
)
from open_range.objectives import ObjectiveGraderSpec, StandardAttackObjective
from open_range.pipeline import BuildPipeline, CandidateWorld, admit, admit_child, build
from open_range.resources import (
    bundled_manifest_dir,
    bundled_manifest_names,
    bundled_manifest_path,
    bundled_schema_dir,
    load_bundled_manifest,
    load_bundled_manifest_registry,
    load_bundled_schema,
    resource_root,
)
from open_range.runtime_types import (
    Action,
    Decision,
    EpisodeScore,
    EpisodeState,
    Observation,
    RuntimeEvent,
    ServiceHealth,
)
from open_range.service import OpenRange
from open_range.snapshot import Snapshot, world_hash
from open_range.store import FileSnapshotStore
from open_range.tracegen import TraceDatasetGenerator, generate_trace_dataset
from open_range.training_data import (
    TraceDatasetReport,
    TraceDecisionRow,
    TraceLineage,
    render_action_text,
)
from open_range.world_ir import WorldIR

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
    "bundled_manifest_dir",
    "bundled_manifest_names",
    "bundled_manifest_path",
    "bundled_schema_dir",
    "generate_trace_dataset",
    "load_bundled_manifest",
    "load_bundled_manifest_registry",
    "load_bundled_schema",
    "manifest_schema",
    "render_action_text",
    "resource_root",
    "validate_manifest",
    "world_hash",
]
