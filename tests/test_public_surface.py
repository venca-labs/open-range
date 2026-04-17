from __future__ import annotations

import open_range


def test_top_level_package_exports_small_guided_surface() -> None:
    assert set(open_range.__all__) == {
        "BuildConfig",
        "BuildPipeline",
        "DEFAULT_BUILD_CONFIG",
        "DEFAULT_EPISODE_CONFIG",
        "EnterpriseSaaSManifest",
        "EpisodeConfig",
        "OFFLINE_BUILD_CONFIG",
        "OFFLINE_REFERENCE_BUILD_CONFIG",
        "OpenRange",
        "Snapshot",
        "WorldIR",
        "load_bundled_manifest",
        "manifest_schema",
        "validate_manifest",
        "world_hash",
    }
