from __future__ import annotations

from open_range.compiler import EnterpriseSaaSManifestCompiler
from open_range.config import BuildConfig
from open_range.weaknesses import CatalogWeaknessSeeder
from tests.support import manifest_payload


def test_telemetry_blindspot_seeding_stays_inside_the_filtered_world() -> None:
    payload = manifest_payload()
    world = EnterpriseSaaSManifestCompiler().compile(
        payload,
        build_config=BuildConfig(
            services_enabled=("siem",),
            weakness_families_enabled=("telemetry_blindspot",),
            validation_profile="graph_only",
        ),
    )
    seeded = CatalogWeaknessSeeder().apply(world)

    assert seeded.weaknesses
    telemetry = seeded.weaknesses[0]
    assert telemetry.family == "telemetry_blindspot"
    assert telemetry.target == "svc-siem"
    assert telemetry.target_ref == "svc-siem"
