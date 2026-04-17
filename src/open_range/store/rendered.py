"""Rendered artifact post-processing helpers."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import yaml

from open_range.config import BuildConfig
from open_range.contracts.snapshot import KindArtifacts
from open_range.render.cilium import CiliumPolicyGenerator


def integrate_network_policies(
    artifacts: KindArtifacts,
    build_config: BuildConfig,
) -> KindArtifacts:
    if build_config.network_policy_backend != "cilium":
        return artifacts

    chart_values = dict(artifacts.chart_values)
    generator = CiliumPolicyGenerator(name_prefix="{{ $.Values.global.namePrefix }}")
    policies = generator.generate_zone_policies(
        chart_values["zones"],
        chart_values["firewallRules"],
    )
    cilium_path = Path(artifacts.chart_dir) / "templates" / "cilium-policies.yaml"
    cilium_path.write_text(
        yaml.safe_dump_all(policies, sort_keys=False),
        encoding="utf-8",
    )
    chart_values["cilium"] = {
        "enabled": True,
        "policyCount": len(policies),
    }
    return sync_artifacts(
        artifacts,
        chart_values=chart_values,
        rendered_files=[str(cilium_path)],
        summary_updates={
            "network_policy_backend": build_config.network_policy_backend,
        },
    )


def sync_artifacts(
    artifacts: KindArtifacts,
    *,
    chart_values: dict[str, Any],
    rendered_files: list[str] | tuple[str, ...] = (),
    summary_updates: dict[str, Any] | None = None,
) -> KindArtifacts:
    values_path = Path(artifacts.values_path)
    values_path.write_text(
        yaml.safe_dump(chart_values, sort_keys=False),
        encoding="utf-8",
    )

    summary_path = Path(artifacts.manifest_summary_path)
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    summary["values_hash"] = hashlib.sha256(
        json.dumps(chart_values, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    if summary_updates:
        summary.update(summary_updates)
    summary_path.write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    next_files = tuple(dict.fromkeys((*artifacts.rendered_files, *rendered_files)))
    return artifacts.model_copy(
        update={
            "rendered_files": next_files,
            "chart_values": chart_values,
        }
    )
