#!/usr/bin/env python3
"""Generate branch-native OpenRange trace datasets from admitted snapshots."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from open_range.resources import load_bundled_manifest
from open_range.tracegen import generate_trace_dataset


def _default_manifest_name() -> str:
    return "tier1_basic.yaml"


def _load_manifest(source: str | Path | None) -> tuple[dict[str, Any], str]:
    if source is None:
        return load_bundled_manifest(_default_manifest_name()), _default_manifest_name()
    path = Path(source)
    if path.exists():
        import yaml

        payload = yaml.safe_load(path.read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            raise ValueError(f"expected a YAML mapping in {path}")
        return payload, str(path)
    return load_bundled_manifest(str(source)), str(source)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate branch-native OpenRange trace datasets."
    )
    parser.add_argument(
        "--manifest",
        default=None,
        help="Bundled manifest name or path to strict manifest YAML.",
    )
    parser.add_argument(
        "--roots",
        type=int,
        default=1,
        help="How many independent root lineages to generate.",
    )
    parser.add_argument(
        "--mutations",
        type=int,
        default=3,
        help="How many sequential admitted mutations per lineage.",
    )
    parser.add_argument(
        "--outdir", default="/tmp/openrange-traces", help="Dataset output directory."
    )
    parser.add_argument(
        "--include-joint-pool",
        action="store_true",
        help="Also export runtime joint_pool traces.",
    )
    parser.add_argument(
        "--no-sim", action="store_true", help="Skip sim-plane bootstrap traces."
    )
    parser.add_argument(
        "--report", default=None, help="Optional explicit JSON report path."
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    manifest, manifest_source = _load_manifest(args.manifest)
    outdir = Path(args.outdir)
    report = generate_trace_dataset(
        manifest,
        outdir,
        manifest_source=manifest_source,
        roots=args.roots,
        mutations_per_root=args.mutations,
        include_sim=not args.no_sim,
        include_joint_pool=args.include_joint_pool,
    )
    report_path = Path(args.report) if args.report else outdir / "report.json"
    report_path.write_text(
        json.dumps(report.model_dump(mode="json"), indent=2), encoding="utf-8"
    )

    print(f"manifest={report.manifest_source}")
    print(f"roots={report.roots}")
    print(f"mutations_per_root={report.mutations_per_root}")
    print(f"rows={report.rows}")
    print(f"raw={report.raw_path}")
    print(f"decision_sft={report.decision_sft_path}")
    for name, path in sorted(report.shard_paths.items()):
        print(f"{name}={path}")
    print(f"report={report_path}")


if __name__ == "__main__":
    main()
