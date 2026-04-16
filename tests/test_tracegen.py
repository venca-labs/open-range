from __future__ import annotations

import json
from pathlib import Path

from open_range.resources import load_bundled_manifest
from open_range.tracegen import generate_trace_dataset


def _read_jsonl(path: Path) -> list[dict]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def test_generate_trace_dataset_writes_raw_and_decision_views(tmp_path: Path) -> None:
    report = generate_trace_dataset(
        load_bundled_manifest("tier1_basic.yaml"),
        tmp_path / "traces",
        manifest_source="tier1_basic.yaml",
        roots=1,
        mutations_per_root=1,
        include_sim=True,
    )

    assert report.rows > 0
    raw_rows = _read_jsonl(Path(report.raw_path))
    sft_rows = _read_jsonl(Path(report.decision_sft_path))

    assert len(raw_rows) == report.rows
    assert len(sft_rows) == report.rows
    assert {"runtime", "sim"} <= {row["trace_source"] for row in raw_rows}
    assert {"red", "blue"} <= {row["role"] for row in raw_rows}
    assert {"reference_runtime", "reference_sim"} <= {
        row["action_source"] for row in raw_rows
    }
    assert {"red_only", "blue_only_live", "blue_only_from_prefix", "joint_pool"} <= {
        row["mode"] for row in raw_rows
    }
    assert all("candidate_actions" not in row for row in raw_rows)
    assert all("chosen_action" in row and row["chosen_action"] for row in raw_rows)
    assert all(
        "grounded_effects" in row and "mitigation_effects" in row for row in raw_rows
    )
    assert all(
        "service_command" not in row["chosen_action"]["payload"] for row in raw_rows
    )
    assert all(len(entry["messages"]) == 3 for entry in sft_rows)
    assert all(entry["lineage_root_world_id"] for entry in sft_rows)
    assert all(entry["split"] in {"train", "val", "test"} for entry in sft_rows)
    assert "sft.red.runtime" in report.shard_paths
    assert "sft.blue.runtime" in report.shard_paths
    assert "sft.red.source.reference_runtime" in report.shard_paths
    assert "sft.red.source.reference_sim" in report.shard_paths
    assert Path(report.shard_paths["sft.red.runtime"]).exists()
    assert Path(report.shard_paths["raw.red.all"]).exists()


def test_generate_trace_dataset_handles_multi_mutation_joint_pool(
    tmp_path: Path,
) -> None:
    report = generate_trace_dataset(
        load_bundled_manifest("tier1_basic.yaml"),
        tmp_path / "traces-multi",
        manifest_source="tier1_basic.yaml",
        roots=4,
        mutations_per_root=2,
        include_sim=True,
        include_joint_pool=True,
    )

    raw_rows = _read_jsonl(Path(report.raw_path))

    assert report.rows == len(raw_rows)
    assert report.rows > 0
    assert "joint_pool" in {row["mode"] for row in raw_rows}
    assert "sft.red.runtime" in report.shard_paths
    assert "sft.blue.runtime" in report.shard_paths
