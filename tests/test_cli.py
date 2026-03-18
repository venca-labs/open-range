from __future__ import annotations

import json
from pathlib import Path

import yaml
from click.testing import CliRunner

from open_range.cli import cli
from tests.support import manifest_payload


def _manifest_payload() -> dict:
    return manifest_payload()


def _write_manifest(tmp_path: Path) -> Path:
    manifest_path = tmp_path / "manifest.yaml"
    manifest_path.write_text(
        yaml.safe_dump(_manifest_payload(), sort_keys=False), encoding="utf-8"
    )
    return manifest_path


def test_build_command_writes_candidate_world(tmp_path: Path):
    manifest_path = _write_manifest(tmp_path)
    output_dir = tmp_path / "rendered"

    result = CliRunner().invoke(
        cli, ["build", "--manifest", str(manifest_path), "--output", str(output_dir)]
    )

    assert result.exit_code == 0, result.output
    world_path = output_dir / "candidate-world.json"
    assert world_path.exists()
    payload = json.loads(world_path.read_text(encoding="utf-8"))
    assert payload["world_family"] == "enterprise_saas_v1"
    assert "Candidate world written to" in result.output


def test_admit_command_persists_snapshot(tmp_path: Path):
    manifest_path = _write_manifest(tmp_path)
    store_dir = tmp_path / "snapshots"
    render_dir = tmp_path / "rendered"

    result = CliRunner().invoke(
        cli,
        [
            "admit",
            "--manifest",
            str(manifest_path),
            "--output",
            str(render_dir),
            "--store-dir",
            str(store_dir),
            "--split",
            "eval",
            "--validation-profile",
            "graph_only",
        ],
    )

    assert result.exit_code == 0, result.output
    snapshot_dirs = [path for path in store_dir.iterdir() if path.is_dir()]
    assert len(snapshot_dirs) == 1
    metadata = json.loads(
        (snapshot_dirs[0] / "metadata.json").read_text(encoding="utf-8")
    )
    assert metadata["split"] == "eval"
    assert "Admitted snapshot written to" in result.output


def test_reset_command_loads_snapshot_from_store(tmp_path: Path):
    manifest_path = _write_manifest(tmp_path)
    store_dir = tmp_path / "snapshots"
    render_dir = tmp_path / "rendered"
    runner = CliRunner()

    admit_result = runner.invoke(
        cli,
        [
            "admit",
            "--manifest",
            str(manifest_path),
            "--output",
            str(render_dir),
            "--store-dir",
            str(store_dir),
            "--validation-profile",
            "graph_only",
        ],
    )
    assert admit_result.exit_code == 0, admit_result.output

    reset_result = runner.invoke(
        cli,
        [
            "reset",
            "--store-dir",
            str(store_dir),
            "--sample-seed",
            "17",
            "--strategy",
            "latest",
        ],
    )

    assert reset_result.exit_code == 0, reset_result.output
    assert "Episode ready on" in reset_result.output
    assert "Sim Time:" in reset_result.output
    assert "Next Actor:" in reset_result.output


def test_traces_command_writes_branch_native_datasets(tmp_path: Path):
    manifest_path = _write_manifest(tmp_path)
    output_dir = tmp_path / "traces"

    result = CliRunner().invoke(
        cli,
        [
            "traces",
            "--manifest",
            str(manifest_path),
            "--output",
            str(output_dir),
            "--roots",
            "1",
            "--mutations",
            "1",
        ],
    )

    assert result.exit_code == 0, result.output
    assert (output_dir / "trace_rows.jsonl").exists()
    assert (output_dir / "decision_sft.jsonl").exists()
    assert (output_dir / "report.json").exists()
    assert "Trace dataset written to" in result.output
