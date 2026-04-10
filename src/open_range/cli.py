"""Standalone OpenRange CLI."""

from __future__ import annotations

import json
import logging
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import click
import yaml

from open_range.build_config import BuildConfig
from open_range.episode_config import EpisodeConfig
from open_range.pipeline import BuildPipeline
from open_range.resources import load_bundled_manifest
from open_range.service import OpenRange
from open_range.store import FileSnapshotStore
from open_range.tracegen import generate_trace_dataset

LOG_FORMAT = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
LOG_DATE_FORMAT = "%H:%M:%S"


def _configure_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format=LOG_FORMAT,
        datefmt=LOG_DATE_FORMAT,
        stream=sys.stderr,
    )


def _load_manifest(source: str) -> dict[str, Any]:
    manifest_path = Path(source)
    if manifest_path.exists():
        payload = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
    else:
        try:
            payload = load_bundled_manifest(source)
        except FileNotFoundError as exc:
            raise click.ClickException(f"manifest not found: {source}") from exc
    if not isinstance(payload, dict):
        raise click.ClickException(
            f"manifest must be a YAML mapping, got {type(payload).__name__}"
        )
    return payload


def _write_json(payload: dict[str, Any], dest: Path) -> Path:
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return dest


def _repo_script(script_name: str) -> Path:
    root = Path(__file__).resolve().parents[2]
    script_path = root / "scripts" / script_name
    if not script_path.exists():
        raise click.ClickException(
            f"required runner script is unavailable: {script_path}"
        )
    return script_path


@click.group()
@click.option(
    "-v", "--verbose", is_flag=True, default=False, help="Enable debug logging."
)
@click.option(
    "--model",
    default=None,
    help="Override default backend AI model (e.g. moonshotai/kimi-k2-instruct).",
)
@click.option(
    "--base-url",
    default=None,
    help="Override default HTTP backend AI URL (e.g. https://integrate.api.nvidia.com/v1/).",
)
@click.option(
    "--asr-url",
    default=None,
    help="Override Parakeet ASR endpoint.",
)
@click.option(
    "--tts-url",
    default=None,
    help="Override Riva FastPitch TTS endpoint.",
)
@click.version_option(package_name="open-range", prog_name="openrange")
def cli(
    verbose: bool,
    model: str | None,
    base_url: str | None,
    asr_url: str | None,
    tts_url: str | None,
) -> None:
    """Build, admit, and run immutable OpenRange snapshots."""
    _configure_logging(verbose)
    if model:
        os.environ["MODEL_ID"] = model
    if base_url:
        os.environ["OPENAI_BASE_URL"] = base_url
    if asr_url:
        os.environ["ASR_URL"] = asr_url
    if tts_url:
        os.environ["TTS_URL"] = tts_url


@cli.command("build")
@click.option(
    "-m",
    "--manifest",
    required=True,
    type=str,
    help="Path to manifest YAML or bundled manifest name.",
)
@click.option(
    "-o",
    "--output",
    required=True,
    type=click.Path(),
    help="Output directory for rendered candidate artifacts.",
)
def build_cmd(manifest: str, output: str) -> None:
    """Compile and render a candidate world from a manifest."""
    output_dir = Path(output)
    candidate = BuildPipeline().build(_load_manifest(manifest), output_dir)
    world_path = _write_json(
        candidate.world.model_dump(mode="json"), output_dir / "candidate-world.json"
    )

    click.echo(f"Candidate world written to {world_path}")
    click.echo(f"  World ID: {candidate.world.world_id}")
    click.echo(f"  Services: {len(candidate.world.services)}")
    click.echo(f"  Weaknesses: {len(candidate.world.weaknesses)}")
    click.echo(f"  Render dir: {candidate.artifacts.render_dir}")


@cli.command("admit")
@click.option(
    "-m",
    "--manifest",
    required=True,
    type=str,
    help="Path to manifest YAML or bundled manifest name.",
)
@click.option(
    "-o",
    "--output",
    required=True,
    type=click.Path(),
    help="Render directory for candidate artifacts.",
)
@click.option(
    "--store-dir",
    default="snapshots",
    type=click.Path(),
    help="Snapshot store directory.",
)
@click.option(
    "--split",
    default="train",
    type=click.Choice(["train", "eval"]),
    help="Pool split for the admitted snapshot.",
)
@click.option(
    "--validation-profile",
    default="full",
    type=click.Choice(["full", "no_necessity", "graph_plus_live", "graph_only"]),
    help="Admission strictness. Use graph_only for explicit offline admission.",
)
def admit_cmd(
    manifest: str, output: str, store_dir: str, split: str, validation_profile: str
) -> None:
    """Build and admit a snapshot into the snapshot store."""
    pipeline = BuildPipeline(store=FileSnapshotStore(store_dir))
    candidate = pipeline.build(
        _load_manifest(manifest),
        Path(output),
        BuildConfig(validation_profile=validation_profile),
    )
    snapshot = pipeline.admit(candidate, split=split)
    snapshot_path = Path(store_dir) / snapshot.snapshot_id / "snapshot.json"

    click.echo(f"Admitted snapshot written to {snapshot_path}")
    click.echo(f"  Snapshot ID: {snapshot.snapshot_id}")
    click.echo(f"  World ID: {snapshot.world_id}")
    click.echo(f"  Split: {split}")
    click.echo(f"  Parent World: {snapshot.parent_world_id or 'root'}")


@cli.command("reset")
@click.option(
    "--store-dir",
    default="snapshots",
    type=click.Path(),
    help="Snapshot store directory.",
)
@click.option(
    "--snapshot-id",
    default=None,
    help="Snapshot id to restore. If omitted, sample from the requested split.",
)
@click.option(
    "--split",
    default="train",
    type=click.Choice(["train", "eval"]),
    help="Pool split to sample from when --snapshot-id is omitted.",
)
@click.option(
    "--strategy",
    default="random",
    type=click.Choice(["random", "latest"]),
    help="Sampling strategy when --snapshot-id is omitted.",
)
@click.option(
    "--sample-seed",
    default=0,
    type=int,
    help="Sampling seed when --snapshot-id is omitted.",
)
@click.option(
    "--mode",
    default="joint_pool",
    type=click.Choice(
        ["red_only", "blue_only_live", "blue_only_from_prefix", "joint_pool"]
    ),
    help="Episode runtime mode.",
)
@click.option(
    "--horizon", default=25.0, type=float, help="Simulated-time episode horizon."
)
def reset_cmd(
    store_dir: str,
    snapshot_id: str | None,
    split: str,
    strategy: str,
    sample_seed: int,
    mode: str,
    horizon: float,
) -> None:
    """Reset the runtime against an admitted snapshot and print the initial state."""
    service = OpenRange(store=FileSnapshotStore(store_dir))
    state = service.reset(
        snapshot_id,
        EpisodeConfig(mode=mode, episode_horizon_minutes=horizon),
        split=split,
        strategy=strategy,
        sample_seed=sample_seed,
    )

    click.echo(f"Episode ready on {state.snapshot_id}")
    click.echo(f"  Episode ID: {state.episode_id}")
    click.echo(f"  Sim Time: {state.sim_time:.2f}")
    click.echo(f"  Controls Red: {state.controls_red}")
    click.echo(f"  Controls Blue: {state.controls_blue}")
    click.echo(f"  Next Actor: {state.next_actor or 'n/a'}")


@cli.command("traces")
@click.option(
    "-m",
    "--manifest",
    required=True,
    type=str,
    help="Path to manifest YAML or bundled manifest name.",
)
@click.option(
    "-o",
    "--output",
    required=True,
    type=click.Path(),
    help="Output directory for generated trace data.",
)
@click.option(
    "--roots",
    default=1,
    type=int,
    help="How many independent root lineages to generate.",
)
@click.option(
    "--mutations",
    default=3,
    type=int,
    help="How many admitted child mutations per lineage.",
)
@click.option(
    "--include-joint-pool",
    is_flag=True,
    default=False,
    help="Also export runtime joint_pool traces.",
)
@click.option(
    "--no-sim", is_flag=True, default=False, help="Skip sim-plane bootstrap traces."
)
def traces_cmd(
    manifest: str,
    output: str,
    roots: int,
    mutations: int,
    include_joint_pool: bool,
    no_sim: bool,
) -> None:
    """Generate branch-native trace datasets from admitted snapshots."""
    output_dir = Path(output)
    report = generate_trace_dataset(
        _load_manifest(manifest),
        output_dir,
        manifest_source=manifest,
        roots=roots,
        mutations_per_root=mutations,
        include_sim=not no_sim,
        include_joint_pool=include_joint_pool,
    )
    report_path = _write_json(
        report.model_dump(mode="json"), output_dir / "report.json"
    )

    click.echo(f"Trace dataset written to {output_dir}")
    click.echo(f"  Rows: {report.rows}")
    click.echo(f"  Raw Rows: {report.raw_path}")
    click.echo(f"  Decision SFT: {report.decision_sft_path}")
    click.echo(f"  Report: {report_path}")


@cli.command("grpo")
@click.option(
    "--model",
    required=True,
    help="Path to the SFT checkpoint used by the Qwen-focused GRPO runner.",
)
@click.option(
    "--data",
    required=True,
    help="Path to the GRPO JSONL training data.",
)
@click.option(
    "--output",
    default="./grpo-output",
    show_default=True,
    help="Output directory for GRPO artifacts.",
)
@click.option(
    "--reward",
    default="online",
    show_default=True,
    type=click.Choice(["binary", "progressive", "online", "both"]),
    help="Reward function selection passed through to the standalone runner.",
)
@click.option(
    "--env-url",
    default="http://localhost:8000",
    show_default=True,
    help="Environment URL when using online reward mode.",
)
@click.option(
    "--seq",
    default=4096,
    show_default=True,
    type=int,
    help="Maximum sequence length.",
)
@click.option(
    "--comp-len",
    default=2048,
    show_default=True,
    type=int,
    help="Maximum completion length.",
)
@click.option(
    "--num-gen",
    default=4,
    show_default=True,
    type=int,
    help="Completions generated per prompt.",
)
@click.option(
    "--epochs",
    default=1,
    show_default=True,
    type=int,
    help="Number of GRPO epochs.",
)
def grpo_cmd(
    model: str,
    data: str,
    output: str,
    reward: str,
    env_url: str,
    seq: int,
    comp_len: int,
    num_gen: int,
    epochs: int,
) -> None:
    """Run the advanced GRPO training path through the standalone Qwen runner."""
    runner = _repo_script("run_grpo.py")
    command = [
        sys.executable,
        str(runner),
        "--model",
        model,
        "--data",
        data,
        "--output",
        output,
        "--reward",
        reward,
        "--env-url",
        env_url,
        "--seq",
        str(seq),
        "--comp-len",
        str(comp_len),
        "--num-gen",
        str(num_gen),
        "--epochs",
        str(epochs),
    ]
    result = subprocess.run(command, check=False)
    if result.returncode != 0:
        raise SystemExit(result.returncode)


if __name__ == "__main__":
    cli()
