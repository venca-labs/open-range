"""Standalone OpenRange CLI."""

from __future__ import annotations

import json
import logging
import subprocess
import sys
from pathlib import Path
from typing import Any

import click
import yaml

from open_range.backend_overrides import BackendOverrides
from open_range.build_config import BuildConfig
from open_range.cluster import KindBackend
from open_range.episode_config import EpisodeConfig
from open_range.k3d_runner import K3dBackend
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


def _build_config_from_options(
    *,
    validation_profile: str = "full",
    security_tier: int = 1,
    cluster_backend: str = "kind",
    network_policy_backend: str = "kubernetes",
    k3d_agents: int = 2,
    k3d_subnet: str = "172.29.0.0/16",
) -> BuildConfig:
    return BuildConfig(
        validation_profile=validation_profile,  # type: ignore[arg-type]
        security_integration_enabled=security_tier > 1,
        security_tier=security_tier,
        cluster_backend=cluster_backend,  # type: ignore[arg-type]
        network_policy_backend=network_policy_backend,  # type: ignore[arg-type]
        k3d_agents=k3d_agents,
        k3d_subnet=k3d_subnet,
    )


def _live_backend_for_option(cluster_backend: str) -> KindBackend | K3dBackend | None:
    if cluster_backend == "none":
        return None
    if cluster_backend == "k3d":
        return K3dBackend()
    return KindBackend()


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
@click.pass_context
def cli(
    ctx: click.Context,
    verbose: bool,
    model: str | None,
    base_url: str | None,
    asr_url: str | None,
    tts_url: str | None,
) -> None:
    """Build, admit, and run immutable OpenRange snapshots."""
    _configure_logging(verbose)
    overrides = BackendOverrides(
        model=model,
        base_url=base_url,
        asr_url=asr_url,
        tts_url=tts_url,
    )
    ctx.ensure_object(dict)
    ctx.obj["backend_overrides"] = overrides


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
@click.option(
    "--security-tier",
    default=1,
    show_default=True,
    type=click.IntRange(1, 5),
    help="Optional security integration tier. Tier 1 keeps the core surface only.",
)
@click.option(
    "--cluster-backend",
    default="kind",
    show_default=True,
    type=click.Choice(["kind", "k3d"]),
    help="Cluster backend used when rendering install artifacts.",
)
@click.option(
    "--network-policy-backend",
    default="kubernetes",
    show_default=True,
    type=click.Choice(["kubernetes", "cilium"]),
    help="Network policy surface to render into the chart.",
)
@click.option(
    "--k3d-agents",
    default=2,
    show_default=True,
    type=click.IntRange(0, 16),
    help="Agent node count when --cluster-backend k3d is selected.",
)
@click.option(
    "--k3d-subnet",
    default="172.29.0.0/16",
    show_default=True,
    help="Cluster subnet when --cluster-backend k3d is selected.",
)
def build_cmd(
    manifest: str,
    output: str,
    security_tier: int,
    cluster_backend: str,
    network_policy_backend: str,
    k3d_agents: int,
    k3d_subnet: str,
) -> None:
    """Compile and render a candidate world from a manifest."""
    output_dir = Path(output)
    candidate = BuildPipeline().build(
        _load_manifest(manifest),
        output_dir,
        _build_config_from_options(
            validation_profile="graph_only",
            security_tier=security_tier,
            cluster_backend=cluster_backend,
            network_policy_backend=network_policy_backend,
            k3d_agents=k3d_agents,
            k3d_subnet=k3d_subnet,
        ),
    )
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
@click.option(
    "--security-tier",
    default=1,
    show_default=True,
    type=click.IntRange(1, 5),
    help="Optional security integration tier. Tier 1 keeps the core surface only.",
)
@click.option(
    "--cluster-backend",
    default="kind",
    show_default=True,
    type=click.Choice(["kind", "k3d"]),
    help="Cluster backend used when rendering install artifacts and live checks.",
)
@click.option(
    "--network-policy-backend",
    default="kubernetes",
    show_default=True,
    type=click.Choice(["kubernetes", "cilium"]),
    help="Network policy surface to render into the chart.",
)
@click.option(
    "--k3d-agents",
    default=2,
    show_default=True,
    type=click.IntRange(0, 16),
    help="Agent node count when --cluster-backend k3d is selected.",
)
@click.option(
    "--k3d-subnet",
    default="172.29.0.0/16",
    show_default=True,
    help="Cluster subnet when --cluster-backend k3d is selected.",
)
def admit_cmd(
    manifest: str,
    output: str,
    store_dir: str,
    split: str,
    validation_profile: str,
    security_tier: int,
    cluster_backend: str,
    network_policy_backend: str,
    k3d_agents: int,
    k3d_subnet: str,
) -> None:
    """Build and admit a snapshot into the snapshot store."""
    pipeline = BuildPipeline(store=FileSnapshotStore(store_dir))
    candidate = pipeline.build(
        _load_manifest(manifest),
        Path(output),
        _build_config_from_options(
            validation_profile=validation_profile,
            security_tier=security_tier,
            cluster_backend=cluster_backend,
            network_policy_backend=network_policy_backend,
            k3d_agents=k3d_agents,
            k3d_subnet=k3d_subnet,
        ),
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
@click.option(
    "--live-cluster-backend",
    default="none",
    show_default=True,
    type=click.Choice(["none", "kind", "k3d"]),
    help="Optionally boot the admitted snapshot onto a live cluster backend.",
)
def reset_cmd(
    store_dir: str,
    snapshot_id: str | None,
    split: str,
    strategy: str,
    sample_seed: int,
    mode: str,
    horizon: float,
    live_cluster_backend: str,
) -> None:
    """Reset the runtime against an admitted snapshot and print the initial state."""
    service = OpenRange(
        store=FileSnapshotStore(store_dir),
        live_backend=_live_backend_for_option(live_cluster_backend),
    )
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
@click.option(
    "--security-tier",
    default=1,
    show_default=True,
    type=click.IntRange(1, 5),
    help="Optional security integration tier for the rendered roots and mutations.",
)
def traces_cmd(
    manifest: str,
    output: str,
    roots: int,
    mutations: int,
    include_joint_pool: bool,
    no_sim: bool,
    security_tier: int,
) -> None:
    """Generate branch-native trace datasets from admitted snapshots."""
    output_dir = Path(output)
    report = generate_trace_dataset(
        _load_manifest(manifest),
        output_dir,
        manifest_source=manifest,
        build_config=_build_config_from_options(
            validation_profile="graph_only",
            security_tier=security_tier,
        ),
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
@click.pass_context
def grpo_cmd(
    ctx: click.Context,
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
    backend_overrides: BackendOverrides = ctx.find_root().obj.get(
        "backend_overrides", BackendOverrides()
    )
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
    backend_overrides.append_grpo_args(command)
    result = subprocess.run(command, check=False)
    if result.returncode != 0:
        raise SystemExit(result.returncode)


if __name__ == "__main__":
    cli()
