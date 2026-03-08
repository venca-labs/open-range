"""OpenRange CLI -- production command-line interface for the cybersecurity gymnasium.

Usage::

    openrange build -m manifests/tier1_basic.yaml
    openrange render -s snapshots/spec.json -o output/
    openrange validate -s snapshots/spec.json
    openrange deploy -s snapshots/spec.json
    openrange server --port 8000
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

import click
import yaml

# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------

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
    # Quiet noisy third-party loggers unless in verbose mode
    if not verbose:
        for name in ("httpx", "httpcore", "litellm", "urllib3", "docker"):
            logging.getLogger(name).setLevel(logging.WARNING)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _run_async(coro: Any) -> Any:
    """Run an async coroutine from synchronous Click context."""
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    if loop and loop.is_running():
        # Shouldn't happen in a CLI, but be safe.
        import concurrent.futures

        with concurrent.futures.ThreadPoolExecutor() as pool:
            return pool.submit(asyncio.run, coro).result()
    return asyncio.run(coro)


def _load_manifest(path: str) -> dict[str, Any]:
    """Load and return a YAML manifest as a dict."""
    p = Path(path)
    if not p.exists():
        click.echo(f"Error: manifest not found: {p}", err=True)
        sys.exit(1)
    with open(p) as f:
        data = yaml.safe_load(f)
    if not isinstance(data, dict):
        click.echo(f"Error: manifest must be a YAML mapping, got {type(data).__name__}", err=True)
        sys.exit(1)
    return data


def _load_snapshot(path: str) -> "SnapshotSpec":
    """Load a snapshot JSON file into a SnapshotSpec."""
    from open_range.protocols import SnapshotSpec

    p = Path(path)
    if not p.exists():
        click.echo(f"Error: snapshot not found: {p}", err=True)
        sys.exit(1)
    with open(p) as f:
        data = json.load(f)
    try:
        return SnapshotSpec.model_validate(data)
    except Exception as exc:
        click.echo(f"Error: invalid snapshot JSON: {exc}", err=True)
        sys.exit(1)


def _write_snapshot(spec: "SnapshotSpec", output_dir: Path) -> Path:
    """Write a SnapshotSpec to spec.json inside output_dir. Returns the file path."""
    output_dir.mkdir(parents=True, exist_ok=True)
    dest = output_dir / "spec.json"
    dest.write_text(json.dumps(spec.model_dump(), indent=2, default=str))
    return dest


def _parse_roles(raw: str) -> tuple[str, ...]:
    """Parse a comma-separated role list."""
    roles = tuple(dict.fromkeys(part.strip().lower() for part in raw.split(",") if part.strip()))
    valid = {"red", "blue"}
    invalid = [role for role in roles if role not in valid]
    if invalid:
        click.echo(
            f"Error: invalid roles: {', '.join(invalid)}. Expected comma-separated values from: red, blue.",
            err=True,
        )
        sys.exit(1)
    if not roles:
        click.echo("Error: at least one role must be selected.", err=True)
        sys.exit(1)
    return roles


# ---------------------------------------------------------------------------
# CLI group
# ---------------------------------------------------------------------------


@click.group()
@click.option("-v", "--verbose", is_flag=True, default=False, help="Enable debug logging.")
@click.version_option(package_name="openenv-open-range", prog_name="openrange")
def cli(verbose: bool) -> None:
    """OpenRange -- multi-agent cybersecurity gymnasium.

    Generate, validate, deploy, and serve Docker-based cyber ranges
    for adversarial Red/Blue agent training.
    """
    _configure_logging(verbose)


# ---------------------------------------------------------------------------
# build
# ---------------------------------------------------------------------------


@cli.command()
@click.option("-m", "--manifest", required=True, type=click.Path(exists=True), help="Path to manifest YAML.")
@click.option("-o", "--output", default="./snapshots", type=click.Path(), help="Output directory for snapshot.")
@click.option("--model", default=None, help="LLM model (default: $OPENRANGE_BUILDER_MODEL or azure/gpt-5.2-codex).")
@click.option("--tier", default=1, type=click.IntRange(1, 5), help="Tier level 1-5.")
@click.option("--seed", default=None, type=int, help="Random seed for reproducibility.")
@click.option("--template-only", is_flag=True, default=False, help="Skip LLM, use deterministic template builder.")
@click.option("--max-tokens", default=16384, type=int, help="Max tokens for LLM generation.")
def build(
    manifest: str,
    output: str,
    model: str | None,
    tier: int,
    seed: int | None,
    template_only: bool,
    max_tokens: int,
) -> None:
    """Generate a snapshot from a manifest YAML.

    Uses the LLM builder by default. Pass --template-only for a deterministic
    snapshot without any LLM calls (useful for testing).
    """
    from open_range.builder.builder import LLMSnapshotBuilder, TemplateOnlyBuilder
    from open_range.protocols import BuildContext

    manifest_data = _load_manifest(manifest)
    context = BuildContext(seed=seed, tier=tier)

    if template_only:
        builder = TemplateOnlyBuilder()
        click.echo(f"Building snapshot (template-only, tier {tier}) ...")
    else:
        resolved_model = model or os.environ.get("OPENRANGE_BUILDER_MODEL", "azure/gpt-5.2-codex")
        builder = LLMSnapshotBuilder(model=resolved_model, max_tokens=max_tokens)
        click.echo(f"Building snapshot (model={resolved_model}, tier {tier}) ...")

    t0 = time.monotonic()
    try:
        spec = _run_async(builder.build(manifest_data, context))
    except Exception as exc:
        click.echo(f"Error: build failed: {exc}", err=True)
        sys.exit(1)
    elapsed = time.monotonic() - t0

    output_path = Path(output)
    dest = _write_snapshot(spec, output_path)

    n_vulns = len(spec.truth_graph.vulns)
    n_steps = len(spec.golden_path)
    n_flags = len(spec.flags)

    click.echo(f"Snapshot written to {dest}")
    click.echo(f"  Vulnerabilities: {n_vulns}")
    click.echo(f"  Golden path steps: {n_steps}")
    click.echo(f"  Flags: {n_flags}")
    click.echo(f"  Elapsed: {elapsed:.1f}s")


# ---------------------------------------------------------------------------
# synthetic-data
# ---------------------------------------------------------------------------


@cli.command("synthetic-data")
@click.option("-o", "--output", required=True, type=click.Path(), help="Output JSONL path for synthetic trajectories.")
@click.option("-m", "--manifest", default=None, type=click.Path(exists=True), help="Path to manifest YAML.")
@click.option("-s", "--snapshot", default=None, type=click.Path(exists=True), help="Path to snapshot JSON.")
@click.option("--num-traces", default=10, type=click.IntRange(1), help="Number of synthetic episodes to generate.")
@click.option("--seed", default=None, type=int, help="Base random seed for reproducibility.")
@click.option("--tier", default=1, type=click.IntRange(1, 5), help="Tier level 1-5 when building from a manifest.")
@click.option("--max-steps", default=12, type=click.IntRange(1), help="Maximum red/blue turns per episode.")
@click.option("--roles", default="red", help="Comma-separated teacher/export roles: red, blue.")
@click.option("--reward-threshold", default=0.0, type=float, help="Minimum total role reward required for export.")
@click.option("--teacher-model", default=None, help="LiteLLM teacher model. If omitted, selected roles use scripted agents.")
@click.option("--red-model", default=None, help="Override model for Red teacher.")
@click.option("--blue-model", default=None, help="Override model for Blue teacher.")
@click.option("--temperature", default=0.2, type=float, help="Teacher sampling temperature.")
@click.option("--max-tokens", default=512, type=int, help="Maximum completion tokens per teacher action.")
@click.option("--template-only/--llm-builder", default=True, help="When using --manifest, build snapshots deterministically instead of via LLM.")
@click.option("--builder-model", default=None, help="LLM builder model when using --llm-builder.")
@click.option("--randomize-flags/--static-flags", default=True, help="Randomize flag values per synthetic episode.")
def synthetic_data(
    output: str,
    manifest: str | None,
    snapshot: str | None,
    num_traces: int,
    seed: int | None,
    tier: int,
    max_steps: int,
    roles: str,
    reward_threshold: float,
    teacher_model: str | None,
    red_model: str | None,
    blue_model: str | None,
    temperature: float,
    max_tokens: int,
    template_only: bool,
    builder_model: str | None,
    randomize_flags: bool,
) -> None:
    """Generate snapshot-grounded synthetic SFT trajectories."""
    from open_range.training.synthetic import (
        SyntheticTraceGenerator,
        build_teacher_agents,
    )

    if bool(manifest) == bool(snapshot):
        click.echo("Error: provide exactly one of --manifest or --snapshot.", err=True)
        sys.exit(1)

    selected_roles = _parse_roles(roles)
    resolved_teacher_model = (
        teacher_model
        or os.environ.get("OPENRANGE_SYNTH_MODEL")
    )
    red_agent, blue_agent = build_teacher_agents(
        teacher_model=resolved_teacher_model,
        roles=selected_roles,
        red_model=red_model,
        blue_model=blue_model,
        temperature=temperature,
        max_tokens=max_tokens,
    )

    if snapshot:
        source_label = f"snapshot={snapshot}"
        generator = SyntheticTraceGenerator(
            snapshot=_load_snapshot(snapshot),
            red_agent=red_agent,
            blue_agent=blue_agent,
            tier=tier,
            max_steps=max_steps,
            randomize_flags=randomize_flags,
        )
    else:
        source_label = f"manifest={manifest}"
        generator = SyntheticTraceGenerator.from_manifest(
            _load_manifest(str(manifest)),
            red_agent=red_agent,
            blue_agent=blue_agent,
            template_only=template_only,
            builder_model=builder_model,
            tier=tier,
            max_steps=max_steps,
            randomize_flags=randomize_flags,
        )

    teacher_roles = []
    if selected_roles:
        if red_model or resolved_teacher_model:
            if "red" in selected_roles:
                teacher_roles.append("red")
        if blue_model or resolved_teacher_model:
            if "blue" in selected_roles:
                teacher_roles.append("blue")

    click.echo(f"Generating synthetic traces from {source_label} ...")
    click.echo(f"  Roles: {', '.join(selected_roles)}")
    click.echo(
        "  Teacher roles: "
        + (", ".join(teacher_roles) if teacher_roles else "none (scripted fallbacks)")
    )
    try:
        logger, count = generator.export_jsonl(
            output,
            num_traces=num_traces,
            seed=seed,
            reward_threshold=reward_threshold,
            roles=selected_roles,
        )
    except Exception as exc:
        click.echo(f"Error: synthetic data generation failed: {exc}", err=True)
        sys.exit(1)

    click.echo(f"Wrote {count} JSONL records to {output}")
    click.echo(f"  Episodes: {len(logger.episodes)}")
    click.echo(f"  Randomized flags: {'yes' if randomize_flags else 'no'}")


# ---------------------------------------------------------------------------
# render
# ---------------------------------------------------------------------------


@cli.command()
@click.option("-s", "--snapshot", required=True, type=click.Path(exists=True), help="Path to snapshot JSON.")
@click.option("-o", "--output", required=True, type=click.Path(), help="Output directory for Helm chart and Kind config.")
def render(snapshot: str, output: str) -> None:
    """Render a snapshot JSON into a Helm chart targeting Kind."""
    from open_range.builder.renderer import KindRenderer

    spec = _load_snapshot(snapshot)
    renderer = KindRenderer()
    output_path = Path(output)

    click.echo(f"Rendering snapshot to {output_path} ...")
    try:
        renderer.render(spec, output_path)
    except Exception as exc:
        click.echo(f"Error: render failed: {exc}", err=True)
        sys.exit(1)

    # List produced files
    if output_path.exists():
        artifacts = sorted(p.name for p in output_path.iterdir() if p.is_file())
        click.echo(f"Produced {len(artifacts)} artifacts:")
        for name in artifacts:
            click.echo(f"  {name}")
        chart_dir = output_path / "openrange"
        if chart_dir.is_dir():
            click.echo(f"  openrange/ (Helm chart)")


# ---------------------------------------------------------------------------
# validate
# ---------------------------------------------------------------------------

# Canonical name -> check class. The order matches the 10-check pipeline.
_CHECK_REGISTRY: dict[str, str] = {
    "build_boot": "open_range.validator.build_boot.BuildBootCheck",
    "exploitability": "open_range.validator.exploitability.ExploitabilityCheck",
    "patchability": "open_range.validator.patchability.PatchabilityCheck",
    "evidence": "open_range.validator.evidence.EvidenceCheck",
    "reward_grounding": "open_range.validator.reward_grounding.RewardGroundingCheck",
    "isolation": "open_range.validator.isolation.IsolationCheck",
    "task_feasibility": "open_range.validator.task_feasibility.TaskFeasibilityCheck",
    "difficulty": "open_range.validator.difficulty.DifficultyCheck",
    "npc_consistency": "open_range.validator.npc_consistency.NPCConsistencyCheck",
    "realism_review": "open_range.validator.realism_review.RealismReviewCheck",
}

# Checks that require running Docker containers.
_DOCKER_CHECKS = {
    "build_boot",
    "exploitability",
    "patchability",
    "evidence",
    "reward_grounding",
    "isolation",
}

_LLM_CHECKS = {"npc_consistency", "realism_review"}


def _import_check(dotted: str) -> Any:
    """Import a check class by dotted path."""
    module_path, class_name = dotted.rsplit(".", 1)
    import importlib

    mod = importlib.import_module(module_path)
    return getattr(mod, class_name)


@cli.command()
@click.option("-s", "--snapshot", required=True, type=click.Path(exists=True), help="Path to snapshot JSON.")
@click.option("--checks", default=None, help="Comma-separated check names (default: all applicable).")
@click.option("--docker/--no-docker", default=False, help="Include Docker-dependent checks (requires running containers).")
def validate(snapshot: str, checks: str | None, docker: bool) -> None:
    """Run validator checks against a snapshot.

    By default runs only offline mechanical checks. Use --docker
    to include checks that need live containers, or --checks to opt into
    advisory LLM checks explicitly.

    Available checks: build_boot, exploitability, patchability, evidence,
    reward_grounding, isolation, task_feasibility, difficulty,
    npc_consistency, realism_review.
    """
    from open_range.protocols import ContainerSet
    from open_range.validator.validator import ValidatorGate

    spec = _load_snapshot(snapshot)

    # Determine which checks to run
    if checks:
        names = [n.strip() for n in checks.split(",")]
        unknown = [n for n in names if n not in _CHECK_REGISTRY]
        if unknown:
            click.echo(f"Error: unknown checks: {', '.join(unknown)}", err=True)
            click.echo(f"Available: {', '.join(_CHECK_REGISTRY)}", err=True)
            sys.exit(1)
    else:
        if docker:
            names = list(_CHECK_REGISTRY)
        else:
            names = [n for n in _CHECK_REGISTRY if n not in _DOCKER_CHECKS and n not in _LLM_CHECKS]

    if not names:
        click.echo("No checks selected.")
        sys.exit(0)

    # Instantiate checks
    check_instances = []
    for name in names:
        cls = _import_check(_CHECK_REGISTRY[name])
        check_instances.append(cls())

    # Containers stub for offline mode, real discovery for docker mode
    containers = ContainerSet()
    gate = ValidatorGate(check_instances)
    click.echo(f"Running {len(check_instances)} checks ...")

    if docker:
        from open_range.builder.renderer import KindRenderer
        from open_range.server.helm_runner import HelmRunner

        with tempfile.TemporaryDirectory(prefix="openrange-validate-") as tmpdir:
            artifacts_dir = Path(tmpdir)
            renderer = KindRenderer()
            click.echo(f"Rendering Helm chart to {artifacts_dir} ...")
            try:
                renderer.render(spec, artifacts_dir)
            except Exception as exc:
                click.echo(f"Error: render failed: {exc}", err=True)
                sys.exit(1)

            chart_path = artifacts_dir / "openrange"
            values_path = chart_path / "values.yaml"
            if not chart_path.exists():
                click.echo(f"Error: no openrange/ chart found in {artifacts_dir}", err=True)
                sys.exit(1)

            rendered_spec = spec.model_copy(deep=True)
            if values_path.exists():
                rendered_spec.compose = yaml.safe_load(values_path.read_text(encoding="utf-8")) or {}

            snapshot_id = rendered_spec.lineage.snapshot_id or Path(snapshot).stem or "validation"
            click.echo("Booting temporary Helm release for validation ...")
            runner = HelmRunner()
            project = None
            try:
                project = runner.boot(
                    snapshot_id=snapshot_id,
                    artifacts_dir=artifacts_dir,
                    compose=rendered_spec.compose,
                )
                containers = project.containers
                result = _run_async(gate.validate(rendered_spec, containers))
            finally:
                if project is not None:
                    runner.teardown(project)
    else:
        result = _run_async(gate.validate(spec, containers))

    # Print results
    for cr in result.checks:
        status = "PASS" if cr.passed else ("ADVISORY" if cr.advisory else "FAIL")
        line = f"  [{status}] {cr.name}"
        if cr.time_s > 0:
            line += f" ({cr.time_s:.2f}s)"
        click.echo(line)
        if cr.error:
            click.echo(f"         {cr.error}")

    click.echo("")
    if result.passed:
        click.echo(f"Validation PASSED ({result.total_time_s:.2f}s)")
    else:
        click.echo(f"Validation FAILED ({result.total_time_s:.2f}s)")
        sys.exit(1)


# ---------------------------------------------------------------------------
# deploy
# ---------------------------------------------------------------------------


@cli.command()
@click.option("-s", "--snapshot", required=True, type=click.Path(exists=True), help="Path to snapshot JSON.")
@click.option("--chart-dir", default=None, type=click.Path(), help="Directory for rendered Helm chart (default: deploy/ next to snapshot).")
def deploy(snapshot: str, chart_dir: str | None) -> None:
    """Deploy a snapshot to a Kind cluster.

    Renders the snapshot into a Helm chart, creates a Kind cluster,
    and installs the chart.
    """
    import subprocess

    from open_range.builder.renderer import KindRenderer

    spec = _load_snapshot(snapshot)

    if chart_dir:
        target = Path(chart_dir)
    else:
        target = Path(snapshot).parent / "deploy"

    # Render Helm chart + Kind config
    renderer = KindRenderer()
    click.echo(f"Rendering Helm chart to {target} ...")
    try:
        renderer.render(spec, target)
    except Exception as exc:
        click.echo(f"Error: render failed: {exc}", err=True)
        sys.exit(1)

    kind_config = target / "kind-config.yaml"
    chart_path = target / "openrange"
    if not chart_path.exists():
        click.echo(f"Error: no openrange/ chart found in {target}", err=True)
        sys.exit(1)

    click.echo("Creating Kind cluster ...")
    try:
        proc = subprocess.run(
            ["kind", "create", "cluster", "--config", str(kind_config)],
            capture_output=True,
            text=True,
            timeout=300,
        )
    except FileNotFoundError:
        click.echo("Error: kind command not found. Install Kind: https://kind.sigs.k8s.io/", err=True)
        sys.exit(1)
    except subprocess.TimeoutExpired:
        click.echo("Error: kind create cluster timed out after 300s.", err=True)
        sys.exit(1)

    if proc.returncode != 0:
        click.echo(f"Error: kind create cluster failed (exit {proc.returncode}):", err=True)
        if proc.stderr:
            click.echo(proc.stderr, err=True)
        sys.exit(1)

    click.echo("Kind cluster created. Installing Helm chart ...")
    try:
        proc = subprocess.run(
            ["helm", "install", "openrange", str(chart_path)],
            capture_output=True,
            text=True,
            timeout=120,
        )
    except FileNotFoundError:
        click.echo("Error: helm command not found. Install Helm: https://helm.sh/", err=True)
        sys.exit(1)
    except subprocess.TimeoutExpired:
        click.echo("Error: helm install timed out after 120s.", err=True)
        sys.exit(1)

    if proc.returncode != 0:
        click.echo(f"Error: helm install failed (exit {proc.returncode}):", err=True)
        if proc.stderr:
            click.echo(proc.stderr, err=True)
        sys.exit(1)

    click.echo("Helm chart installed.")

    # Show pod status
    try:
        ps = subprocess.run(
            ["kubectl", "get", "pods", "--all-namespaces", "-l", "app.kubernetes.io/part-of=openrange"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if ps.stdout:
            click.echo(ps.stdout)
    except Exception:
        pass  # Non-critical


# ---------------------------------------------------------------------------
# server
# ---------------------------------------------------------------------------


@cli.command()
@click.option("--host", default="0.0.0.0", help="Host to bind.")
@click.option("--port", default=8000, type=int, help="Port to listen on.")
@click.option("--mock/--no-mock", default=False, help="Use mock mode (no Docker required).")
def server(host: str, port: int, mock: bool) -> None:
    """Start the OpenEnv server.

    In mock mode, the environment simulates container interactions without
    requiring a running Docker stack.
    """
    import uvicorn

    if mock:
        os.environ["OPENRANGE_MOCK"] = "1"
        click.echo(f"Starting OpenRange server in MOCK mode on {host}:{port} ...")
    else:
        click.echo(f"Starting OpenRange server on {host}:{port} ...")

    try:
        uvicorn.run(
            "open_range.server.app:app",
            host=host,
            port=port,
            log_level="info",
        )
    except Exception as exc:
        click.echo(f"Error: server failed: {exc}", err=True)
        sys.exit(1)


# ---------------------------------------------------------------------------
# Train command
# ---------------------------------------------------------------------------


@cli.command()
@click.option(
    "--model", default="Qwen/Qwen3.5-4B",
    help="HuggingFace model name (e.g. Qwen/Qwen3.5-4B, Qwen/Qwen3.5-9B).",
)
@click.option(
    "--data", "data_paths", multiple=True, required=True,
    help="Path(s) to JSONL SFT data files.",
)
@click.option("--output", "output_dir", default="outputs/sft", help="Output directory.")
@click.option("--merge-output", "merge_output_dir", default=None, help="Also save merged model here.")
@click.option("--epochs", default=3, type=int, help="Number of training epochs.")
@click.option("--batch-size", default=2, type=int, help="Per-device batch size.")
@click.option("--lr", "learning_rate", default=2e-5, type=float, help="Learning rate.")
@click.option("--lora-r", default=16, type=int, help="LoRA rank.")
@click.option("--lora-alpha", default=16, type=int, help="LoRA alpha.")
@click.option("--max-seq-length", default=0, type=int, help="Max sequence length (0=auto from data).")
@click.option("--min-reward", default=None, type=float, help="Filter samples below this reward.")
def train(
    model: str,
    data_paths: tuple[str, ...],
    output_dir: str,
    merge_output_dir: str | None,
    epochs: int,
    batch_size: int,
    learning_rate: float,
    lora_r: int,
    lora_alpha: int,
    max_seq_length: int,
    min_reward: float | None,
) -> None:
    """Run Unsloth SFT training on OpenRange CTF trajectories.

    Converts OpenAI-style tool_calls to qwen3_coder XML for Qwen3.5.
    Auto-detects sequence length from data (no truncation).

    Example::

        openrange train --model Qwen/Qwen3.5-4B --data data/sft.jsonl
        openrange train --model Qwen/Qwen3.5-4B --data data/sft.jsonl --merge-output outputs/merged
    """
    from open_range.training.sft_trainer import SFTConfig, run_sft

    config = SFTConfig(
        model_name=model,
        data_paths=list(data_paths),
        output_dir=output_dir,
        merge_output_dir=merge_output_dir,
        epochs=epochs,
        batch_size=batch_size,
        learning_rate=learning_rate,
        lora_r=lora_r,
        lora_alpha=lora_alpha,
        max_seq_length=max_seq_length,
        min_reward=min_reward,
    )

    click.echo(f"Training {model} on {len(data_paths)} data file(s)")
    click.echo(f"  LoRA: r={lora_r}, alpha={lora_alpha}")
    click.echo(f"  Epochs: {epochs}, Batch: {batch_size}, LR: {learning_rate}")
    click.echo(f"  Output: {output_dir}")
    if merge_output_dir:
        click.echo(f"  Merge: {merge_output_dir}")

    try:
        result = run_sft(config)
        click.echo(f"\nDone! Loss: {result['training_loss']:.4f}")
        click.echo(f"  Samples: {result['num_samples']}")
        click.echo(f"  Seq length: {result['max_seq_length']}")
        click.echo(f"  LoRA adapter: {result['lora_adapter']}")
        if result.get("merged_model"):
            click.echo(f"  Merged model: {result['merged_model']}")
    except Exception as exc:
        click.echo(f"Error: {exc}", err=True)
        sys.exit(1)


# ---------------------------------------------------------------------------
# GRPO command
# ---------------------------------------------------------------------------


@cli.command()
@click.option(
    "--model", default="outputs/sft-merged",
    help="HuggingFace model or local path (start from SFT checkpoint).",
)
@click.option(
    "--data", "data_paths", multiple=True, required=True,
    help="Path(s) to JSONL online RL data files.",
)
@click.option("--output", "output_dir", default="outputs/grpo", help="Output directory.")
@click.option("--merge-output", "merge_output_dir", default=None, help="Also save merged model here.")
@click.option("--reward", "reward_mode", default="progressive",
              type=click.Choice(["binary", "progressive", "online"]),
              help="Reward function: binary (flag only), progressive (multi-signal), online (live env).")
@click.option("--env-url", default=None, help="OpenRange server URL (required for --reward online).")
@click.option("--num-generations", default=4, type=int, help="Completions per prompt.")
@click.option("--max-completion-length", default=2048, type=int, help="Max tokens per completion.")
@click.option("--max-seq-length", default=4096, type=int, help="Max sequence length.")
@click.option("--batch-size", default=1, type=int, help="Per-device batch size.")
@click.option("--lr", "learning_rate", default=5e-6, type=float, help="Learning rate.")
@click.option("--lora-r", default=16, type=int, help="LoRA rank.")
@click.option("--beta", default=0.04, type=float, help="KL penalty coefficient.")
@click.option("--temperature", default=0.7, type=float, help="Sampling temperature.")
def grpo(
    model: str,
    data_paths: tuple[str, ...],
    output_dir: str,
    merge_output_dir: str | None,
    reward_mode: str,
    env_url: str | None,
    num_generations: int,
    max_completion_length: int,
    max_seq_length: int,
    batch_size: int,
    learning_rate: float,
    lora_r: int,
    beta: float,
    temperature: float,
) -> None:
    """Run Unsloth GRPO training on CTF trajectories.

    Uses progressive reward by default (flag + format + efficiency + progression).
    Binary reward checks flag capture only. Online reward executes against a live
    OpenRange environment.

    Example::

        openrange grpo --model outputs/sft-merged --data data/online_rl.jsonl
        openrange grpo --model outputs/sft-merged --data data/online_rl.jsonl --reward binary
        openrange grpo --model outputs/sft-merged --data data/online_rl.jsonl --reward online --env-url http://localhost:8000
    """
    from open_range.training.grpo_trainer import GRPOConfig, run_grpo

    if reward_mode == "online" and not env_url:
        click.echo("Error: --env-url required for online reward mode.", err=True)
        sys.exit(1)

    config = GRPOConfig(
        model_name=model,
        data_paths=list(data_paths),
        output_dir=output_dir,
        merge_output_dir=merge_output_dir,
        reward_mode=reward_mode,
        env_url=env_url,
        num_generations=num_generations,
        max_completion_length=max_completion_length,
        max_seq_length=max_seq_length,
        batch_size=batch_size,
        learning_rate=learning_rate,
        lora_r=lora_r,
        beta=beta,
        temperature=temperature,
    )

    click.echo(f"GRPO training: {model}")
    click.echo(f"  Reward: {reward_mode}")
    click.echo(f"  Generations/prompt: {num_generations}")
    click.echo(f"  LoRA: r={lora_r}, LR: {learning_rate}")
    click.echo(f"  Output: {output_dir}")

    try:
        result = run_grpo(config)
        click.echo(f"\nDone! Loss: {result['training_loss']:.4f}")
        click.echo(f"  Prompts: {result['num_prompts']}")
        click.echo(f"  Reward mode: {result['reward_mode']}")
        click.echo(f"  LoRA adapter: {result['lora_adapter']}")
        if result.get("merged_model"):
            click.echo(f"  Merged model: {result['merged_model']}")
    except Exception as exc:
        click.echo(f"Error: {exc}", err=True)
        sys.exit(1)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    cli()
