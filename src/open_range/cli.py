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
@click.option("--bootstrap-traces", multiple=True, type=click.Path(exists=True), help="Existing SFT JSONL files to merge into the output.")
@click.option("--bootstrap-examples", default=0, type=click.IntRange(0), help="How many bootstrap traces to inject as few-shot examples per generated role.")
@click.option("--merge-bootstrap/--generated-only", default=True, help="Merge bootstrap traces into the output file, or emit only newly generated records.")
@click.option("--tool-info", multiple=True, type=click.Path(exists=True), help="Text, JSON, or YAML tool catalog file to append to generated system prompts.")
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
    bootstrap_traces: tuple[str, ...],
    bootstrap_examples: int,
    merge_bootstrap: bool,
    tool_info: tuple[str, ...],
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
    from open_range.training.dataset import (
        append_tool_context,
        extract_bootstrap_messages,
        load_jsonl_records,
        load_tool_context,
        write_jsonl_records,
    )

    if bool(manifest) == bool(snapshot):
        click.echo("Error: provide exactly one of --manifest or --snapshot.", err=True)
        sys.exit(1)

    selected_roles = _parse_roles(roles)
    resolved_teacher_model = (
        teacher_model
        or os.environ.get("OPENRANGE_SYNTH_MODEL")
    )
    bootstrap_records = load_jsonl_records(bootstrap_traces) if bootstrap_traces else []
    tool_context = load_tool_context(tool_info) if tool_info else ""
    red_agent, blue_agent = build_teacher_agents(
        teacher_model=resolved_teacher_model,
        roles=selected_roles,
        red_model=red_model,
        blue_model=blue_model,
        red_bootstrap_messages=extract_bootstrap_messages(
            bootstrap_records,
            role="red",
            limit=bootstrap_examples,
        ),
        blue_bootstrap_messages=extract_bootstrap_messages(
            bootstrap_records,
            role="blue",
            limit=bootstrap_examples,
        ),
        red_system_suffix=tool_context,
        blue_system_suffix=tool_context,
        temperature=temperature,
        max_tokens=max_tokens,
    )

    if snapshot:
        source_label = f"snapshot={snapshot}"
        generator = SyntheticTraceGenerator(
            snapshot=_load_snapshot(snapshot),
            red_agent=red_agent,
            blue_agent=blue_agent,
            active_roles=selected_roles,
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
            active_roles=selected_roles,
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
        logger = generator.generate(
            num_traces=num_traces,
            seed=seed,
        )
        generated_records = logger.to_records(
            reward_threshold=reward_threshold,
            roles=selected_roles,
        )
        if tool_context:
            generated_records = append_tool_context(
                generated_records,
                tool_context,
            )

        records_to_write = [*bootstrap_records, *generated_records] if merge_bootstrap else generated_records
        count = write_jsonl_records(output, records_to_write)
        generated_count = len(generated_records)
        bootstrap_count = len(bootstrap_records)
    except Exception as exc:
        click.echo(f"Error: synthetic data generation failed: {exc}", err=True)
        sys.exit(1)

    click.echo(f"Wrote {count} JSONL records to {output}")
    click.echo(f"  Generated records: {generated_count}")
    if bootstrap_traces and merge_bootstrap:
        click.echo(f"  Bootstrap records: {bootstrap_count}")
    elif bootstrap_traces:
        click.echo(f"  Bootstrap records loaded for prompting only: {bootstrap_count}")
    if bootstrap_examples:
        click.echo(f"  Few-shot bootstrap examples per role: {bootstrap_examples}")
    if tool_info:
        click.echo(f"  Tool catalogs applied: {len(tool_info)}")
    click.echo(f"  Episodes: {len(logger.episodes)}")
    click.echo(f"  Randomized flags: {'yes' if randomize_flags else 'no'}")


# ---------------------------------------------------------------------------
# render
# ---------------------------------------------------------------------------


@cli.command()
@click.option("-s", "--snapshot", required=True, type=click.Path(exists=True), help="Path to snapshot JSON.")
@click.option("-o", "--output", required=True, type=click.Path(), help="Output directory for Docker artifacts.")
def render(snapshot: str, output: str) -> None:
    """Render a snapshot JSON into Docker artifacts (Dockerfiles, compose, configs)."""
    from open_range.builder.renderer import SnapshotRenderer

    spec = _load_snapshot(snapshot)
    renderer = SnapshotRenderer()
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
_DOCKER_CHECKS = {"build_boot", "exploitability", "patchability", "evidence", "reward_grounding"}


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

    By default runs only offline checks (no Docker required). Use --docker
    to include checks that need live containers.

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
            names = [n for n in _CHECK_REGISTRY if n not in _DOCKER_CHECKS]

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
@click.option("--compose-dir", default=None, type=click.Path(), help="Directory containing docker-compose.yml (default: render into temp dir).")
def deploy(snapshot: str, compose_dir: str | None) -> None:
    """Deploy a snapshot to running Docker containers.

    Renders the snapshot into Docker artifacts and runs docker compose up.
    If --compose-dir is given, uses that directory; otherwise renders into
    a temporary directory alongside the snapshot.
    """
    import subprocess

    from open_range.builder.renderer import SnapshotRenderer

    spec = _load_snapshot(snapshot)

    if compose_dir:
        target = Path(compose_dir)
    else:
        target = Path(snapshot).parent / "deploy"

    # Render artifacts
    renderer = SnapshotRenderer()
    click.echo(f"Rendering Docker artifacts to {target} ...")
    try:
        renderer.render(spec, target)
    except Exception as exc:
        click.echo(f"Error: render failed: {exc}", err=True)
        sys.exit(1)

    compose_file = target / "docker-compose.yml"
    if not compose_file.exists():
        click.echo(f"Error: no docker-compose.yml found in {target}", err=True)
        sys.exit(1)

    click.echo("Starting containers with docker compose ...")
    try:
        proc = subprocess.run(
            ["docker", "compose", "-f", str(compose_file), "up", "-d", "--build"],
            cwd=str(target),
            capture_output=True,
            text=True,
            timeout=300,
        )
    except FileNotFoundError:
        click.echo("Error: docker command not found. Is Docker installed and in PATH?", err=True)
        sys.exit(1)
    except subprocess.TimeoutExpired:
        click.echo("Error: docker compose up timed out after 300s.", err=True)
        sys.exit(1)

    if proc.returncode != 0:
        click.echo(f"Error: docker compose up failed (exit {proc.returncode}):", err=True)
        if proc.stderr:
            click.echo(proc.stderr, err=True)
        sys.exit(1)

    click.echo("Containers started.")

    # Show running container status
    try:
        ps = subprocess.run(
            ["docker", "compose", "-f", str(compose_file), "ps", "--format", "table"],
            cwd=str(target),
            capture_output=True,
            text=True,
            timeout=30,
        )
        if ps.stdout:
            click.echo(ps.stdout)
    except Exception:
        pass  # Non-critical


# ---------------------------------------------------------------------------
# episode
# ---------------------------------------------------------------------------


@cli.command()
@click.option("-s", "--snapshot", required=True, type=click.Path(exists=True), help="Path to snapshot JSON.")
@click.option("--mode", default="red", type=click.Choice(["red", "blue", "both"]), help="Agent role(s) to play.")
@click.option("--golden-path", "golden", is_flag=True, default=False, help="Replay golden path steps (Red only).")
@click.option("--interactive", is_flag=True, default=False, help="Interactive mode (read commands from stdin).")
@click.option("--docker/--no-docker", default=False, help="Use Docker containers (default: mock mode).")
@click.option("--max-steps", default=50, type=click.IntRange(1), help="Maximum steps per episode.")
def episode(
    snapshot: str,
    mode: str,
    golden: bool,
    interactive: bool,
    docker: bool,
    max_steps: int,
) -> None:
    """Run an episode against a snapshot.

    Golden-path mode replays the snapshot's golden path commands as Red.
    Interactive mode reads commands from stdin. Default runs golden path
    if available, otherwise enters interactive mode.

    \b
    Examples:
        openrange episode -s snapshots/spec.json --golden-path
        openrange episode -s snapshots/spec.json --interactive --mode both
    """
    from open_range.models import RangeAction
    from open_range.server.environment import RangeEnvironment

    spec = _load_snapshot(snapshot)

    env = RangeEnvironment(docker_available=docker, max_steps=max_steps)
    obs = env.reset(snapshot=spec, episode_id="cli-episode")
    click.echo(f"[RESET] {obs.stdout[:200]}")
    click.echo()

    if golden or (not interactive and spec.golden_path):
        # Golden path replay
        if not spec.golden_path:
            click.echo("Error: snapshot has no golden path steps.", err=True)
            sys.exit(1)

        click.echo(f"Replaying {len(spec.golden_path)} golden path steps ...\n")
        for gp in spec.golden_path:
            action = RangeAction(command=gp.command, mode="red")
            result = env.step(action)
            reward = result.reward if result.reward is not None else 0.0

            status = ""
            if result.flags_captured:
                status = f" FLAGS={result.flags_captured}"
            if result.done:
                status += " [DONE]"

            click.echo(f"  [{gp.step:2d}] RED >> {gp.command[:80]}")
            if docker:
                stdout_preview = result.stdout[:120].replace("\n", " ")
                click.echo(f"       stdout: {stdout_preview}")
            else:
                click.echo(f"       expect: {gp.expect_in_stdout[:60]}")
            click.echo(f"       reward={reward:.4f}{status}")

            if result.done:
                break

    elif interactive:
        # Interactive REPL
        click.echo("Interactive mode. Type commands, Ctrl-D to exit.\n")
        current_mode = mode if mode != "both" else "red"
        try:
            while True:
                prompt = f"[{current_mode.upper()}] >> "
                try:
                    cmd = input(prompt)
                except EOFError:
                    break
                if not cmd.strip():
                    continue
                if cmd.strip() == "/switch" and mode == "both":
                    current_mode = "blue" if current_mode == "red" else "red"
                    click.echo(f"Switched to {current_mode.upper()}")
                    continue

                action = RangeAction(command=cmd, mode=current_mode)
                result = env.step(action)
                if result.stdout:
                    click.echo(result.stdout)
                if result.stderr:
                    click.echo(result.stderr, err=True)
                reward = result.reward if result.reward is not None else 0.0
                click.echo(f"[reward={reward:.4f}]")
                if result.done:
                    click.echo("[EPISODE DONE]")
                    break
        except KeyboardInterrupt:
            click.echo("\nInterrupted.")
    else:
        click.echo("No golden path and --interactive not set. Use --interactive for manual play.", err=True)
        sys.exit(1)

    # Print final state
    state = env.state
    click.echo(f"\n{'='*60}")
    click.echo(f"  RESULT")
    click.echo(f"{'='*60}")
    click.echo(f"  Steps:       {state.step_count}")
    click.echo(f"  Flags found: {state.flags_found}")
    click.echo(f"  Tier:        {state.tier}")
    click.echo(f"  Episode:     {state.episode_id}")
    click.echo(f"{'='*60}")


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
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    cli()
