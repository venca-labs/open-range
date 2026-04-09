<div align="center">
  <h1>OpenRange</h1>
  <img src="assets/evolving_gym_hero.png" alt="OpenRange: validator-admitted enterprise cyber range" width="800" />
  <br />
  <br />
  <img src="https://img.shields.io/badge/Package-open--range-blue" alt="Package: open-range" />
  <img src="https://img.shields.io/badge/Runtime-red%2Fblue%2Fgreen-red" alt="Runtime: red/blue/green" />
  <img src="https://img.shields.io/badge/License-Apache_2.0-blue.svg" alt="License: Apache 2.0" />
</div>

OpenRange is a manifest-first cyber range for training red and blue agents in
bounded enterprise worlds. It compiles a business manifest into a world,
validates that world with private reference traces and deterministic probes,
freezes it as an immutable snapshot, and runs episodes with red, blue, and
green-user dynamics.

## Why OpenRange

Static cyber tasks are useful for evaluation, but they are a weak training
target. They are fixed, narrow, easy to memorize, and usually offense-only.
OpenRange is aimed at the opposite shape: families of admitted enterprise-like
worlds that can be replayed, mutated between snapshots, and used for runtime and
training-data generation.

|  | Static cyber task | OpenRange |
|--|-------------------|-----------|
| **World** | One fixed puzzle | Admitted enterprise world from a manifest |
| **Reset** | Same challenge again | Load a stored snapshot from a pool |
| **Validation** | Often manual or benchmark-specific | Deterministic admission with private references |
| **Roles** | Usually red only | Red, blue, and green in one runtime |
| **Training data** | External transcripts or logs | Branch-native traces from admitted snapshots |

## Try it now

The fastest way to experience OpenRange locally is directly through the PyPI package. This requires no external dependencies and runs the engine fully offline over a synthetic simulation plane.

```bash
pip install open-range
openrange admit -m tier1_basic.yaml -o /tmp/openrange-build --store-dir /tmp/openrange-snapshots --validation-profile graph_only
```

This deterministic pipeline will immediately compile a tier-1 enterprise environment, synthesize internal vulnerabilities, and freeze it into an immutable snapshot. You can then trace an episode by invoking `openrange reset --store-dir /tmp/openrange-snapshots --sample-seed 7`.

## Offline Exploration vs Live Ranges

OpenRange splits execution into two physical planes:
1. **Offline Exploration:** The default `graph_only` path builds and runs episodes instantly in-memory via `TinyWorld` and synthetic decision tracking. Ideal for iterating on scenarios and RL tuning.
2. **Live Ranges:** The `full` profile renders live Kubernetes architectures (`kind`), deploys genuine service images, and exposes physical web interfaces. This path provides high-fidelity validation.

## What You Can Do

- Build and admit worlds from strict manifests
- Run red/blue/green episodes over immutable snapshots
- Sample snapshots from train and eval pools
- Generate branch-native trace datasets for training
- Use offline admission for local iteration or live validation when running with Kind

## Documentation

- [How an Episode Works](docs/how-an-episode-works.md): practical runtime walkthrough
- [Architecture](docs/architecture.md): package layers and runtime boundaries
- [Training Data Spec](docs/training-data-spec.md): canonical trace and export contract
- [Benchmark Offensive Coverage](docs/benchmark-offensive-coverage.md): web-offensive slice and objective grounding
- [Effect Grounding](docs/effect-grounding.md): grounded effect and mitigation semantics
- [Weakness Lifecycle](docs/weakness-lifecycle.md): weakness realization, admission, and mutation
- [NPC Profiles](docs/npc-profiles.md): green-user behavior shaping

## Getting Started

### 1. Install from Source

If you want to modify OpenRange or build on top of it:

```bash
uv sync
uv run openrange --help
```

### 2. Admit a Snapshot Locally

For a local first run, use the explicit offline profile:

```bash
uv run openrange admit \
  -m manifests/tier1_basic.yaml \
  -o /tmp/openrange-build \
  --store-dir /tmp/openrange-snapshots \
  --validation-profile graph_only
```

Then reset the runtime onto an admitted snapshot:

```bash
uv run openrange reset \
  --store-dir /tmp/openrange-snapshots \
  --mode blue_only_live \
  --sample-seed 7
```

`graph_only` is the cheapest offline path. `full` and `graph_plus_live` require
a live Kind-backed setup.

### 3. Generate Trace Data

```bash
uv run openrange traces \
  -m manifests/tier1_basic.yaml \
  -o /tmp/openrange-traces \
  --roots 3 \
  --mutations 1
```

This writes raw decision rows, SFT-ready rows, and a small dataset report tied
to admitted snapshots.

## Python API

You can programmatically compose and manage OpenRange episodes using the exact same public API that powers the CLI:

```python
from open_range import BuildConfig, BuildPipeline, EpisodeConfig, OpenRange, load_bundled_manifest

# 1. Build and Admit an immutable snapshot
pipeline = BuildPipeline()
candidate = pipeline.build(
    load_bundled_manifest("tier1_basic.yaml"),
    "/tmp/openrange-build",
    BuildConfig(validation_profile="graph_only"),
)
snapshot = pipeline.admit(candidate)

# 2. Spin up the Simulator Engine
env = OpenRange()
state = env.reset(snapshot.snapshot_id, EpisodeConfig(mode="blue_only_live"))

# 3. Step the Loop
decision = env.next_decision()

print(f"Active Snapshot: {state.snapshot_id}")
print(f"Awaiting turn from: {decision.actor} @ time: {decision.obs.sim_time}")
```

## Scope

OpenRange currently focuses on a validator-admitted enterprise web-security
training slice:

- exact web flaws plus config, secret, workflow, and telemetry weaknesses
- private reference attack and defense traces
- immutable snapshots and mutation between snapshots
- red exploit-to-objective behavior
- blue detection, containment, and continuity under green-user noise

It does not expose the old public golden-path architecture or the legacy
OpenEnv HTTP server surface.

## Optional Extras

Training dependencies are optional:

```bash
uv sync --extra training
```

## Evaluation

For environment-side evaluation over admitted snapshots and sequential mutations:

```bash
uv run scripts/eval_rollouts.py \
  --manifest manifests/tier1_basic.yaml \
  --mutations 3 \
  --out /tmp/openrange-rollout-eval.json
```

This writes a JSON report with:
- base snapshot plus sequential admitted child worlds
- bootstrap-trace winner/turn counts
- runtime rollout results for `joint_pool`, `red_only`, `blue_only_live`, and `blue_only_from_prefix`
- aggregate win-rate, reward, continuity, and turn metrics by mode

## Trace Generation

For branch-native datasets tied to admitted snapshots and mutations:

```bash
uv run scripts/generate_traces.py \
  --manifest manifests/tier1_basic.yaml \
  --roots 3 \
  --mutations 1 \
  --outdir /tmp/openrange-traces
```

Or through the CLI:

```bash
openrange traces -m manifests/tier1_basic.yaml -o /tmp/openrange-traces --roots 3 --mutations 1
```

The generator also writes role/source shards such as:
- `sft_red_runtime.jsonl`
- `sft_blue_runtime.jsonl`
- `sft_red_all.jsonl`
- `sft_blue_all.jsonl`

## Experimental Model Probe

This is an optional bounded red-only probe that loads a tiny LoRA adapter and
uses it to score a small candidate action set at each runtime decision.
It is intentionally narrower than a full policy evaluation: it is
reference-conditioned and red-only because the current tiny bootstrap dataset is
not yet a full red/blue runtime-action corpus.

```bash
uv run scripts/eval_model_rollouts.py \
  --adapter /tmp/openrange-sft-tiny-split/adapter \
  --manifest manifests/tier1_basic.yaml \
  --mutations 3 \
  --out /tmp/openrange-model-rollout.json
```

## Container Image

The root [Dockerfile](Dockerfile) builds a CLI image for the standalone package:

```bash
docker build -t openrange .
docker run --rm openrange --help
```

## Verification

```bash
uv run -m pytest tests -q
```

## Development

```bash
uv sync
uv run ruff format .
uv run ruff check .
uv run pytest
uv run pre-commit install
uv run pre-commit run --all-files
```

## License

Apache 2.0
