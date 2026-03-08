# Synthetic Data

OpenRange includes a snapshot-backed synthetic trajectory generator for SFT warm-start and offline data collection. The design is influenced by Open Trajectory Gym's split between world specification, executor, and teacher model, but it is implemented in the OpenRange training layer so it stays aligned with the existing `SnapshotSpec`, `RangeEnvironment`, and `TrajectoryLogger` types.

## Why It Lives In `training/`

Synthetic trace generation is a training concern, not a runtime concern:

- The live server still owns real `reset()` / `step()` episodes on Docker infrastructure.
- Synthetic generation reuses the same `SnapshotSpec` and reward/meta-command semantics, but swaps Docker execution for a fast simulator.
- Export still goes through `TrajectoryLogger`, so downstream SFT JSONL format does not fork.

This keeps OpenRange's real environment and synthetic data path close enough to share prompts, actions, and episode structure without turning the production server into a data-generation service.

## Components

- `SyntheticRangeEnvironment`: a fast `RangeEnvironment` subclass that simulates common Red and Blue commands from a loaded snapshot.
- `SyntheticTraceGenerator`: drives Red and Blue agents through synthetic episodes and records them with `TrajectoryLogger`.
- `build_teacher_agents()`: constructs LiteLLM-backed teacher agents for selected roles and scripted fallbacks for the rest.
- `randomize_snapshot_flags()`: clones a snapshot and rewrites flag values per episode so traces do not memorize static flag strings.

## LiteLLM Support

Install the optional dependency:

```bash
uv sync --extra synthetic
```

Any LiteLLM model string supported by `LLMRangeAgent` works. For Azure OpenAI, export the usual LiteLLM/Azure variables and pass the deployment name as the model:

```bash
export AZURE_API_KEY=...
export AZURE_API_BASE=...
export AZURE_API_VERSION=...

uv run openrange synthetic-data \
  --manifest manifests/tier1_basic.yaml \
  --output data/sft_red.jsonl \
  --roles red \
  --teacher-model azure/gpt-5.2-codex
```

Codex-style Azure deployments often reject `temperature`; `LLMRangeAgent` now omits it automatically for model names containing `codex`.

## CLI

Generate traces from an existing snapshot:

```bash
uv run openrange synthetic-data \
  --snapshot snapshots/spec.json \
  --output data/sft_red.jsonl \
  --num-traces 25 \
  --roles red
```

Merge previously collected bootstrap traces and append a reusable tool catalog to generated system prompts:

```bash
uv run openrange synthetic-data \
  --manifest manifests/tier1_basic.yaml \
  --output data/synthetic_sft_5.jsonl \
  --num-traces 5 \
  --roles red \
  --teacher-model azure/gpt-5.2-codex \
  --bootstrap-traces data/sft.jsonl \
  --tool-info data/tool_info.md
```

Generate traces from a manifest using the deterministic builder:

```bash
uv run openrange synthetic-data \
  --manifest manifests/tier1_basic.yaml \
  --output data/sft_red_blue.jsonl \
  --roles red,blue \
  --num-traces 50
```

Generate traces from a manifest using both an LLM builder and LLM teachers:

```bash
uv run openrange synthetic-data \
  --manifest manifests/tier1_basic.yaml \
  --llm-builder \
  --builder-model azure/gpt-5.2-codex \
  --teacher-model azure/gpt-5.2-codex \
  --roles red \
  --output data/frontier_red.jsonl
```

## Python API

```python
from open_range.training import SyntheticTraceGenerator, build_teacher_agents

red, blue = build_teacher_agents(
    teacher_model="azure/gpt-5.2-codex",
    roles=("red",),
    max_tokens=256,
)

generator = SyntheticTraceGenerator.from_manifest(
    manifest=tier1_manifest,
    red_agent=red,
    blue_agent=blue,
    template_only=True,
    max_steps=8,
)

logger, lines = generator.export_jsonl(
    "data/sft_red.jsonl",
    num_traces=10,
    roles=("red",),
)
```

## Testing

Unit coverage lives in `tests/test_synthetic.py`.

There is also a gated live-model smoke test that exercises the synthetic generator against a real LiteLLM model:

```bash
uv run --extra synthetic pytest tests/test_synthetic.py -m live_model -q
```

The live test is skipped automatically unless the required Azure environment variables are present.
