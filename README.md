# OpenRange

OpenRange is a manifest-first red/blue/green cyber range packaged as an installable Python control plane.

The supported surface is:

- strict public manifests for the bounded `enterprise_saas_v1` family
- a Python build/admit/store/runtime API under [`src/open_range`](/home/talian/priv/open-range/src/open_range)
- a small CLI exposed as `openrange`
- packaged chart assets, schemas, docs, and manifest examples

The legacy OpenEnv server/client stack and public golden-path model are not part of the current package surface.

## Package shape

```text
src/open_range/      importable runtime, compiler, renderer, admission, store
manifests/           checked-in strict manifest examples
schemas/             generated JSON schemas
examples/            small runnable demos against the current API
data/                repo-only training artifacts
docs/                current package documentation
```

## Installation

```bash
pip install .
openrange --help
openrange-demo
openrange-bootstrap-demo
```

## Training Dependencies

The base package does not install model-training dependencies by default.
Use the training extra explicitly:

```bash
uv sync --extra training
```

This installs the small training stack used by the current branch:
PyTorch, Transformers, Datasets, Accelerate, PEFT, and TRL.

## Tiny Train/Eval Path

The branch includes a branch-native tiny LoRA warmup path.
It now starts from generated decision traces over admitted snapshots rather than
from the older mixed bootstrap chat file.

Generate branch-native traces first:

```bash
PYTHONPATH=src .venv/bin/python scripts/generate_traces.py \
  --manifest manifests/tier1_basic.yaml \
  --roots 3 \
  --mutations 1 \
  --outdir /tmp/openrange-traces
```

This writes:

- raw decision rows: `/tmp/openrange-traces/trace_rows.jsonl`
- branch-native decision SFT rows: `/tmp/openrange-traces/decision_sft.jsonl`
- red runtime shard: `/tmp/openrange-traces/sft_red_runtime.jsonl`
- blue runtime shard: `/tmp/openrange-traces/sft_blue_runtime.jsonl`
- dataset report: `/tmp/openrange-traces/report.json`

The tiny SFT path can also generate a small branch-native dataset on the fly if
`--data` is omitted.

The tiny train/eval scripts are role-correct by default:
- `--roles red`
- `--trace-sources runtime,sim`

That keeps the small adapter aligned with the current red-only model probe
instead of mixing red and blue decision rows into one tiny run.

Train:

```bash
uv sync --extra dev --extra training
HF_HOME=/tmp/hf-home TOKENIZERS_PARALLELISM=false \
python scripts/train_tiny_sft.py \
  --data /tmp/openrange-traces/decision_sft.jsonl \
  --roles red \
  --outdir /tmp/openrange-sft-tiny \
  --max-samples 64 \
  --max-length 1024 \
  --max-steps 8 \
  --grad-accum 4 \
  --batch-size 1 \
  --eval-ratio 0.25 \
  --min-eval-samples 8
```

Evaluate the saved adapter on the held-out split:

```bash
HF_HOME=/tmp/hf-home TOKENIZERS_PARALLELISM=false \
python scripts/eval_tiny_sft.py \
  --data /tmp/openrange-traces/decision_sft.jsonl \
  --adapter /tmp/openrange-sft-tiny/adapter \
  --roles red \
  --max-samples 64 \
  --eval-ratio 0.25 \
  --min-eval-samples 8 \
  --max-length 1024 \
  --out /tmp/openrange-sft-eval.json
```

Current default tiny model:
- `HuggingFaceTB/SmolLM2-360M-Instruct`

## Training Data

OpenRange training data is now treated as a first-class artifact of admitted
snapshots.

The canonical contract is documented in:

- [docs/training-data-spec.md](/home/talian/priv/open-range/docs/training-data-spec.md)

Key rules:

- raw data comes from executed traces over admitted snapshots
- `sim` and `runtime` traces stay explicitly separated
- rows carry snapshot, world, world hash, lineage, mode, role, observation, candidates, chosen action, emitted events, reward delta, winner, and terminal reason
- dataset splits are assigned by lineage root, not random row
- derived SFT rows preserve `split` and lineage metadata
- trace export writes clean role/source shards for red, blue, runtime, and sim subsets
- train/eval filtering happens before row caps, so role-correct subsets are not starved by mixed trace distributions

## Benchmark-Aligned Offensive Coverage

The offensive slice is documented separately in:

- [docs/benchmark-offensive-coverage.md](/home/talian/priv/open-range/docs/benchmark-offensive-coverage.md)

Current implementation points:

- exact `code_web` flaws carry benchmark tags plus benchmark-aligned `objective_tags`
- red objectives compile with derived offensive objective tags where applicable
- admission now builds service-native grader specs for grounded red objectives
- `EpisodeConfig.prompt_mode` supports `zero_day` and `one_day`
- runtime first observations expose prompt-mode-specific briefings without leaking private witnesses

## Current pipeline

```text
manifest
  -> validate_manifest
  -> ManifestCompiler
  -> WorldSynthesizer
  -> WeaknessSeeder
  -> KindRenderer
  -> AdmissionController
  -> SnapshotStore
  -> OpenRange runtime
```

## What is implemented

- strict manifest, `WorldIR`, `WitnessBundle`, and `ValidatorReport` models
- deterministic `enterprise_saas_v1` compiler
- deterministic bounded synthesis for seeded business artifacts
- deterministic weakness seeding from an allowed-family catalog, including the full required non-code kind set for `config_identity`, `secret_exposure`, `workflow_abuse`, and `telemetry_blindspot`
- exact `code_web` flaw templates for the required web exploit kinds, rendered as concrete PHP handlers and witnessable routes
- benchmark-aligned offensive objective library and service-native grader specs for the supported web-first objective slice
- exact config/workflow/mailbox realizations for the required non-code weakness kinds, including mailbox-borne phishing and token leakage cases
- representative service-native mitigations for exact web flaws plus bounded config/file mitigations for non-code weaknesses
- Kind renderer with service payloads, firewall rules, and red/blue/green sandboxes
- deterministic admission with optional live Kind checks
- shared predicate engine used by both admission and runtime terminal/objective reasoning
- immutable snapshot store with train/eval splits
- simulated-time runtime with `EpisodeConfig`, actor-specific observations, and `next_decision()`
- live pod execution bridge and typed event flow
- deterministic curriculum and tandem episode driver, including persistent weakness patch/remove and alternate-route hardening
- checked-in manifest examples that validate and compile against the rewritten package

## Current gaps

- there is no production OpenEnv HTTP/WebSocket layer on this branch
- live remediation is a hybrid: exact web flaws use service-native route guards and some config/file weaknesses use direct artifact rewrites, but full remediation engineering is still out of scope
- admission now checks for public-surface secret leakage, obvious unguarded web routes, and missing service-local telemetry on critical weakness targets, but shortcut discovery is still intentionally non-exhaustive
- green reactive behavior is deterministic and bounded, not policy-rich

## CLI

```bash
openrange build  -m manifests/tier1_basic.yaml -o /tmp/openrange-build
openrange admit  -m manifests/tier1_basic.yaml -o /tmp/openrange-build --store-dir snapshots
openrange reset  --store-dir snapshots --sample-seed 7 --mode joint_pool
```

## Python usage

```python
from open_range import BuildPipeline, EpisodeConfig, OpenRange, load_bundled_manifest

pipeline = BuildPipeline()
candidate = pipeline.build(load_bundled_manifest("tier1_basic.yaml"), "/tmp/openrange-build")
snapshot = pipeline.admit(candidate)

service = OpenRange()
state = service.reset(snapshot.snapshot_id, EpisodeConfig(mode="joint_pool"))
decision = service.next_decision()
```

## Demo

```bash
PYTHONPATH=src .venv/bin/python examples/demo.py --manifest manifests/tier1_basic.yaml
PYTHONPATH=src .venv/bin/python -m open_range.examples.demo
openrange-demo
```

## Bootstrap Example

The package also includes an explicit warmup/bootstrap example. This keeps the
old synthetic warm-start idea separate from the environment contract by using
the optional sim plane rather than modifying the runtime itself.

```bash
PYTHONPATH=src .venv/bin/python -m open_range.examples.bootstrap
openrange-bootstrap-demo
```

## Rollout Evaluation

For environment-side evaluation over admitted snapshots and sequential mutations:

```bash
PYTHONPATH=src .venv/bin/python scripts/eval_rollouts.py \
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
PYTHONPATH=src .venv/bin/python scripts/generate_traces.py \
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

## Model-In-Loop Probe

There is also a bounded red-only probe that loads the tiny LoRA adapter and
uses it to score a small candidate action set at each runtime decision.
This is intentionally narrower than a full policy evaluation: it is
witness-conditioned and red-only because the current tiny bootstrap dataset is
not yet a full red/blue runtime-action corpus.

```bash
HF_HOME=/tmp/hf-home TOKENIZERS_PARALLELISM=false \
python scripts/eval_model_rollouts.py \
  --adapter /tmp/openrange-sft-tiny-split/adapter \
  --manifest manifests/tier1_basic.yaml \
  --mutations 3 \
  --out /tmp/openrange-model-rollout.json
```

## Container image

The root [Dockerfile](/home/talian/priv/open-range/Dockerfile) now builds a CLI image for the standalone package:

```bash
docker build -t openrange .
docker run --rm openrange --help
```

## Verification

```bash
PYTHONPATH=src .venv/bin/python -m pytest tests -q
```
