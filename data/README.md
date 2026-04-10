# Data

Files under `data/` are repo-local training artifacts and references.

They are not part of the supported runtime package surface.

Current usage:

- `sft.jsonl`: seed supervised trajectories
- `synthetic*.jsonl`: generated or experimental datasets
- `synthetic_sft_5_bootstrap.jsonl`: older mixed bootstrap chat dataset retained as legacy reference
- `tool_info.md`: prompt-side tool catalog material

The preferred branch-native path is now dynamic trace generation from admitted snapshots:

```bash
uv run scripts/generate_traces.py \
  --manifest manifests/tier1_basic.yaml \
  --roots 3 \
  --mutations 1 \
  --outdir /tmp/openrange-traces
```

This produces:

- raw trace rows: `/tmp/openrange-traces/trace_rows.jsonl`
- branch-native decision SFT rows: `/tmp/openrange-traces/decision_sft.jsonl`
- red runtime training shard: `/tmp/openrange-traces/sft_red_runtime.jsonl`
- blue runtime training shard: `/tmp/openrange-traces/sft_blue_runtime.jsonl`

Those exported rows are tied to:

- admitted snapshot ids
- world ids and world hashes
- lineage roots and mutation generation
- runtime mode and start state
- role-correct observations, candidate actions, chosen actions, and emitted events
- terminal outcome metadata

Tiny training path:

```bash
HF_HOME=/tmp/hf-home TOKENIZERS_PARALLELISM=false \
uv run scripts/train_tiny_sft.py \
  --data /tmp/openrange-traces/decision_sft.jsonl \
  --roles red \
  --outdir /tmp/openrange-sft-tiny

HF_HOME=/tmp/hf-home TOKENIZERS_PARALLELISM=false \
uv run scripts/eval_tiny_sft.py \
  --data /tmp/openrange-traces/decision_sft.jsonl \
  --adapter /tmp/openrange-sft-tiny/adapter \
  --roles red
```

The small model probe is currently red-only, so role filtering should stay
explicit in tiny SFT/eval runs unless you are intentionally training a mixed
decision model.
