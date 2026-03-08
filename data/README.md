# Training Data

Seed and generated datasets for SFT warm-start live under `data/`.

## Files

| File | Purpose |
|------|---------|
| `sft.jsonl` | Seed SFT dataset in ChatML format, including assistant tool calls and tool responses. |
| `tool_info.md` | Reusable tool catalog that can be injected into generated system prompts with `--tool-info`. |
| `synthetic*.jsonl` | Generated synthetic datasets from `openrange synthetic-data` (gitignored). |

## Seed SFT Format

Each line in `sft.jsonl` is a single solved trajectory:

```json
{
  "messages": [
    {"role": "system", "content": "..."},
    {"role": "user", "content": "..."},
    {"role": "assistant", "content": "...", "tool_calls": [...]},
    {"role": "tool", "tool_call_id": "...", "name": "shell_command", "content": "..."}
  ],
  "metadata": {"source": "bootstrap", "success": true},
  "ground_truth_flag": "FLAG{...}",
  "optimal_steps": 8
}
```

## Generating Synthetic Data

Use the seed file as bootstrap context and merge newly generated OpenRange traces into a single output:

```bash
uv run --extra synthetic openrange synthetic-data \
  --manifest manifests/tier1_basic.yaml \
  --output data/synthetic_sft_5.jsonl \
  --num-traces 5 \
  --roles red \
  --teacher-model azure/gpt-5.2-codex \
  --bootstrap-traces data/sft.jsonl \
  --tool-info data/tool_info.md
```

The output file keeps the imported bootstrap records intact and appends the generated OpenRange records after them.
