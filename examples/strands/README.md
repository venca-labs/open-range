# Strands Eval Example

This is a temporary example runner.

It lives in `open-range` as an example only. It is not part of the core package
surface.

## Dependency Group

Use the temporary dependency group:

```bash
uv sync --group temp-eval
```

Or just run the example directly with `uv run`.

## Example Command

Run from the repo root:

```bash
uv run --group temp-eval python examples/strands/run_openrange_strands.py \
  --endpoint http://127.0.0.1:8001/v1/chat/completions \
  --model omnicoder-9b-ctf \
  --model-link https://huggingface.co/Tesslate/OmniCoder-9B \
  --validation-profile full \
  --manifest tier1_basic.yaml \
  --mutations 0 \
  --max-turns 8 \
  --timeout 60 \
  --max-output-tokens 256 \
  --live-cluster-backend kind \
  -o /tmp/openrange-live-strands.json
```

## Notes

- `--model-link` is just report metadata. It does not change runtime behavior.
- `--validation-profile full` requires live runtime. It will fail instead of silently downgrading.
- `--offline-diagnostic` is for explicit offline smoke runs only.
- The report is written to the path given by `-o`.
