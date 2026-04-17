# Custom Eval Runner

This is the custom eval runner we have been using for the DGX live smoke runs.

It lives in `open-range` as an example only. It is not part of the core package
surface.

## DGX Command

Run this on the DGX or another host that has the OpenAI-compatible endpoint on
`127.0.0.1:8001`:

```bash
uv run --with 'strands-agents[openai]>=1.4' python examples/custom_eval/run_openrange_eval.py \
  --endpoint http://127.0.0.1:8001/v1/chat/completions \
  --model omnicoder-9b-ctf \
  --model-link https://huggingface.co/Tesslate/OmniCoder-9B \
  --validation-profile full \
  --manifest tier1_basic.yaml \
  --mutations 0 \
  --max-turns 5 \
  --timeout 60 \
  --max-output-tokens 256 \
  --live-cluster-backend kind \
  -o /tmp/openrange-live-eval.json
```

## Notes

- this is a custom runner, not a framework example
- `--model-link` is just report metadata. It does not change runtime behavior.
- `--validation-profile full` requires live runtime. It will fail instead of silently downgrading.
- `--offline-diagnostic` is for explicit offline smoke runs only.
- The report is written to the path given by `-o`.
