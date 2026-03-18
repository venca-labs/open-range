#!/usr/bin/env python3
"""Evaluate a tiny OpenRange LoRA adapter on a held-out chat split."""

from __future__ import annotations

import argparse
import json
import random
from pathlib import Path
from typing import Any

from train_tiny_sft import (
    DEFAULT_MODEL,
    CausalCollator,
    filter_examples,
    limit_examples,
    load_examples,
    parse_filter,
    resolve_data_path,
    split_examples,
    tokenize_rows,
)


def _assistant_prefix(example: dict[str, Any]) -> str:
    messages = example.get("messages", [])
    if len(messages) < 3:
        raise ValueError("expected at least system/user/assistant messages")
    rendered: list[str] = []
    for message in messages[:2]:
        role = str(message.get("role", "unknown")).strip().lower()
        content = str(message.get("content", ""))
        block = [f"<{role}>"]
        if content:
            block.append(content)
        block.append(f"</{role}>")
        rendered.append("\n".join(block))
    rendered.append("<assistant>\n")
    return "\n\n".join(rendered)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Evaluate a tiny OpenRange LoRA adapter."
    )
    parser.add_argument(
        "--data",
        default=None,
        help="Path to JSONL chat data. If omitted, generate branch-native decision traces.",
    )
    parser.add_argument(
        "--base-model", default=DEFAULT_MODEL, help="Base model id or local path."
    )
    parser.add_argument(
        "--adapter", required=True, help="Path to a saved LoRA adapter directory."
    )
    parser.add_argument("--seed", type=int, default=7)
    parser.add_argument("--max-samples", type=int, default=96)
    parser.add_argument("--eval-ratio", type=float, default=0.2)
    parser.add_argument("--min-eval-samples", type=int, default=8)
    parser.add_argument(
        "--roles",
        default="red",
        help="Comma-separated role filter for branch-native datasets.",
    )
    parser.add_argument(
        "--modes", default="", help="Optional comma-separated runtime-mode filter."
    )
    parser.add_argument(
        "--trace-sources",
        default="runtime",
        help="Comma-separated trace-source filter.",
    )
    parser.add_argument("--max-length", type=int, default=2048)
    parser.add_argument("--max-new-tokens", type=int, default=96)
    parser.add_argument(
        "--out",
        default="/tmp/openrange-sft-eval.json",
        help="Where to write eval metrics.",
    )
    return parser.parse_args()


def main() -> None:
    import torch
    from peft import PeftModel
    from transformers import (
        AutoModelForCausalLM,
        AutoTokenizer,
        Trainer,
        TrainingArguments,
    )

    args = parse_args()
    random.seed(args.seed)
    torch.manual_seed(args.seed)

    rows = load_examples(
        resolve_data_path(args.data, seed=args.seed), limit=None, seed=args.seed
    )
    rows = filter_examples(
        rows,
        roles=parse_filter(args.roles),
        modes=parse_filter(args.modes),
        trace_sources=parse_filter(args.trace_sources),
    )
    rows = limit_examples(rows, limit=args.max_samples, seed=args.seed)
    if len(rows) < 2:
        raise ValueError(
            "need at least two rows for held-out evaluation after filtering "
            f"(roles={args.roles!r}, modes={args.modes!r}, trace_sources={args.trace_sources!r})"
        )
    _train_rows, eval_rows = split_examples(
        rows,
        eval_ratio=args.eval_ratio,
        min_eval_rows=args.min_eval_samples,
    )

    if torch.cuda.is_available() and torch.cuda.is_bf16_supported():
        dtype = torch.bfloat16
    elif torch.cuda.is_available():
        dtype = torch.float16
    else:
        dtype = torch.float32

    tokenizer = AutoTokenizer.from_pretrained(args.adapter, use_fast=True)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token
    tokenizer.padding_side = "right"

    base_model = AutoModelForCausalLM.from_pretrained(
        args.base_model,
        dtype=dtype,
        device_map="auto" if torch.cuda.is_available() else None,
    )
    model = PeftModel.from_pretrained(base_model, args.adapter)
    model.eval()

    eval_dataset = tokenize_rows(tokenizer, eval_rows, max_length=args.max_length)
    collator = CausalCollator(tokenizer, torch)
    trainer = Trainer(
        model=model,
        args=TrainingArguments(
            output_dir="/tmp/openrange-sft-eval-tmp",
            report_to="none",
            do_eval=True,
            per_device_eval_batch_size=1,
            remove_unused_columns=False,
            dataloader_pin_memory=torch.cuda.is_available(),
            use_cpu=not torch.cuda.is_available(),
        ),
        eval_dataset=eval_dataset,
        data_collator=collator,
    )
    metrics = trainer.evaluate()

    formatted = 0
    previews: list[dict[str, str]] = []
    sample_count = min(3, len(eval_rows))
    for row in eval_rows[:sample_count]:
        prompt = _assistant_prefix(row)
        inputs = tokenizer(prompt, return_tensors="pt").to(model.device)
        output = model.generate(
            **inputs,
            max_new_tokens=args.max_new_tokens,
            do_sample=False,
            pad_token_id=tokenizer.pad_token_id,
        )
        generated = tokenizer.decode(
            output[0][inputs["input_ids"].shape[1] :], skip_special_tokens=True
        )
        if "<tool_call>" in generated or generated.strip():
            formatted += 1
        previews.append(
            {
                "prompt": prompt,
                "generated": generated,
            }
        )

    report = {
        "eval_loss": float(metrics["eval_loss"]),
        "eval_rows": len(eval_rows),
        "format_nonempty_rate": formatted / sample_count if sample_count else 0.0,
        "roles": sorted(parse_filter(args.roles) or []),
        "modes": sorted(parse_filter(args.modes) or []),
        "trace_sources": sorted(parse_filter(args.trace_sources) or []),
        "previews": previews,
        "adapter": args.adapter,
        "base_model": args.base_model,
    }
    out_path = Path(args.out)
    out_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

    print(f"eval_loss={report['eval_loss']:.4f}")
    print(f"eval_rows={report['eval_rows']}")
    print(f"format_nonempty_rate={report['format_nonempty_rate']:.3f}")
    print(f"report={out_path}")


if __name__ == "__main__":
    main()
