#!/usr/bin/env python3
"""Run a tiny LoRA SFT warmup on OpenRange chat data.

This script is intentionally small and pragmatic:
- uses a tiny instruct model by default
- consumes JSONL rows with a `messages` array
- flattens tool-using chats into plain text
- applies LoRA on all linear layers
- performs a deterministic train/eval split

It is meant to prove the branch can run a real model-training job locally,
not to be the final production training stack.
"""

from __future__ import annotations

import argparse
import json
import random
import shutil
from pathlib import Path
from typing import Any

from open_range.build_config import BuildConfig
from open_range.resources import load_bundled_manifest
from open_range.tracegen import generate_trace_dataset

DEFAULT_MODEL = "HuggingFaceTB/SmolLM2-360M-Instruct"
TRACE_BUILD_CONFIG = BuildConfig(validation_profile="graph_only")
DEFAULT_TRACESET_ROOT = Path("/tmp/openrange-trace-train-data-runtime")


def _tool_call_text(tool_calls: list[dict[str, Any]]) -> str:
    blocks: list[str] = []
    for call in tool_calls:
        function = call.get("function", {})
        name = function.get("name", "tool")
        arguments = function.get("arguments", "")
        blocks.append(
            "<tool_call>\n"
            f"<name>{name}</name>\n"
            f"<arguments>{arguments}</arguments>\n"
            "</tool_call>"
        )
    return "\n".join(blocks)


def message_to_text(message: dict[str, Any]) -> str:
    role = str(message.get("role", "unknown")).strip().lower()
    content = str(message.get("content", ""))
    tool_calls = message.get("tool_calls", [])
    name = message.get("name")

    blocks = [f"<{role}>"]
    if name:
        blocks.append(f"<name>{name}</name>")
    if content:
        blocks.append(content)
    if tool_calls:
        blocks.append(_tool_call_text(tool_calls))
    blocks.append(f"</{role}>")
    return "\n".join(blocks)


def example_to_text(example: dict[str, Any]) -> str:
    messages = example.get("messages", [])
    rendered = [message_to_text(message) for message in messages]
    if example.get("ground_truth_flag"):
        rendered.append(f"<ground_truth>{example['ground_truth_flag']}</ground_truth>")
    return "\n\n".join(rendered)


def load_examples(path: Path, *, limit: int | None, seed: int) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            rows.append(json.loads(line))
    random.Random(seed).shuffle(rows)
    if limit is not None and len(rows) > limit:
        rows = limit_examples(rows, limit=limit, seed=seed)
    return rows


def limit_examples(
    rows: list[dict[str, Any]], *, limit: int | None, seed: int
) -> list[dict[str, Any]]:
    if limit is None or len(rows) <= limit:
        return list(rows)
    limited = list(rows)
    random.Random(seed).shuffle(limited)
    if len(limited) > limit:
        split_values = {
            str(row.get("split", "")).strip() for row in rows if isinstance(row, dict)
        }
        explicit_splits = {
            value for value in split_values if value in {"train", "val", "test"}
        }
        if "train" in explicit_splits and ({"val", "test"} & explicit_splits):
            train_rows = [row for row in limited if row.get("split") == "train"]
            eval_rows = [row for row in limited if row.get("split") in {"val", "test"}]
            eval_target = max(1, int(round(limit * len(eval_rows) / len(limited))))
            eval_target = min(eval_target, len(eval_rows), max(1, limit - 1))
            train_target = min(len(train_rows), max(1, limit - eval_target))
            limited = train_rows[:train_target] + eval_rows[:eval_target]
            random.Random(seed).shuffle(limited)
        else:
            limited = limited[:limit]
    return limited


def filter_examples(
    rows: list[dict[str, Any]],
    *,
    roles: set[str] | None = None,
    modes: set[str] | None = None,
    trace_sources: set[str] | None = None,
) -> list[dict[str, Any]]:
    filtered: list[dict[str, Any]] = []
    for row in rows:
        if roles is not None and row.get("role") not in roles:
            continue
        if modes is not None and row.get("mode") not in modes:
            continue
        if trace_sources is not None and row.get("trace_source") not in trace_sources:
            continue
        filtered.append(row)
    return filtered


def split_examples(
    rows: list[dict[str, Any]],
    *,
    eval_ratio: float,
    min_eval_rows: int,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    if not rows:
        return [], []
    split_values = {
        str(row.get("split", "")).strip() for row in rows if isinstance(row, dict)
    }
    explicit_splits = {
        value for value in split_values if value in {"train", "val", "test"}
    }
    if "train" in explicit_splits and ({"val", "test"} & explicit_splits):
        train_rows = [row for row in rows if row.get("split") == "train"]
        eval_rows = [row for row in rows if row.get("split") in {"val", "test"}]
        if train_rows and eval_rows:
            deficit = min_eval_rows - len(eval_rows)
            if deficit > 0 and len(train_rows) > 1:
                promote = min(deficit, len(train_rows) - 1)
                eval_rows = eval_rows + train_rows[:promote]
                train_rows = train_rows[promote:]
            return train_rows, eval_rows
    eval_count = max(min_eval_rows, int(round(len(rows) * eval_ratio)))
    eval_count = min(eval_count, max(1, len(rows) - 1))
    return rows[eval_count:], rows[:eval_count]


def tokenize_rows(
    tokenizer: Any,
    rows: list[dict[str, Any]],
    *,
    max_length: int,
) -> Any:
    items: list[dict[str, list[int]]] = []
    for row in rows:
        encoded = tokenizer(
            example_to_text(row),
            truncation=True,
            max_length=max_length,
            padding=False,
        )
        items.append(
            {
                "input_ids": list(encoded["input_ids"]),
                "attention_mask": list(encoded["attention_mask"]),
                "labels": list(encoded["input_ids"]),
            }
        )
    return items


class CausalCollator:
    def __init__(self, tokenizer: Any, torch_mod: Any) -> None:
        self.tokenizer = tokenizer
        self.torch = torch_mod

    def __call__(self, features: list[dict[str, Any]]) -> dict[str, Any]:
        max_len = max(len(feature["input_ids"]) for feature in features)
        input_ids: list[list[int]] = []
        attention_mask: list[list[int]] = []
        labels: list[list[int]] = []
        pad_id = self.tokenizer.pad_token_id

        for feature in features:
            ids = list(feature["input_ids"])
            mask = list(feature["attention_mask"])
            lbls = list(feature["labels"])
            pad = max_len - len(ids)
            input_ids.append(ids + [pad_id] * pad)
            attention_mask.append(mask + [0] * pad)
            labels.append(lbls + [-100] * pad)

        return {
            "input_ids": self.torch.tensor(input_ids, dtype=self.torch.long),
            "attention_mask": self.torch.tensor(attention_mask, dtype=self.torch.long),
            "labels": self.torch.tensor(labels, dtype=self.torch.long),
        }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Tiny LoRA SFT for OpenRange chat data."
    )
    parser.add_argument(
        "--data",
        default=None,
        help="Path to JSONL chat data. If omitted, generate branch-native decision traces.",
    )
    parser.add_argument(
        "--model", default=DEFAULT_MODEL, help="Hugging Face model id or local path."
    )
    parser.add_argument(
        "--outdir", default="/tmp/openrange-sft-tiny", help="Output directory."
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
    parser.add_argument("--epochs", type=float, default=1.0)
    parser.add_argument("--max-steps", type=int, default=24)
    parser.add_argument("--batch-size", type=int, default=1)
    parser.add_argument("--grad-accum", type=int, default=8)
    parser.add_argument("--learning-rate", type=float, default=2e-4)
    parser.add_argument("--lora-r", type=int, default=8)
    parser.add_argument("--lora-alpha", type=int, default=16)
    return parser.parse_args()


def resolve_data_path(data: str | None, *, seed: int) -> Path:
    if data:
        return Path(data)
    generated_root = DEFAULT_TRACESET_ROOT / f"seed-{seed}"
    if generated_root.exists():
        shutil.rmtree(generated_root)
    report = generate_trace_dataset(
        load_bundled_manifest("tier1_basic.yaml"),
        generated_root,
        manifest_source="tier1_basic.yaml",
        build_config=TRACE_BUILD_CONFIG,
        roots=2,
        mutations_per_root=1,
        include_sim=False,
        include_joint_pool=False,
    )
    return Path(report.decision_sft_path)


def parse_filter(value: str) -> set[str] | None:
    items = {item.strip() for item in value.split(",") if item.strip()}
    return items or None


def main() -> None:
    import torch
    from peft import LoraConfig, get_peft_model
    from transformers import (
        AutoModelForCausalLM,
        AutoTokenizer,
        Trainer,
        TrainingArguments,
    )

    args = parse_args()
    random.seed(args.seed)
    torch.manual_seed(args.seed)

    data_path = resolve_data_path(args.data, seed=args.seed)
    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    rows = load_examples(data_path, limit=None, seed=args.seed)
    rows = filter_examples(
        rows,
        roles=parse_filter(args.roles),
        modes=parse_filter(args.modes),
        trace_sources=parse_filter(args.trace_sources),
    )
    rows = limit_examples(rows, limit=args.max_samples, seed=args.seed)
    if len(rows) < 2:
        raise ValueError(
            f"need at least two rows in {data_path} after filtering "
            f"(roles={args.roles!r}, modes={args.modes!r}, trace_sources={args.trace_sources!r})"
        )
    train_rows, eval_rows = split_examples(
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

    tokenizer = AutoTokenizer.from_pretrained(args.model, use_fast=True)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token
    tokenizer.padding_side = "right"

    model = AutoModelForCausalLM.from_pretrained(
        args.model,
        dtype=dtype,
        device_map="auto" if torch.cuda.is_available() else None,
    )
    model.config.use_cache = False
    if hasattr(model, "gradient_checkpointing_enable"):
        model.gradient_checkpointing_enable()

    lora_config = LoraConfig(
        r=args.lora_r,
        lora_alpha=args.lora_alpha,
        lora_dropout=0.05,
        bias="none",
        task_type="CAUSAL_LM",
        target_modules="all-linear",
    )
    model = get_peft_model(model, lora_config)
    model.print_trainable_parameters()

    train_dataset = tokenize_rows(tokenizer, train_rows, max_length=args.max_length)
    eval_dataset = tokenize_rows(tokenizer, eval_rows, max_length=args.max_length)
    collator = CausalCollator(tokenizer, torch)

    training_args = TrainingArguments(
        output_dir=str(outdir),
        num_train_epochs=args.epochs,
        max_steps=args.max_steps,
        per_device_train_batch_size=args.batch_size,
        per_device_eval_batch_size=args.batch_size,
        gradient_accumulation_steps=args.grad_accum,
        learning_rate=args.learning_rate,
        bf16=torch.cuda.is_available() and torch.cuda.is_bf16_supported(),
        fp16=torch.cuda.is_available() and not torch.cuda.is_bf16_supported(),
        logging_steps=1,
        eval_strategy="steps",
        eval_steps=max(1, args.max_steps // 2),
        save_steps=args.max_steps,
        save_total_limit=1,
        report_to="none",
        remove_unused_columns=False,
        dataloader_pin_memory=torch.cuda.is_available(),
        do_train=True,
        do_eval=True,
    )

    trainer = Trainer(
        model=model,
        args=training_args,
        train_dataset=train_dataset,
        eval_dataset=eval_dataset,
        data_collator=collator,
    )
    stats = trainer.train()
    eval_metrics = trainer.evaluate()
    model.save_pretrained(outdir / "adapter")
    tokenizer.save_pretrained(outdir / "adapter")

    metrics = {
        "train_loss": float(stats.training_loss),
        "eval_loss": float(eval_metrics["eval_loss"]),
        "rows_total": len(rows),
        "rows_train": len(train_rows),
        "rows_eval": len(eval_rows),
        "roles": sorted(parse_filter(args.roles) or []),
        "modes": sorted(parse_filter(args.modes) or []),
        "trace_sources": sorted(parse_filter(args.trace_sources) or []),
        "model": args.model,
        "output_dir": str(outdir / "adapter"),
    }
    (outdir / "metrics.json").write_text(
        json.dumps(metrics, indent=2), encoding="utf-8"
    )

    print(f"train_loss={metrics['train_loss']:.4f}")
    print(f"eval_loss={metrics['eval_loss']:.4f}")
    print(f"rows_train={metrics['rows_train']}")
    print(f"rows_eval={metrics['rows_eval']}")
    print(f"model={metrics['model']}")
    print(f"output={metrics['output_dir']}")


if __name__ == "__main__":
    main()
