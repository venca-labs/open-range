from __future__ import annotations

import importlib.util
from pathlib import Path


def _load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_tiny_sft_helpers_are_deterministic() -> None:
    module = _load_module(
        Path(__file__).resolve().parents[1] / "scripts" / "train_tiny_sft.py",
        "train_tiny_sft_test",
    )
    data_path = module.resolve_data_path(None, seed=7)
    rows = module.load_examples(
        data_path,
        limit=12,
        seed=7,
    )
    train_rows, eval_rows = module.split_examples(
        rows, eval_ratio=0.25, min_eval_rows=3
    )

    assert len(rows) == 12
    assert len(train_rows) >= 3
    assert len(eval_rows) >= 3
    assert module.example_to_text(train_rows[0]).startswith("<system>")
    assert "/openrange-trace-train-data-runtime/seed-7/" in str(data_path)
    assert {row["trace_source"] for row in rows} == {"runtime"}


def test_tiny_sft_limit_applies_after_role_filtering() -> None:
    module = _load_module(
        Path(__file__).resolve().parents[1] / "scripts" / "train_tiny_sft.py",
        "train_tiny_sft_filter_test",
    )
    rows = []
    for index in range(12):
        role = "blue" if index < 8 else "red"
        split = "train" if index % 3 else "val"
        rows.append(
            {
                "role": role,
                "mode": "red_only" if role == "red" else "blue_only_live",
                "trace_source": "runtime",
                "split": split,
                "messages": [
                    {"role": "system", "content": "sys"},
                    {"role": "user", "content": f"row {index}"},
                    {"role": "assistant", "content": "ok"},
                ],
            }
        )

    filtered = module.filter_examples(rows, roles={"red"})
    limited = module.limit_examples(filtered, limit=4, seed=7)

    assert len(filtered) == 4
    assert len(limited) == 4
    assert {row["role"] for row in limited} == {"red"}


def test_tiny_sft_tokenize_rows_returns_trainer_ready_items() -> None:
    module = _load_module(
        Path(__file__).resolve().parents[1] / "scripts" / "train_tiny_sft.py",
        "train_tiny_sft_tokenize_test",
    )

    class FakeTokenizer:
        def __call__(
            self,
            text: str,
            *,
            truncation: bool,
            max_length: int,
            padding: bool,
        ) -> dict[str, list[int]]:
            assert truncation is True
            assert padding is False
            tokens = [ord(char) % 17 for char in text][:max_length]
            return {
                "input_ids": tokens,
                "attention_mask": [1] * len(tokens),
            }

    rows = [
        {
            "messages": [
                {"role": "system", "content": "sys"},
                {"role": "user", "content": "hello"},
                {"role": "assistant", "content": "ok"},
            ]
        }
    ]

    tokenized = module.tokenize_rows(FakeTokenizer(), rows, max_length=8)

    assert len(tokenized) == 1
    assert tokenized[0]["input_ids"]
    assert tokenized[0]["attention_mask"]
    assert tokenized[0]["labels"] == tokenized[0]["input_ids"]
