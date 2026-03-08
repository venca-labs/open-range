"""Dataset helpers for synthetic and bootstrap SFT records."""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any, Iterable

import yaml


def load_jsonl_records(paths: Iterable[str | Path]) -> list[dict[str, Any]]:
    """Load newline-delimited JSON records from one or more files."""
    records: list[dict[str, Any]] = []
    for raw_path in paths:
        path = Path(raw_path)
        with path.open("r", encoding="utf-8") as handle:
            for lineno, line in enumerate(handle, start=1):
                text = line.strip()
                if not text:
                    continue
                payload = json.loads(text)
                if not isinstance(payload, dict):
                    raise TypeError(f"{path}:{lineno} is not a JSON object")
                records.append(payload)
    return records


def load_tool_context(paths: Iterable[str | Path]) -> str:
    """Load and normalize a tool-context file or files."""
    blocks: list[str] = []
    for raw_path in paths:
        path = Path(raw_path)
        suffix = path.suffix.lower()
        text = path.read_text(encoding="utf-8").strip()
        if not text:
            continue
        if suffix in {".json", ".yaml", ".yml"}:
            payload = json.loads(text) if suffix == ".json" else yaml.safe_load(text)
            blocks.append(_render_tool_payload(payload))
        else:
            blocks.append(text)
    return "\n\n".join(block for block in blocks if block.strip())


def append_tool_context(
    records: list[dict[str, Any]],
    tool_context: str,
) -> list[dict[str, Any]]:
    """Append tool descriptions to the first system prompt in each record."""
    if not tool_context.strip():
        return [copy.deepcopy(record) for record in records]

    block = tool_context.strip()
    if not block.lower().startswith("available tools"):
        block = "Available tools:\n" + block

    enriched: list[dict[str, Any]] = []
    for record in records:
        clone = copy.deepcopy(record)
        messages = clone.get("messages", [])
        if isinstance(messages, list):
            for message in messages:
                if not isinstance(message, dict):
                    continue
                if message.get("role") != "system":
                    continue
                content = str(message.get("content", "")).rstrip()
                if block not in content:
                    message["content"] = f"{content}\n\n{block}".strip()
                break
        enriched.append(clone)
    return enriched


def extract_bootstrap_messages(
    records: list[dict[str, Any]],
    *,
    role: str = "red",
    limit: int = 0,
) -> list[dict[str, Any]]:
    """Extract few-shot chat messages from prior SFT records."""
    if limit <= 0:
        return []

    examples: list[dict[str, Any]] = []
    ranked_records = sorted(records, key=_bootstrap_record_rank, reverse=True)
    used = 0
    for record in ranked_records:
        record_role = (
            str(record.get("role", "")).strip().lower()
            or str(record.get("metadata", {}).get("role", "")).strip().lower()
        )
        if record_role and record_role != role:
            continue

        messages = record.get("messages", [])
        if not isinstance(messages, list):
            continue
        example = [
            copy.deepcopy(message)
            for message in messages
            if isinstance(message, dict)
        ]
        if example and example[0].get("role") == "system":
            example = example[1:]
        if not example:
            continue

        examples.extend(example)
        used += 1
        if used >= limit:
            break

    return examples


def write_jsonl_records(path: str | Path, records: list[dict[str, Any]]) -> int:
    """Write JSONL records to *path*."""
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record) + "\n")
    return len(records)


def _render_tool_payload(payload: Any) -> str:
    if isinstance(payload, str):
        return payload.strip()
    if isinstance(payload, dict):
        lines = []
        for key, value in payload.items():
            if isinstance(value, str):
                lines.append(f"- {key}: {value}")
            else:
                rendered = json.dumps(value, sort_keys=True)
                lines.append(f"- {key}: {rendered}")
        return "\n".join(lines)
    if isinstance(payload, list):
        lines = []
        for item in payload:
            if isinstance(item, dict):
                name = str(item.get("name", "")).strip()
                description = str(item.get("description", "")).strip()
                if name and description:
                    lines.append(f"- {name}: {description}")
                elif name:
                    lines.append(f"- {name}")
                else:
                    lines.append(f"- {json.dumps(item, sort_keys=True)}")
            else:
                lines.append(f"- {item}")
        return "\n".join(lines)
    return str(payload).strip()


def _bootstrap_record_rank(record: dict[str, Any]) -> tuple[int, int, int]:
    metadata = record.get("metadata", {})
    success = 1 if metadata.get("success") else 0
    total_turns = int(metadata.get("total_turns") or 0)
    tool_turns = sum(
        1
        for message in record.get("messages", [])
        if isinstance(message, dict)
        and message.get("role") == "assistant"
        and message.get("tool_calls")
    )
    return success, tool_turns, total_turns
