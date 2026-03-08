"""Training utilities for OpenRange."""

from open_range.training.dataset import (
    append_tool_context,
    extract_bootstrap_messages,
    load_jsonl_records,
    load_tool_context,
    write_jsonl_records,
)
from open_range.training.synthetic import (
    SyntheticRangeEnvironment,
    SyntheticTraceGenerator,
    build_teacher_agents,
    randomize_snapshot_flags,
)

__all__ = [
    "append_tool_context",
    "extract_bootstrap_messages",
    "load_jsonl_records",
    "load_tool_context",
    "SyntheticRangeEnvironment",
    "SyntheticTraceGenerator",
    "build_teacher_agents",
    "randomize_snapshot_flags",
    "write_jsonl_records",
]
