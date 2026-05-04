"""LLM-driven task instruction + verifier generation.

The procedural builder runs unchanged when no LLM is provided; these
tests exercise the LLM path with a scripted local backend so they're
hermetic (no network / no API keys).
"""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest
from cyber_webapp.llm_generation import (
    LLMGenerationError,
    generate_task_instruction,
    generate_verifier_source,
)

import openrange as OR
from openrange.core.builder import build
from openrange.core.errors import StoreError
from openrange.core.graph import Edge, Node, WorldGraph
from openrange.core.pack import Task

V1_MANIFEST: dict[str, object] = {
    "world": {"goal": "find the admin flag"},
    "pack": {"id": "cyber.webapp", "source": {"kind": "builtin"}},
}


# ---------------------------------------------------------------------------
# Scripted LLM backends (no network)
# ---------------------------------------------------------------------------


def _scripted_codex(tmp_path: Path, body: str) -> OR.CodexBackend:
    """Build a local CodexBackend that runs the given script."""
    path = tmp_path / "scripted_backend.py"
    path.write_text(
        "#!/usr/bin/env python3\n" + textwrap.dedent(body),
        encoding="utf-8",
    )
    path.chmod(0o755)
    return OR.CodexBackend(command=path, model="local", timeout=10)


_INSTRUCTION_BACKEND = """
import json
import sys
from pathlib import Path

output_path = Path(sys.argv[sys.argv.index("--output-last-message") + 1])
prompt = json.loads(sys.stdin.read().split("\\n\\n", 1)[1])
world = prompt["world"]
services = world["services"]
vulns = world["vulnerabilities"]
service_names = ", ".join(s["name"] for s in services)
vuln_kinds = ", ".join(v["kind"] for v in vulns) or "no known vulns"
output = {
    "instruction": (
        f"Find the admin flag exposed across services {service_names}. "
        f"Suspected vulnerability classes: {vuln_kinds}. "
        f"Read OPENRANGE_TASK.json for the base_url, then write the flag "
        f"to result.json."
    ),
}
output_path.write_text(json.dumps(output), encoding="utf-8")
"""


_VERIFIER_BACKEND = """
import json
import sys
from pathlib import Path

output_path = Path(sys.argv[sys.argv.index("--output-last-message") + 1])
prompt = json.loads(sys.stdin.read().split("\\n\\n", 1)[1])
output = {
    "verifier_source": (
        "def verify(state):\\n"
        "    result = state.get('result') or {}\\n"
        "    world = state.get('world') or {}\\n"
        "    submitted = result.get('flag')\\n"
        "    expected = world.get('flag')\\n"
        "    passed = (\\n"
        "        submitted is not None\\n"
        "        and submitted != ''\\n"
        "        and submitted == expected\\n"
        "    )\\n"
        "    return {\\n"
        "        'passed': passed,\\n"
        "        'score': 1.0 if passed else 0.0,\\n"
        "        'details': {'kind': 'llm-generated'},\\n"
        "    }\\n"
    ),
}
output_path.write_text(json.dumps(output), encoding="utf-8")
"""


_BAD_INSTRUCTION_BACKEND = """
import json
import sys
from pathlib import Path

output_path = Path(sys.argv[sys.argv.index("--output-last-message") + 1])
output_path.write_text(json.dumps({"instruction": ""}), encoding="utf-8")
"""


_BAD_VERIFIER_BACKEND = """
import json
import sys
from pathlib import Path

output_path = Path(sys.argv[sys.argv.index("--output-last-message") + 1])
output_path.write_text(
    json.dumps({"verifier_source": "x = 1  # no verify function"}),
    encoding="utf-8",
)
"""


# ---------------------------------------------------------------------------
# Standalone helper tests
# ---------------------------------------------------------------------------


def _trivial_graph() -> WorldGraph:
    return WorldGraph(
        nodes=(
            Node("svc_web", "service", {"name": "web", "kind": "web"}),
            Node(
                "ep_search",
                "endpoint",
                {"path": "/search", "method": "GET"},
            ),
            Node(
                "vuln_sqli",
                "vulnerability",
                {"kind": "sql_injection", "family": "code_web"},
            ),
            Node(
                "secret_flag",
                "secret",
                {"kind": "flag", "value_ref": "ORANGE{x}"},
            ),
        ),
        edges=(
            Edge("svc_web", "exposes", "ep_search"),
            Edge("vuln_sqli", "affects", "ep_search"),
        ),
    )


def test_generate_task_instruction_returns_llm_text(tmp_path: Path) -> None:
    backend = _scripted_codex(tmp_path, _INSTRUCTION_BACKEND)
    instruction = generate_task_instruction(_trivial_graph(), backend)
    assert "web" in instruction
    assert "sql_injection" in instruction
    assert "result.json" in instruction


def test_generate_task_instruction_rejects_empty_response(tmp_path: Path) -> None:
    backend = _scripted_codex(tmp_path, _BAD_INSTRUCTION_BACKEND)
    with pytest.raises(LLMGenerationError, match="usable instruction"):
        generate_task_instruction(_trivial_graph(), backend)


def test_generate_verifier_source_returns_parseable_python(tmp_path: Path) -> None:
    backend = _scripted_codex(tmp_path, _VERIFIER_BACKEND)
    task = Task(
        id="find_admin_flag",
        instruction="find the flag",
        entrypoints=(),
        verifier_id="admin_flag_found",
    )
    source = generate_verifier_source(_trivial_graph(), task, backend)
    assert "def verify(state):" in source
    # Smoke-execute the verifier to make sure the LLM-generated source is callable.
    verifier = OR.verifier_from_source(source)
    result = verifier({"result": {"flag": "x"}, "world": {"flag": "x"}})
    assert result["passed"] is True
    fail = verifier({"result": {"flag": ""}, "world": {"flag": "x"}})
    assert fail["passed"] is False


def test_generate_verifier_source_rejects_invalid_python(tmp_path: Path) -> None:
    backend = _scripted_codex(tmp_path, _BAD_VERIFIER_BACKEND)
    task = Task(
        id="t",
        instruction="i",
        entrypoints=(),
        verifier_id="v",
    )
    with pytest.raises(LLMGenerationError, match="invalid"):
        generate_verifier_source(_trivial_graph(), task, backend)


# ---------------------------------------------------------------------------
# Build pipeline integration
# ---------------------------------------------------------------------------


def _both_stages_backend(tmp_path: Path) -> OR.CodexBackend:
    """Backend that handles both instruction and verifier prompts.

    Distinguishes by checking which key appears in the prompt: the
    instruction prompt has a 'world' top-level key, the verifier
    prompt has 'world' AND 'task'.
    """
    body = """
import json
import sys
from pathlib import Path

output_path = Path(sys.argv[sys.argv.index("--output-last-message") + 1])
prompt = json.loads(sys.stdin.read().split("\\n\\n", 1)[1])
if "task" in prompt:
    output = {
        "verifier_source": (
            "def verify(state):\\n"
            "    result = state.get('result') or {}\\n"
            "    world = state.get('world') or {}\\n"
            "    submitted = result.get('flag')\\n"
            "    expected = world.get('flag')\\n"
            "    passed = (\\n"
            "        submitted is not None\\n"
            "        and submitted != ''\\n"
            "        and submitted == expected\\n"
            "    )\\n"
            "    return {\\n"
            "        'passed': passed,\\n"
            "        'score': 1.0 if passed else 0.0,\\n"
            "        'details': {'origin': 'llm'},\\n"
            "    }\\n"
        ),
    }
else:
    services = prompt["world"]["services"]
    vulns = prompt["world"]["vulnerabilities"]
    output = {
        "instruction": (
            f"Exploit services [{', '.join(s['name'] for s in services)}] "
            f"using {', '.join(v['kind'] for v in vulns) or 'available vulns'}. "
            f"Read OPENRANGE_TASK.json. Write result.json."
        ),
    }
output_path.write_text(json.dumps(output), encoding="utf-8")
"""
    return _scripted_codex(tmp_path, body)


def test_build_with_llm_uses_llm_generated_instruction(tmp_path: Path) -> None:
    snapshot = build(V1_MANIFEST, llm=_both_stages_backend(tmp_path))
    task = snapshot.get_tasks()[0]
    # Default template starts with "Read OPENRANGE_TASK.json"; LLM
    # output starts with "Exploit services...".
    assert task.instruction.startswith("Exploit services")


def test_build_with_llm_uses_llm_generated_verifier(tmp_path: Path) -> None:
    snapshot = build(V1_MANIFEST, llm=_both_stages_backend(tmp_path))
    source = snapshot.episode_checks[0].source
    assert "'origin': 'llm'" in source


def test_build_without_llm_falls_back_to_template_instruction() -> None:
    snapshot = build(V1_MANIFEST)
    task = snapshot.get_tasks()[0]
    assert task.instruction.startswith("Read OPENRANGE_TASK.json")


def test_build_with_failing_llm_falls_back_silently(tmp_path: Path) -> None:
    """An LLM that returns junk shouldn't sink the build."""
    backend = _scripted_codex(tmp_path, _BAD_INSTRUCTION_BACKEND)
    snapshot = build(V1_MANIFEST, llm=backend)
    # Falls back to template — empty LLM response triggers LLMGenerationError
    # which the builder swallows.
    assert snapshot.get_tasks()[0].instruction.startswith(
        "Read OPENRANGE_TASK.json",
    )


# ---------------------------------------------------------------------------
# Stored verifier still loadable after build
# ---------------------------------------------------------------------------


def test_llm_verifier_round_trips_through_snapshot(tmp_path: Path) -> None:
    snapshot = build(V1_MANIFEST, llm=_both_stages_backend(tmp_path))
    rebuilt = OR.Snapshot.from_mapping(snapshot.as_dict())
    verifier = rebuilt.verifier(rebuilt.get_tasks()[0].id)
    flag = next(
        n.attrs["value_ref"]
        for n in rebuilt.world_graph.nodes
        if n.type == "secret" and n.attrs.get("kind") == "flag"
    )
    result = verifier({"result": {"flag": flag}, "world": {"flag": flag}})
    assert result["passed"] is True


# Silence unused-import noise for typing helpers used in script bodies.
_ = StoreError
