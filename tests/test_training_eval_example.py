from __future__ import annotations

import importlib.util
import json
import textwrap
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import cast
from urllib.request import urlopen

import pytest

import openrange as OR
from examples.strands_eval import (
    MANIFEST,
    StrandsAgentHarness,
    StrandsDependencyError,
    run_task,
)


@dataclass(frozen=True, slots=True)
class StaticBuilderBackend:
    def complete(self, request: OR.LLMRequest) -> OR.LLMResult:
        prompt = cast(Mapping[str, object], json.loads(request.prompt))
        output = verification_output() if "task" in prompt else world_output()
        return OR.LLMResult(json.dumps(output), output)


@dataclass(frozen=True, slots=True)
class HttpFileAgentHarness:
    def run(self, _instruction: str, cwd: Path) -> OR.LLMResult:
        task = json.loads((cwd / "OPENRANGE_TASK.json").read_text(encoding="utf-8"))
        base_url = str(task["base_url"])
        robots = urlopen(base_url + "/robots.txt", timeout=5).read().decode()
        admin = json.loads(
            urlopen(base_url + disallowed_path(robots), timeout=5).read().decode(),
        )
        (cwd / str(task["result_file"])).write_text(
            json.dumps({"flag": admin["flag"]}),
            encoding="utf-8",
        )
        return OR.LLMResult("done")


def world_output() -> dict[str, object]:
    return {
        "service": "webapp",
        "title": "OpenRange Web Portal",
        "flag": "ORANGE{webapp_admin_flag}",
    }


def verification_output() -> dict[str, object]:
    return {
        "verifier_source": textwrap.dedent(
            """
            def verify(state):
                result = state.get('result', {})
                world = state.get('world', {})
                passed = result.get('flag') == world.get('flag')
                passed = passed and world.get('flag') != ''
                return {'passed': passed, 'score': 1.0 if passed else 0.0}
            """,
        ),
        "admission_source": textwrap.dedent(
            """
            def admission_state(interface):
                robots = interface['http_get']('/robots.txt').decode()
                path = ''
                for line in robots.splitlines():
                    if line.startswith('Disallow:'):
                        path = line.split(':', 1)[1].strip()
                data = interface['http_get_json'](path)
                return {'result': {'flag': data['flag']}, 'requests': []}
            """,
        ),
    }


def disallowed_path(robots: str) -> str:
    for line in robots.splitlines():
        key, _, value = line.partition(":")
        if key.lower() == "disallow":
            return value.strip()
    raise AssertionError("robots.txt did not declare an admin path")


def has_strands_dependencies() -> bool:
    return (
        importlib.util.find_spec("strands") is not None
        and importlib.util.find_spec("strands_tools") is not None
        and importlib.util.find_spec("strands_tools.shell") is not None
    )


def test_strands_agent_harness_dependency_error_is_not_cli_specific() -> None:
    if has_strands_dependencies():
        pytest.skip("Strands optional dependencies are installed")

    with pytest.raises(StrandsDependencyError, match="Strands dependencies") as excinfo:
        StrandsAgentHarness().agent()

    assert "examples.strands_eval" not in str(excinfo.value)
    assert "uv run" not in str(excinfo.value)


def test_training_eval_runs_full_snapshot_episode_pipeline(tmp_path: Path) -> None:
    run_root = tmp_path / "run"
    run = OR.OpenRangeRun(run_root)
    snapshot = run.build(MANIFEST, llm=StaticBuilderBackend())
    task = snapshot.get_tasks()[0]

    report = run_task(
        snapshot,
        task,
        HttpFileAgentHarness(),
        run,
    )

    assert report["snapshot_id"] == snapshot.id
    assert report["task_id"] == task.id
    assert report["passed"] is True
    assert report["agent_summary"] == "done"
    assert report["verifier_result"] == {"passed": True, "score": 1.0}
    assert report["final_state"] == {
        "result": {"flag": "ORANGE{webapp_admin_flag}"},
        "world": {
            "difficulty": "llm",
            "flag": "ORANGE{webapp_admin_flag}",
            "mode": "simulation",
            "npc_count": 0,
            "previous_snapshot": None,
            "service": "webapp",
            "title": "OpenRange Web Portal",
        },
        "requests": [
            {"method": "GET", "path": "/robots.txt", "status": 200},
            {"method": "GET", "path": "/admin/debug", "status": 200},
        ],
    }
    assert json.loads(
        (run_root / task.id / "agent" / "OPENRANGE_TASK.json").read_text(
            encoding="utf-8",
        ),
    )["base_url"].startswith("http://127.0.0.1:")
