from __future__ import annotations

import json
import sys
import textwrap
from pathlib import Path

import pytest

import openrange as OR
from examples.codex_eval import (
    MANIFEST,
    CodexHarness,
    main,
    resolve_run_root,
    run_slug,
    run_task,
    write_report,
)


def executable(tmp_path: Path, name: str, body: str) -> Path:
    path = tmp_path / name
    path.write_text(
        "#!/usr/bin/env python3\n" + textwrap.dedent(body),
        encoding="utf-8",
    )
    path.chmod(0o755)
    return path


def builder_llm(tmp_path: Path) -> OR.CodexBackend:
    command = executable(
        tmp_path,
        "builder_backend.py",
        """
        import json
        import sys
        from pathlib import Path

        output_path = Path(sys.argv[sys.argv.index("--output-last-message") + 1])
        prompt = json.loads(sys.stdin.read().split("\\n\\n", 1)[1])
        if "task" in prompt:
            output = {
                "verifier_source": (
                    "def verify(state):\\n"
                    "    result = state.get('result', {})\\n"
                    "    world = state.get('world', {})\\n"
                    "    passed = result.get('flag') == world.get('flag')\\n"
                    "    passed = passed and world.get('flag') != ''\\n"
                    "    return {'passed': passed, "
                    "'score': 1.0 if passed else 0.0}\\n"
                ),
                "admission_source": (
                    "def admission_state(interface):\\n"
                    "    robots = interface['http_get']("
                    "'/robots.txt').decode()\\n"
                    "    path = ''\\n"
                    "    for line in robots.splitlines():\\n"
                    "        if line.startswith('Disallow:'):\\n"
                    "            path = line.split(':', 1)[1].strip()\\n"
                    "    data = interface['http_get_json'](path)\\n"
                    "    return {'result': {'flag': data['flag']}, "
                    "'requests': []}\\n"
                ),
            }
        else:
            output = {
                "service": "webapp",
                "title": "OpenRange Web Portal",
                "flag": "ORANGE{webapp_admin_flag}",
            }
        output_path.write_text(json.dumps(output), encoding="utf-8")
        """,
    )
    return OR.CodexBackend(command=command, model="local", timeout=5)


def test_codex_eval_allocates_fresh_or_runs_directory(tmp_path: Path) -> None:
    runs_dir = tmp_path / "or-runs"
    first = resolve_run_root(None, runs_dir, MANIFEST)
    second = resolve_run_root(None, runs_dir, MANIFEST)
    explicit = tmp_path / "explicit-run"
    stale = tmp_path / "stale-run"
    stale.mkdir()
    (stale / "dashboard.json").write_text("{}", encoding="utf-8")

    report = {"run_root": str(first), "reports": []}
    write_report(first, report)

    assert first.parent == runs_dir
    assert second.parent == runs_dir
    assert first != second
    assert first.name.endswith("-find_admin_flag_vulnerable_webapp")
    assert second.name.endswith("-find_admin_flag_vulnerable_webapp")
    assert run_slug({"world": {"goal": "!!!"}}) == "eval"
    assert run_slug({"world": "invalid"}) == "eval"
    assert resolve_run_root(explicit, runs_dir, MANIFEST) == explicit
    assert explicit.exists()
    assert json.loads((first / "report.json").read_text(encoding="utf-8")) == report
    with pytest.raises(OR.EpisodeRuntimeError, match="not empty"):
        resolve_run_root(stale, runs_dir, MANIFEST)


def test_codex_eval_main_writes_report_under_unique_run_root(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    command = executable(
        tmp_path,
        "codex_cli.py",
        """
        import json
        import sys
        from pathlib import Path
        from urllib.request import urlopen

        task_file = Path("OPENRANGE_TASK.json")
        if task_file.exists():
            task = json.loads(task_file.read_text(encoding="utf-8"))
            base_url = task["base_url"]
            urlopen(base_url + "/robots.txt", timeout=5).read()
            admin = json.loads(
                urlopen(base_url + "/admin/debug", timeout=5).read().decode(),
            )
            Path(task["result_file"]).write_text(
                json.dumps({"flag": admin["flag"]}),
                encoding="utf-8",
            )
            print("done")
            raise SystemExit

        output_path = Path(sys.argv[sys.argv.index("--output-last-message") + 1])
        prompt = json.loads(sys.stdin.read().split("\\n\\n", 1)[1])
        if "task" in prompt:
            output = {
                "verifier_source": (
                    "def verify(state):\\n"
                    "    result = state.get('result', {})\\n"
                    "    world = state.get('world', {})\\n"
                    "    passed = result.get('flag') == world.get('flag')\\n"
                    "    passed = passed and world.get('flag') != ''\\n"
                    "    return {'passed': passed, "
                    "'score': 1.0 if passed else 0.0}\\n"
                ),
                "admission_source": (
                    "def admission_state(interface):\\n"
                    "    robots = interface['http_get']("
                    "'/robots.txt').decode()\\n"
                    "    path = ''\\n"
                    "    for line in robots.splitlines():\\n"
                    "        if line.startswith('Disallow:'):\\n"
                    "            path = line.split(':', 1)[1].strip()\\n"
                    "    data = interface['http_get_json'](path)\\n"
                    "    return {'result': {'flag': data['flag']}, "
                    "'requests': []}\\n"
                ),
            }
        else:
            output = {
                "service": "webapp",
                "title": "OpenRange Web Portal",
                "flag": "ORANGE{webapp_admin_flag}",
            }
        output_path.write_text(json.dumps(output), encoding="utf-8")
        """,
    )
    runs_dir = tmp_path / "or-runs"
    old_argv = sys.argv

    try:
        sys.argv = [
            "examples.codex_eval",
            "--runs-dir",
            str(runs_dir),
            "--codex-command",
            str(command),
            "--model",
            "local",
            "--builder-timeout",
            "5",
            "--agent-timeout",
            "5",
            "--no-dashboard",
        ]
        main()
    finally:
        sys.argv = old_argv

    output = json.loads(capsys.readouterr().out)
    run_root = Path(str(output["run_root"]))

    assert run_root.parent == runs_dir
    assert output["reports"][0]["passed"] is True
    assert output["reports"][0]["agent_summary"] == "done"
    assert json.loads((run_root / "report.json").read_text(encoding="utf-8")) == output
    assert not (run_root / "dashboard.json").exists()


def test_codex_eval_runs_full_snapshot_episode_pipeline(tmp_path: Path) -> None:
    command = executable(
        tmp_path,
        "codex_agent.py",
        """
        import json
        import sys
        from pathlib import Path
        from urllib.request import urlopen

        prompt = sys.stdin.read()
        Path("seen_prompt.txt").write_text(prompt, encoding="utf-8")
        task = json.loads(Path("OPENRANGE_TASK.json").read_text(encoding="utf-8"))
        base_url = task["base_url"]
        urlopen(base_url + "/robots.txt", timeout=5).read()
        admin = json.loads(
            urlopen(base_url + "/admin/debug", timeout=5).read().decode(),
        )
        Path(task["result_file"]).write_text(
            json.dumps({"flag": admin["flag"]}),
            encoding="utf-8",
        )
        print("done")
        """,
    )
    run_root = tmp_path / "run"
    run = OR.OpenRangeRun(OR.RunConfig(run_root, dashboard_port=0))
    snapshot = run.build(
        MANIFEST,
        llm=builder_llm(tmp_path),
    )
    harness = CodexHarness(command=command, model="local")
    task = snapshot.get_tasks()[0]

    report = run_task(snapshot, task, harness, run)
    agent_root = run_root / task.id / "agent"
    task_file = json.loads(
        (agent_root / "OPENRANGE_TASK.json").read_text(encoding="utf-8"),
    )

    assert task.interface == task.entrypoints
    assert task.interface[0].kind == "http"
    assert task.interface[0].target == "webapp"
    assert report["snapshot_id"] == snapshot.id
    assert report["task_id"] == task.id
    assert report["passed"] is True
    assert report["agent_summary"] == "done"
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
    assert task.verify(report["final_state"])["passed"] is True
    assert (agent_root / "seen_prompt.txt").read_text(
        encoding="utf-8",
    ) == task.instruction
    assert task_file["task_id"] == task.id
    assert task_file["base_url"].startswith("http://127.0.0.1:")
    assert task_file["result_schema"] == {
        "properties": {
            "flag": {"type": "string", "world_field": "flag"},
        },
        "required": ["flag"],
        "type": "object",
    }
    assert task_file["result_file"] == "result.json"
    assert "dashboard" not in report
    dashboard_events = [
        json.loads(line)
        for line in (run_root / "dashboard.events.jsonl").read_text(
            encoding="utf-8",
        ).splitlines()
    ]
    dashboard = json.loads(
        (run_root / "dashboard.json").read_text(encoding="utf-8"),
    )
    turns = [
        event["data"]
        for event in dashboard_events
        if event["type"] == "env_turn"
    ]
    builder_steps = [
        event["data"]
        for event in dashboard_events
        if event["type"] == "builder_step"
    ]

    assert [turn["action"] for turn in turns] == [
        {"reset": True},
        {"start": "http_server"},
        {"method": "GET", "path": "/robots.txt"},
        {"method": "GET", "path": "/admin/debug"},
        {"finish": True},
    ]
    assert [step["step"] for step in builder_steps] == [
        "build_started",
        "pack_resolved",
        "attempt_started",
        "world_generation_started",
        "world_generated",
        "task_generation_started",
        "task_generated",
        "verifier_generation_started",
        "verifier_generated",
        "admission_probe_started",
        "admission_probe_generated",
        "admission_started",
        "admission_passed",
        "snapshot_created",
        "builder_finished",
    ]
    assert "ORANGE{" not in json.dumps(builder_steps)
    assert dashboard["turns"] == turns
    assert dashboard["builder"]["steps"] == builder_steps
    assert dashboard["state"]["events"] == dashboard_events


def test_codex_eval_rejects_snapshot_result_without_http_requests(
    tmp_path: Path,
) -> None:
    command = executable(
        tmp_path,
        "codex_agent.py",
        """
        import json
        from pathlib import Path

        task = json.loads(Path("OPENRANGE_TASK.json").read_text(encoding="utf-8"))
        Path(task["result_file"]).write_text(
            json.dumps({"flag": "ORANGE{webapp_admin_flag}"}),
            encoding="utf-8",
        )
        print("done")
        """,
    )
    snapshot = OR.build(MANIFEST, llm=builder_llm(tmp_path))
    harness = CodexHarness(command=command, model="local")
    task = snapshot.get_tasks()[0]

    with pytest.raises(OR.EpisodeRuntimeError, match="public interface"):
        run_task(snapshot, task, harness, tmp_path / "run")
