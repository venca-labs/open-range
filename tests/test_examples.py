from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from open_range.examples.bootstrap import run_bootstrap_demo
from open_range.examples.demo import run_demo


def test_demo_runs_against_checked_in_manifest():
    result = run_demo(quiet=True)

    assert result["snapshot_id"]
    assert result["done"] is True
    assert result["winner"] == "blue"
    assert result["turn_count"] >= 2


def test_bootstrap_demo_runs_against_checked_in_manifest():
    result = run_bootstrap_demo(quiet=True)

    assert result["snapshot_id"]
    assert result["bootstrap_turn_count"] >= 2
    assert set(result["bootstrap_roles"]) == {"blue", "red"}
    assert result["runtime_done"] is True
    assert result["runtime_winner"] == "blue"


REPO_ROOT = Path(__file__).resolve().parent.parent


def test_demo_script_entrypoint_runs():
    command_cwd = REPO_ROOT
    command = [
        sys.executable,
        "examples/demo.py",
        "--manifest",
        "manifests/tier1_basic.yaml",
        "--seed",
        "7",
    ]
    result = subprocess.run(
        command, capture_output=True, text=True, check=False, cwd=command_cwd
    )

    assert result.returncode == 0, result.stderr
    assert "winner=" in result.stdout
    assert "snapshot=" in result.stdout
