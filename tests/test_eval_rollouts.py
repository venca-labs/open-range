from __future__ import annotations

import importlib.util
from pathlib import Path


def _load_module(name: str, relpath: str):
    path = Path(__file__).resolve().parents[1] / relpath
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_evaluate_rollouts_builds_mutations_and_reports_modes() -> None:
    mod = _load_module("eval_rollouts", "scripts/eval_rollouts.py")
    report = mod.evaluate_rollouts(manifest="tier1_basic.yaml", mutations=1, quiet=True)

    assert report["snapshot_count"] == 2
    assert len(report["snapshots"]) == 2
    assert {"joint_pool", "red_only", "blue_only_live", "blue_only_from_prefix"} <= set(
        report["aggregate"]
    )
    assert report["snapshots"][0]["validator"]["admitted"] is True
