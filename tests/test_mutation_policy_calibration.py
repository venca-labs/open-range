from __future__ import annotations

import json
from pathlib import Path

import yaml
from click.testing import CliRunner

from open_range.curriculum import FrontierMutationPolicy, PopulationStats
from open_range.devtools.mutation_policy_calibration import (
    build_score_report,
    main,
)


def _population_entries() -> list[dict[str, object]]:
    return [
        {
            "snapshot_id": "snap-hard",
            "world_id": "world-hard",
            "split": "train",
            "episodes": 12,
            "red_win_rate": 0.05,
            "blue_win_rate": 0.9,
            "flake_rate": 0.02,
            "novelty": 0.8,
            "blue_signal_points": 5,
        },
        {
            "snapshot_id": "snap-frontier",
            "world_id": "world-frontier",
            "split": "train",
            "episodes": 8,
            "red_win_rate": 0.52,
            "blue_win_rate": 0.48,
            "flake_rate": 0.01,
            "novelty": 0.6,
            "blue_signal_points": 4,
        },
        {
            "snapshot_id": "snap-eval",
            "world_id": "world-eval",
            "split": "eval",
            "episodes": 50,
            "red_win_rate": 0.5,
            "blue_win_rate": 0.5,
            "flake_rate": 0.0,
            "novelty": 1.0,
            "blue_signal_points": 6,
        },
    ]


def _write_population_file(tmp_path: Path, payload: object) -> Path:
    population_path = tmp_path / "population.yaml"
    population_path.write_text(
        yaml.safe_dump(payload, sort_keys=False), encoding="utf-8"
    )
    return population_path


def test_build_score_report_exposes_component_contributions():
    report = build_score_report(
        [PopulationStats.model_validate(entry) for entry in _population_entries()],
        policy=FrontierMutationPolicy(),
    )

    assert report["eligible_candidates"] == 2
    assert len(report["skipped_candidates"]) == 1
    assert report["scores"][0]["snapshot_id"] == "snap-frontier"
    assert report["scores"][0]["signals"] == {
        "stability": 0.99,
        "frontier": 0.96,
        "novelty": 0.6,
        "signal_richness": 0.666667,
        "coverage": 0.8,
    }
    assert report["scores"][0]["contributions"] == {
        "stability": 0.3465,
        "frontier": 0.288,
        "novelty": 0.09,
        "signal_richness": 0.066667,
        "coverage": 0.08,
    }
    assert report["scores"][0]["total"] == 0.871167


def test_calibration_command_renders_text_report(tmp_path: Path):
    population_path = _write_population_file(
        tmp_path, {"population": _population_entries()}
    )

    result = CliRunner().invoke(main, ["--population", str(population_path)])

    assert result.exit_code == 0, result.output
    assert "Population size: 3" in result.output
    assert "Eligible train candidates: 2" in result.output
    assert "snap-frontier" in result.output
    assert "world-frontier" in result.output
    assert "frontier: value=0.960000 weight=0.30 contribution=0.288000" in result.output
    assert "Skipped candidates:" in result.output
    assert "snap-eval [world-eval] split=eval" in result.output


def test_calibration_command_renders_json_report(tmp_path: Path):
    population_path = _write_population_file(tmp_path, _population_entries())

    result = CliRunner().invoke(
        main,
        ["--population", str(population_path), "--format", "json"],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["weights"] == {
        "coverage": 0.1,
        "frontier": 0.3,
        "novelty": 0.15,
        "signal_richness": 0.1,
        "stability": 0.35,
    }
    assert payload["scores"][0]["snapshot_id"] == "snap-frontier"
    assert payload["scores"][0]["contributions"]["signal_richness"] == 0.066667
    assert payload["skipped_candidates"][0]["snapshot_id"] == "snap-eval"
