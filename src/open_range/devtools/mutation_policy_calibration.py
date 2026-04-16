"""Inspect and compare mutation-policy parent scoring for development workflows."""

from __future__ import annotations

import json
from typing import Any, TextIO

import click
import yaml
from pydantic import ValidationError

from open_range.curriculum import FrontierMutationPolicy, PopulationStats


def _load_population(stream: TextIO) -> list[PopulationStats]:
    source_name = getattr(stream, "name", "<stdin>")
    payload = yaml.safe_load(stream.read())
    if isinstance(payload, list):
        entries = payload
    elif isinstance(payload, dict) and "population" in payload:
        entries = payload["population"]
    else:
        raise click.ClickException(
            f"{source_name} must be a list of PopulationStats entries or a mapping "
            "with a top-level 'population' list"
        )
    if not isinstance(entries, list):
        raise click.ClickException(
            f"{source_name} must provide population entries as a list"
        )
    try:
        return [PopulationStats.model_validate(entry) for entry in entries]
    except ValidationError as exc:
        raise click.ClickException(
            f"invalid PopulationStats entry in {source_name}: {exc}"
        ) from exc


def build_score_report(
    population: list[PopulationStats],
    *,
    policy: FrontierMutationPolicy | None = None,
) -> dict[str, Any]:
    active_policy = policy or FrontierMutationPolicy()
    scores = active_policy.score_parents(population)
    return {
        "weights": active_policy.score_weights(),
        "population_size": len(population),
        "eligible_candidates": len(scores),
        "skipped_candidates": [
            entry.model_dump(mode="json")
            for entry in population
            if entry.split != "train"
        ],
        "scores": [score.model_dump(mode="json") for score in scores],
    }


def render_text_report(report: dict[str, Any]) -> str:
    weights: dict[str, float] = report["weights"]
    scores: list[dict[str, Any]] = report["scores"]
    skipped: list[dict[str, Any]] = report["skipped_candidates"]

    lines = [
        f"Population size: {report['population_size']}",
        f"Eligible train candidates: {report['eligible_candidates']}",
        f"Skipped non-train candidates: {len(skipped)}",
    ]

    if scores:
        snapshot_width = max(
            len("Snapshot"), *(len(score["snapshot_id"]) for score in scores)
        )
        world_width = max(len("World"), *(len(score["world_id"]) for score in scores))
        rank_width = len("Rank")
        total_width = len("Total")
        lines.extend(
            [
                "",
                f"{'Rank':<{rank_width}}  {'Snapshot':<{snapshot_width}}  {'World':<{world_width}}  {'Total':>{total_width}}",
                f"{'-' * rank_width}  {'-' * snapshot_width}  {'-' * world_width}  {'-' * total_width}",
            ]
        )
        for index, score in enumerate(scores, start=1):
            lines.append(
                f"{index:<{rank_width}}  {score['snapshot_id']:<{snapshot_width}}  "
                f"{score['world_id']:<{world_width}}  {score['total']:.6f}"
            )

        for index, score in enumerate(scores, start=1):
            lines.extend(
                [
                    "",
                    (
                        f"{index}. {score['snapshot_id']} [{score['world_id']}] "
                        f"total={score['total']:.6f}"
                    ),
                ]
            )
            for signal_name, weight in weights.items():
                lines.append(
                    "   "
                    f"{signal_name}: value={score['signals'][signal_name]:.6f} "
                    f"weight={weight:.2f} "
                    f"contribution={score['contributions'][signal_name]:.6f}"
                )
    else:
        lines.extend(["", "No train-split candidates were eligible for scoring."])

    if skipped:
        lines.extend(["", "Skipped candidates:"])
        for entry in skipped:
            lines.append(
                f"  - {entry['snapshot_id']} [{entry['world_id']}] split={entry['split']}"
            )

    return "\n".join(lines)


@click.command()
@click.option(
    "--population",
    "population_file",
    required=True,
    type=click.File("r", encoding="utf-8"),
    help=(
        "JSON or YAML file containing PopulationStats entries. The file may be a "
        "top-level list or a mapping with a 'population' list. Use '-' for stdin."
    ),
)
@click.option(
    "--format",
    "output_format",
    default="text",
    show_default=True,
    type=click.Choice(["text", "json"]),
    help="Render a human-readable calibration report or machine-readable JSON.",
)
def main(population_file: TextIO, output_format: str) -> None:
    """Inspect parent-score behavior for the v1 frontier mutation policy."""
    population = _load_population(population_file)
    report = build_score_report(population)
    if output_format == "json":
        click.echo(json.dumps(report, indent=2, sort_keys=True))
        return
    click.echo(render_text_report(report))


if __name__ == "__main__":
    main()
