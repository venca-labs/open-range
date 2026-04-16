# Contributing to OpenRange

Thanks for contributing.

## What To Work On

Small bug fixes, tests, docs improvements, and scoped quality-of-life changes are
great candidates for pull requests.

Please start with an issue or discussion before investing heavily in:

- larger features or scope-expanding behavior
- admission, runtime, or validation contract changes
- broad refactors or compatibility shims back toward the deleted architecture

## Local Setup

OpenRange uses [`uv`](https://github.com/astral-sh/uv) for local development.

```bash
uv sync --group dev
```

Useful smoke checks:

```bash
uv run openrange --help
```

Training dependencies are optional:

```bash
uv sync --extra training
```

## Checks

Before opening a pull request, run the checks relevant to your change.

```bash
uv run ruff format --check .
uv run ruff check .
uv run pytest tests/ -v --tb=short
```

Optional Docker parse check:

```bash
docker buildx build --check -f Dockerfile .
```

For local iteration, prefer targeted tests first. If your change touches
admission, runtime, Kind-backed flows, training, or evaluation, include the
exact non-routine verification commands you ran in the PR description.

## Pull Requests

Good pull requests are usually:

- scoped to one clear change
- explicit about what changed and why
- backed by tests when behavior changes
- accompanied by doc updates when public behavior or workflows change

Target `dev` by default unless a maintainer asks for a different base branch.

Use the repository PR template in
[.github/PULL_REQUEST_TEMPLATE.md](.github/PULL_REQUEST_TEMPLATE.md).

Keep the `Testing` section short and factual:

- list only manual or non-routine verification that reviewers would not
  otherwise see in CI
- if there was no special verification beyond CI-covered lint/unit checks, say
  that plainly
- do not paste long terminal transcripts into the PR body

Use `Review Notes` only for reviewer focus areas, tradeoffs, risks, or follow-up
work.

## Project Context

If you need more background before changing core behavior, start with:

- [`docs/architecture.md`](docs/architecture.md)
- [`docs/training-data-spec.md`](docs/training-data-spec.md)
- [`AGENTS.md`](AGENTS.md) for repo-specific Codex guidance
