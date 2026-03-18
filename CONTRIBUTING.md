# Contributing to OpenRange

Thanks for contributing.

## What To Work On

Small bug fixes, tests, docs improvements, and scoped quality-of-life changes are
great candidates for pull requests.

For larger features, behavioral changes, or broad refactors, please start with
an issue or discussion before investing heavily in implementation. That helps us
align on scope early and avoids wasted work.

## Local Setup

OpenRange uses [`uv`](https://github.com/astral-sh/uv) for local development.

```bash
uv sync --group dev
```

Useful smoke checks:

```bash
uv run openrange --help
uv run openrange-demo
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

## Pull Requests

Good pull requests are usually:

- scoped to one clear change
- explicit about what changed and why
- backed by tests when behavior changes
- accompanied by doc updates when public behavior or workflows change

Use the repository PR template in
[.github/PULL_REQUEST_TEMPLATE.md](.github/PULL_REQUEST_TEMPLATE.md).

Keep the `Testing` section short and factual:

- list the command(s) you ran
- mark them pass/fail
- if something was not run, say so plainly
- do not paste long terminal transcripts into the PR body

## Project Context

If you need more background before changing core behavior, start with:

- [`docs/architecture.md`](docs/architecture.md)
- [`docs/training-data-spec.md`](docs/training-data-spec.md)
- [`AGENTS.md`](AGENTS.md) for repo-specific Codex guidance
