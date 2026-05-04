# OpenRange
![OpenRange visual](assets/open-range-visual.png)

[![License](https://img.shields.io/github/license/vecna-labs/open-range?style=flat-square)](LICENSE)
[![CI](https://img.shields.io/github/actions/workflow/status/vecna-labs/open-range/ci.yml?branch=main&style=flat-square)](https://github.com/vecna-labs/open-range/actions/workflows/ci.yml)
[![Issues](https://img.shields.io/github/issues/vecna-labs/open-range?style=flat-square)](https://github.com/vecna-labs/open-range/issues)
[![Pull Requests](https://img.shields.io/github/issues-pr/vecna-labs/open-range?style=flat-square)](https://github.com/vecna-labs/open-range/pulls)
[![Stars](https://img.shields.io/github/stars/vecna-labs/open-range?style=flat-square)](https://github.com/vecna-labs/open-range/stargazers)
[![Forks](https://img.shields.io/github/forks/vecna-labs/open-range?style=flat-square)](https://github.com/vecna-labs/open-range/forks)
[![Contributors](https://img.shields.io/github/contributors/vecna-labs/open-range?style=flat-square)](https://github.com/vecna-labs/open-range/graphs/contributors)

OpenRange is a domain-agnostic environment platform for training and evaluating agents. Give it a manifest and a pack; it builds a runnable world, verifies that tasks are actually solvable in the generated environment, freezes the result as a snapshot, and hands your agent harness a stable episode to run against.

> [!WARNING]
> OpenRange moves fast. Some docs describe the current implementation, while others describe the direction the project is working toward. APIs, pack contracts, examples, and dashboard details may change as the project stabilizes.

> [!NOTE]
> **Project Provenance:** OpenRange is managed by Vecna as an open-source project. The core evaluation engine and admission concepts were heavily inspired by the [open-cybernauts/open-range](https://github.com/open-cybernauts/open-range) proof of concept built during the OpenEnv HuggingFace Hackathon in early March.

### 📞 Community Call
Join us every **Friday at 12:00 PM CT** for the Open Range Community Call.
- 🎥 [Google Meet](https://meet.google.com/zuj-skfh-xjk)
- 📱 Dial in: [(US) +1 443-671-4919](tel:+14436714919) · PIN: `320 286 452#` · [More numbers](https://tel.meet/zuj-skfh-xjk?pin=6302524387334)
- 💬 [Join our Discord](https://discord.gg/KqDbvm9T5)

## How it works

OpenRange turns a request into an admitted world an agent can act inside:

```text
manifest + pack + builder
        → world graph + runtime artifacts + tasks
        → feasibility checks / admission
        → frozen world snapshot
        → agent episode
        → structured result
```

The key design boundary: **OpenRange owns the world, not the agent.** It handles world construction, task admission, runtime coordination, episode verification, and observability. Your harness owns the model, tools, rollout loop, training algorithm, and reward policy.

This lets OpenRange support different domains — cyber ranges, trading environments, robotics tasks, enterprise simulations — without forcing every agent framework into the same API shape. The agent interacts with whatever surface the world exposes: HTTP endpoints, files, shells, MCP tools, simulator APIs, browser sessions, or custom interfaces.

## Core concepts

**Manifests** describe what you want built: domain, scenario, constraints, task families, scale, and runtime backing.

**Packs** are the reusable starting points for a family of worlds. A pack might include code, containers, templates, simulator bindings, scripted state machines, seed data, and verifier helpers. It doesn't describe one world — it describes what kinds of worlds can be built and how.

**Builders** turn a manifest and pack into a concrete world. A builder can be handwritten Python, procedural generation, an LLM pipeline, or a hybrid. The builder outputs a world graph, runtime artifacts, tasks, feasibility checks, and admission metadata.

**Admission** is the gate between generation and execution. A feasibility check verifies that a generated task is actually solvable in the generated world. If a check fails, the builder repairs or regenerates the relevant piece. A task is never accepted without a passing feasibility check against a frozen world snapshot.

**Episodes** reset an admitted snapshot into separate environment and agent workspaces, run the agent, collect final state, and return a structured result — not a scalar reward. A training adapter maps that result into whatever signal your setup needs.

See [docs/start_here.md](docs/start_here.md) for the full design breakdown.

## Install

OpenRange uses [`uv`](https://github.com/astral-sh/uv) and requires Python 3.14.

```bash
uv sync --group dev
```

Optional Strands Agents support:

```bash
uv sync --extra strands
```

## Build a world

```python
import openrange as OR

run = OR.OpenRangeRun(OR.RunConfig("or-runs/dev-run", dashboard=True))
snapshot = run.build(
    {
        "world": {"goal": "find the admin flag in a vulnerable webapp"},
        "pack": {"id": "cyber.webapp.offense", "source": {"kind": "builtin"}},
    },
    llm=OR.CodexBackend(),
)

for task in snapshot.get_tasks():
    print(task.id, task.instruction)
```

The built-in `cyber.webapp.offense` pack is a loopback-only vulnerable Python HTTP app used as source context for generated web-offense tasks.

## Run an eval

Codex-backed eval pipeline:

```bash
uv run python -m examples.codex_eval \
  --runs-dir or-runs \
  --builder-timeout 300 \
  --agent-timeout 300 \
  --dashboard-port 8000
```

This builds an admitted snapshot, resets a webapp episode with separate environment and agent roots, runs Codex against the generated task instruction, collects final state, verifies it, and writes a report to an immutable run directory.

Strands Agents:

```bash
uv run --extra strands python -m examples.strands_eval \
  --run-root or-runs/strands-eval \
  --builder-timeout 300 \
  --dashboard-port 8000
```

OpenRange handles build, reset, final-state collection, verification, and reporting. Strands handles the agent loop and tools.

## Inspect runs

Live eval runs write two dashboard artifacts:

- `dashboard.events.jsonl` — append-only stream of builder and episode events
- `dashboard.json` — polling snapshot with builder steps and runtime turns

```bash
# Open a saved eval run
uv run openrange dashboard --run-root or-runs/<run-id>

# Inspect saved snapshots
uv run openrange dashboard --store-dir snapshots

# Build and inspect from the CLI
uv run openrange build path/to/manifest.yaml --output snapshots
uv run openrange inspect snapshots/<snapshot-id>.json
```


## Project layout

```text
src/openrange/    core library, runtime, dashboard, and built-in packs
examples/         runnable eval harness examples
docs/             design notes and implementation direction
tests/            integration-focused test suite
CONTRIBUTING.md   contribution workflow and local setup
```

Start with:

- [OpenRange overview](docs/start_here.md)
- [API lifecycle](docs/api.md)
- [Dashboard](docs/dashboard.md)
- [Contributing](CONTRIBUTING.md)

## Contributing

Contributions are welcome across code, docs, examples, pack design, bug reports, and design discussion. See [CONTRIBUTING.md](CONTRIBUTING.md) for local setup, the development workflow, and how to run the test suite. Open an issue for larger changes before building too far ahead, and use the pull request template when submitting changes.

Please follow the [Code of Conduct](CODE_OF_CONDUCT.md). Security-sensitive reports can go to **security@vecna-labs.dev**.

## License

OpenRange is released under the [MIT License](LICENSE).
