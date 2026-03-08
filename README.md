---
title: OpenRange Environment Server
emoji: 🎯
colorFrom: red
colorTo: blue
sdk: docker
pinned: false
app_port: 8000
base_path: /web
tags:
  - openenv
  - rl-environment
---

# OpenRange

A multi-agent cybersecurity gymnasium on [OpenEnv](https://github.com/meta-pytorch/OpenEnv). Red and Blue agents train on validated enterprise networks that mutate between episodes.

---

## How It Works

A **manifest** declares a family of legal enterprise worlds — topology, services, identities, trust relationships, vulnerability classes, and mutation bounds. A shared **ManagedSnapshotRuntime** inside the shipped OpenEnv server process owns the admitted snapshot population. It compiles a graph-friendly root snapshot from the manifest, normalizing trust-only principals into a canonical principal catalog, then derives child snapshots by applying explicit typed mutations to admitted parents. Parent selection is policy-driven over the admitted population rather than raw latest/random sampling. Each candidate child is validated in layers: manifest compliance, canonical graph checks, structural/task checks, and, in managed-generation mode, booted runtime checks before admission. `reset()` selects one frozen admitted snapshot. `step()` runs commands inside it.

```mermaid
flowchart LR
    M[Manifest<br/>legal family +<br/>mutation envelope] --> B[Base snapshot compiler]
    B --> P[Admitted root snapshot]
    P --> R[ManagedSnapshotRuntime<br/>shared inside server process]
    R --> U[Policy-guided parent selector +<br/>typed mutator]
    U --> V{Validator<br/>manifest + graph +<br/>runtime checks}
    V -->|fail| U
    V -->|pass| S[Admitted snapshot population]
    S --> E["reset() → step() → obs + reward"]

    style V fill:#ffd93d,color:#333
    style S fill:#6bcb77,color:#fff
```

Red and Blue operate on the **same infrastructure simultaneously**. Red's stealth reward depends on whether Blue catches them. Blue's detection reward depends on Red's actual actions in the logs. This coupling drives co-evolution.

## Quick Start

```bash
# Install
git clone https://github.com/open-cybernauts/open-range.git
cd open-range
uv sync

# Optional: enable the LiteLLM-backed builder pipeline
uv sync --extra builder

# Optional: enable LiteLLM-backed synthetic teacher agents
uv sync --extra synthetic

# Optional: enable background refill inside the server
export OPENRANGE_ENABLE_MANAGED_REFILL=1
export OPENRANGE_RUNTIME_BUILDER=llm

# End-to-end demo (no Docker, no LLM)
uv run python examples/demo.py

# Generate synthetic SFT traces from a snapshot or manifest
uv run openrange synthetic-data \
  --manifest manifests/tier1_basic.yaml \
  --output data/sft_red.jsonl \
  --roles red

# Merge local bootstrap traces and tool context into generated output
uv run openrange synthetic-data \
  --manifest manifests/tier1_basic.yaml \
  --output data/synthetic_sft_5.jsonl \
  --num-traces 5 \
  --roles red \
  --bootstrap-traces data/sft.jsonl \
  --tool-info data/tool_info.md

# Run the OpenEnv client against a running server
uv run python examples/remote_client_demo.py --base-url http://localhost:8000

# Run the FastAPI server
uv run server                                   # default: 127.0.0.1:8000
uv run server --port 9000                       # custom port
uv run server --host 0.0.0.0                    # bind all interfaces

# Or via uvicorn directly
uv run uvicorn server.app:app --host 0.0.0.0 --port 8000 --reload

# Tests
uv run pytest tests/ -v --tb=short
```

## Core Components

**Manifest** — YAML defining the legal world family and mutation envelope: hosts, zones, services, users, NPCs, data assets, credential policies, monitoring coverage, trust relationships, and which vulnerability classes the runtime may plant or extend. Three example manifests ship (healthcare, fintech, SaaS) at tiers 1-3.

**ManagedSnapshotRuntime** — Shared singleton created at server startup. Owns the `SnapshotStore`, base builder, population-aware parent selector, parent-snapshot mutator, validator gate, `SnapshotRenderer`, snapshot preload, optional background refill, and episode-result feedback. This is the hidden orchestrator behind the env; callers still only see `reset()`, `step()`, and `state()`.

**Builder / Mutator** — The base builder compiles an initial `SnapshotSpec` from a manifest. Root hydration then expands that into canonical topology state: host details, dependency edges, trust edges, and a principal catalog that can represent trust-only people without inventing login accounts. The mutator derives child `SnapshotSpec`s from admitted parents using typed mutation plans plus an explicit mutation-policy layer that scores parents and candidate edits with curriculum, replay, novelty, and lineage signals. Each snapshot carries lineage metadata (`snapshot_id`, `parent_snapshot_id`, `root_snapshot_id`, generation depth, mutation summary) and can emit constrained service/app payloads through `SnapshotSpec.files`. Three base builders ship: `LLMSnapshotBuilder` (production, via litellm), `TemplateOnlyBuilder` (deterministic shipped default), `FileBuilder` (load from disk).

The deployed package exposes the standard OpenEnv `reset()`, `step()`, and `state()` contract through `server.app:app`, which is the entrypoint referenced by `openenv.yaml`.

**Validator** — Admission gate for candidate snapshots. The shipped runtime first enforces manifest compliance plus graph-native checks such as graph consistency, path solvability, evidence sufficiency, and reward grounding before structural/task checks. When `OPENRANGE_ENABLE_LIVE_ADMISSION=1`, the runtime also boots the rendered child bundle, applies rendered payload files, constructs a real `ContainerSet`, and runs live build/exploit/evidence/reward checks before admission. Public/HF mode can still rely on a prebuilt admitted pool with live admission disabled.

**Environment** — `RangeEnvironment(Environment)` following the OpenEnv contract. `reset()` asks the shared runtime for a frozen admitted snapshot. `step(action)` routes commands to the appropriate container — Red runs on the attacker box, Blue runs on the SIEM. No artificial command allowlists; the container's installed tools are the constraint.

**Rewards** — All grounded in container state, not LLM judgment:

| Red | Blue |
|-----|------|
| Flag capture (binary, `docker exec cat`) | Detection (TP rate vs Red's log) |
| Efficiency (`gamma^steps`) | Patch validity (re-run exploit, must fail) |
| Stealth (inversely coupled to Blue detection) | Availability (healthcheck fraction) |
| Anti-hallucination (-0.3 per fake flag) | False positive penalty (-0.2 per NPC flagged) |

**NPC Traffic** — Background noise and social engineering surface. Two levels:

- **Level 0** (shell scripts): `http_traffic.sh`, `db_traffic.sh`, `ssh_traffic.sh` generate benign traffic that Blue must filter from real attacks. Scripts discover targets dynamically (available pages, databases, tables) — no hardcoded endpoints.
- **Level 1** (LLM agents): Each NPC persona runs an autonomous workday via LiteLLM — browsing pages, sending emails, querying databases, accessing file shares. NPCs also react to incoming stimuli (phishing emails) based on their `security_awareness` profile.

All NPC actions are derived from the `SnapshotSpec` at runtime (pages, shares, tables, credentials, domain), so they generalize to any Builder-generated environment. NPC logs carry structured fields (`type`, `label`, `source`, `result`) that couple directly to Red/Blue reward signals.

Configure the NPC model via environment variable:
```bash
export OPENRANGE_NPC_MODEL="azure/gpt-5.2-codex"  # or openai/gpt-4o, anthropic/claude-haiku-4-5-20251001, ollama/llama3
```

**Agents** — Structural protocol: any object with `reset(briefing, role)` and `act(observation) -> command` works. Ships with `LLMRangeAgent` (litellm, any provider), `ScriptedAgent`, and `HumanAgent`.

**Synthetic Data** — `open_range.training.synthetic` provides snapshot-grounded trajectory generation for SFT warm-start. It uses a fast simulated `RangeEnvironment`, optional LiteLLM teacher agents, per-episode flag randomization, and exports JSONL through `TrajectoryLogger`.

```python
from open_range.agents.episode import run_episode
from open_range.agents.llm_agent import LLMRangeAgent
from open_range.server.environment import RangeEnvironment

env = RangeEnvironment()
red = LLMRangeAgent(model="anthropic/claude-sonnet-4-20250514")
blue = LLMRangeAgent(model="openai/gpt-4o")
result = run_episode(env, red, blue, max_steps=50)
```

## Tier System

Difficulty grows horizontally — more hosts, zones, and chained attack surface. Not just harder passwords.

| Tier | Scale | Example |
|------|-------|---------|
| 1 | 6-8 hosts, 3-4 zones | Healthcare clinic: web + DB + mail + LDAP + SIEM |
| 2 | 10-12 hosts, 5-6 zones | Financial firm: + VPN, internal APIs, certificate authority |
| 3 | 14-18 hosts, 7-8 zones | SaaS company: + CI/CD, container registry, partner extranet |

## Server Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Liveness check |
| GET | `/metadata` | Environment name, version |
| POST | `/reset` | Start episode, returns initial observation |
| POST | `/step` | Execute action, returns observation + reward |
| GET | `/state` | Current episode state |
| WS | `/ws` | WebSocket session |

Built directly on the OpenEnv HTTP/WebSocket contract.

## Docs

- [Architecture](docs/architecture.md) — full pipeline, network topology, episode lifecycle
- [Builder & Validator](docs/builder-validator.md) — snapshot generation and admission
- [Red & Blue Agents](docs/red-blue-agents.md) — tandem training, reward coupling, curriculum
- [Synthetic Data](docs/synthetic-data.md) — snapshot-backed SFT trace generation with LiteLLM teachers
- [Agent Protocols](docs/agent-protocols.md) — agent interface, episode runner, evaluation
- [OpenEnv Compliance](docs/openenv-compliance.md) — API contract, models, deployment

## Built On

- [OpenEnv](https://github.com/meta-pytorch/OpenEnv) — standardized agentic execution environments
- Ideas from [R2E-Gym](https://arxiv.org/abs/2504.07164) (hybrid verification), [Self-Play SWE-RL](https://arxiv.org/abs/2512.18552) (formal specs, inverse mutation), PAIRED/UED (constrained generation), POET (mutate + admit)

## License

Apache 2.0
