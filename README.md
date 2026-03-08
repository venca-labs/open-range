# OpenRange

**Multi-agent cyber range with zero-sum Red/Blue dynamics, validated company snapshots, and self-improving enterprise worlds.**

The first cybersecurity environment in the [OpenEnv](https://github.com/meta-pytorch/OpenEnv) ecosystem.

---

## What is this?

OpenRange drops Red and Blue agents into a **real enterprise network** -- firewalls, web apps, databases, directory services, mail servers, VPNs, SIEM -- then lets them fight. The environment is not a single static benchmark and it is not a free-form LLM sandbox. A manifest defines a legal family of company worlds. A LiteLLM-led builder/mutator proposes candidate snapshots inside that family. Every proposal is compiled into a canonical `SnapshotSpec` (a typed snapshot specification for that company world) plus hidden topology, truth, evidence, and task graphs. Deterministic helper checks make those proposals admissible. `reset()` then selects a **frozen validated snapshot** for the next episode, while background mutation prepares future snapshots asynchronously.

```
You define the legal company family:
  topology, identities, services, bug families, task families, difficulty knobs

The LiteLLM builder/mutator proposes a candidate snapshot:
  add billing-api -> seed SSRF -> derive exploit/remediation chain -> emit evidence

The proposal compiles into a canonical SnapshotSpec + hidden graphs:
  topology graph + truth graph + evidence graph + task graph

Deterministic helper-backed validation admits only runnable snapshots:
  manifest compliance, reachability, exploitability, patchability,
  evidence sufficiency, reward grounding, isolation/leakage

The OpenEnv runtime stays standard:
  reset() -> pick frozen snapshot + sample task
  step(action) -> act inside that snapshot
```

## Core Components

| Component | What it does | Typical implementation |
|------|-------------|-------------|
| **Manifest compiler** | Defines the legal world space: topology, services, identities, bug families, task families, difficulty knobs | YAML schema + templates |
| **Builder / mutator** | Uses LiteLLM to propose candidate snapshots, mutations, and task structure inside the manifest-constrained family | LiteLLM + rules + templates |
| **Canonical `SnapshotSpec`** | Compiles the proposal into typed hidden truth: topology, truth, evidence, and task graphs | Pydantic models + graph structs |
| **Deterministic helpers** | Answer the specific admission questions: compliance, solvability, exploitability, patchability, evidence, reward grounding | Mechanical check modules |
| **Validator gate** | Combines helper outputs and admits only snapshots that are runnable, coherent, and solvable | Mechanical admission over graph/spec + rendered artifacts |
| **Snapshot manager** | Publishes admitted company snapshots and hands a frozen one to `reset()` | Background queue + snapshot store |
| **Red** | External attacker. Recon, exploit, pivot, escalate, exfiltrate. | Outside the firewall -- no creds, no access |
| **Blue** | Internal defender. SIEM analysis, patching, firewall rules, incident response. | SOC workstation on management network |

Red and Blue operate on the **same infrastructure simultaneously** in a zero-sum adversarial dynamic. Red's stealth reward depends on whether Blue catches them. Blue's detection reward depends on Red's actual actions in the logs. This multi-agent coupling creates natural co-evolution: as Red learns stealth, Blue must learn deeper detection -- and vice versa.

## Architecture

```mermaid
flowchart LR
    A[Base company family<br/>AcmeCorp repo, infra, docs, tools] --> B
    M[Manifest / mutation policy<br/>allowed services, bug families, task families] --> B
    S[Curriculum / failure stats<br/>what Red or Blue is weak at] --> B

    B[LiteLLM builder / mutator<br/>propose next snapshot<br/>mutations, bugs, tasks] --> C

    subgraph C[Canonical SnapshotSpec and hidden graphs]
        C1[Topology graph<br/>hosts, services, users, trust edges]
        C2[Truth graph<br/>bug, exploit chain, blast radius, remediation]
        C3[Evidence graph<br/>logs, alerts, files, tickets, docs]
        C4[Task graph<br/>exploit, investigate, patch, report]
    end

    C --> D
    D{Validator gate<br/>build/run, exploitability,<br/>patchability, evidence, reward} -->|fail| B
    D -->|pass| E[Frozen validated snapshot<br/>Acme v_k]

    subgraph R[OpenEnv runtime]
        F["reset()<br/>select frozen snapshot + sample task + init episode"]
        G[Red / Blue agents]
        H["step(action)<br/>run command or tool on current frozen snapshot"]
        I[Observation + reward]
        J[Rollout results<br/>solve rate, evidence quality, patch validity]
    end

    E --> F
    F --> G
    G --> H
    H --> I
    I --> G
    H --> J

    J -. async evolve next snapshot .-> S

    style A fill:#4a9eff,color:#fff
    style M fill:#4a9eff,color:#fff
    style B fill:#ff6b6b,color:#fff
    style D fill:#ffd93d,color:#333
    style E fill:#6bcb77,color:#fff
    style R fill:#7c73e611,stroke:#7c73e6
```

The generator here is a **LiteLLM-led proposal pipeline** rather than a free-form oracle. The model proposes the world, the canonical graph/spec makes it legible, and deterministic helpers make it admissible. That keeps core world logic manifest-constrained and validator-checkable even when the builder uses model-generated code, docs, tickets, or alert text.

Serving stays OpenEnv/Hugging Face-friendly: the deployed app exposes the normal `reset()`, `step()`, and `state` contract, and admitted snapshots can be served without live model calls in the request path. When packaged for deployment, that contract can be wrapped with the required OpenEnv/HF metadata.

## Network Topology

Even the **basic** range emulates a real corporate network. Every tier is a functioning enterprise with interconnected services, proper network segmentation, and realistic traffic.

```mermaid
flowchart TB
    subgraph internet [Internet]
        ATK[Red Agent<br/>Attacker Workstation]
    end

    subgraph fw [Perimeter Firewall - iptables]
        FW1[Firewall<br/>NAT + ACLs + IDS]
    end

    subgraph dmz [DMZ Network - 10.0.1.0/24]
        WEB[Web Server<br/>nginx reverse proxy<br/>+ PHP/Python app]
        MAIL[Mail Server<br/>Postfix SMTP<br/>+ Dovecot IMAP]
        DNS[DNS Server<br/>Bind9<br/>corp.local zone]
    end

    subgraph internal [Internal Network - 10.0.2.0/24]
        DB[Database Server<br/>MySQL + PostgreSQL<br/>app data + credentials]
        FILES[File Server<br/>Samba SMB shares<br/>sensitive docs + configs]
        APP[App Server<br/>Internal APIs<br/>microservices]
    end

    subgraph mgmt [Management Network - 10.0.3.0/24]
        AD[Domain Controller<br/>OpenLDAP + Kerberos<br/>Active Directory]
        SIEM[SIEM + Log Server<br/>Rsyslog + ELK<br/>Blue agent entry point]
        JUMP[Jump Box<br/>SSH bastion<br/>admin access only]
    end

    ATK -->|ports 80,443,25| FW1
    FW1 --> WEB
    FW1 --> MAIL
    FW1 --> DNS
    WEB -->|SQL queries| DB
    WEB -->|LDAP auth| AD
    MAIL -->|user lookup| AD
    APP -->|file access| FILES
    APP -->|DB queries| DB
    FILES -->|auth| AD
    DB -->|logs| SIEM
    WEB -->|logs| SIEM
    MAIL -->|logs| SIEM
    AD -->|logs| SIEM
    JUMP -->|admin SSH| WEB
    JUMP -->|admin SSH| DB

    style internet fill:#ff6b6b22,stroke:#ff6b6b
    style fw fill:#ffd93d22,stroke:#ffd93d
    style dmz fill:#4a9eff22,stroke:#4a9eff
    style internal fill:#6bcb7722,stroke:#6bcb77
    style mgmt fill:#7c73e622,stroke:#7c73e6
```

**This is what Red has to break into. This is what Blue has to defend.**

Every service is real. The web app queries the database. Users authenticate against LDAP. Mail flows through Postfix. Logs stream to the SIEM. NPC traffic simulates employees browsing, sending email, and running cron jobs -- so Blue can't just flag everything as malicious.

NPCs evolve from shell-script noise generators to **LLM-driven simulated experts** -- employees with persona cards, susceptibility profiles, and realistic communication styles. These are domain-specialized LLM agents (marketing coordinator, CISO, IT admin) that generate authentic enterprise behavior: sending emails, filing tickets, browsing intranet, and responding to social engineering attempts based on their security awareness level. Red can craft spearphishing emails, pretext calls, and watering-hole attacks against NPCs who decide whether to click, ignore, or report. Blue must detect these social engineering campaigns in logs alongside normal NPC traffic.

## Episode Lifecycle

```mermaid
sequenceDiagram
    participant W as Background Mutator
    participant V as Validator
    participant S as Snapshot Store
    participant T as Training Loop
    participant E as OpenEnv Server
    participant C as Frozen Company Snapshot

    W->>W: Apply legal mutations from manifest
    W->>W: Seed bug chain, evidence, and tasks
    W->>V: Candidate snapshot + truth graph
    V->>V: Build/run, exploitability, patchability, reward checks
    alt PASS
        V->>S: Publish Acme v_k
    else FAIL
        V-->>W: Retry with failure context
    end

    T->>E: reset()
    E->>S: Select validated snapshot + task
    S-->>E: Frozen snapshot Acme v_k
    E-->>T: RangeObservation with task briefing

    rect rgb(255, 107, 107, 0.1)
        Note over T,C: Red Team Operations on the frozen snapshot
        T->>E: step Red: nmap perimeter scan
        E->>C: docker exec attacker nmap -sV fw
        C-->>E: 80, 443, 25 open
        E-->>T: observation + reward

        T->>E: step Red: enumerate web app
        E->>C: docker exec attacker nikto web
        C-->>E: discovered /admin, /api, /search
        E-->>T: observation + reward

        T->>E: step Red: exploit SQLi in search
        E->>C: docker exec attacker curl ...
        C-->>E: DB credentials leaked
        E-->>T: observation + reward

        T->>E: step Red: pivot to internal DB
        E->>C: docker exec attacker mysql -h db ...
        C-->>E: flag captured from flags table
        E-->>T: observation + flag reward
    end

    rect rgb(74, 158, 255, 0.1)
        Note over T,C: Blue Team Operations on the same frozen snapshot
        T->>E: step Blue: check SIEM alerts
        E->>C: docker exec siem tail alerts
        C-->>E: anomalous queries from web to db
        E-->>T: observation + reward

        T->>E: step Blue: analyze attack pattern
        E->>C: docker exec siem grep SQLi signatures
        C-->>E: injection pattern matched
        E-->>T: observation + detection reward

        T->>E: step Blue: patch and block
        E->>C: docker exec web parameterize query
        C-->>E: patch applied, firewall rule added
        E-->>T: observation + patch reward
    end

    Note over W,S: Background mutation affects future resets only
    Note over T,C: Rewards computed from container state and action logs
```

## Episodes vs Evolution

`reset()` does **not** rebuild the world in the hot path. It selects a prevalidated company snapshot and starts a new task session on that frozen state. Mutation and admission happen between episodes, so OpenRange stays compatible with the normal OpenEnv `reset()`, `step()`, and `state()` contract without collapsing into a static benchmark.

```mermaid
flowchart LR
    subgraph ep1 [Episode A]
        direction TB
        A1["reset() selects Acme v12"] --> B1[Red and Blue act inside frozen snapshot]
    end

    subgraph bg [Between Episodes]
        direction TB
        M1[Mutator proposes Acme v13] --> M2{Validator gate}
        M2 -->|fail| M1
        M2 -->|pass| M3[Publish Acme v13]
    end

    subgraph ep2 [Episode B]
        direction TB
        A2["future reset() selects Acme v13"] --> B2[New task on next frozen snapshot]
    end

    ep1 -->|episode ends| bg
    bg -->|"next reset()"| ep2

    style ep1 fill:#ff6b6b22,stroke:#ff6b6b
    style bg fill:#ffd93d22,stroke:#ffd93d
    style ep2 fill:#6bcb7722,stroke:#6bcb77
```

Agents still have to **generalize** across vulnerability classes, pivot chains, evidence patterns, and remediation paths -- but each episode remains coherent because the active world is frozen while the agent interacts with it.

## Quick Start

```bash
# Install
git clone https://github.com/open-cybernauts/open-range.git
cd open-range
uv sync --all-extras

# Run the end-to-end demo (no Docker, no LLM required)
uv run python examples/demo.py

# Run the FastAPI server
python -m open_range.server                     # default: 127.0.0.1:8000
python -m open_range.server --port 9000         # custom port
python -m open_range.server --host 0.0.0.0      # bind all interfaces

# Or via uvicorn directly
uv run uvicorn open_range.server.app:app --host 0.0.0.0 --port 8000 --reload
```

### Server Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Liveness check |
| GET | `/metadata` | Environment name, version, description |
| GET | `/schema` | JSON schemas for action, observation, state |
| POST | `/reset` | Reset environment, returns initial observation |
| POST | `/step` | Execute an action, returns observation + reward + done |
| GET | `/state` | Current episode state |
| WS | `/ws` | Persistent WebSocket session (per-connection environment) |

If `openenv` is installed, the server delegates to `openenv.core.env_server.create_app`. Otherwise it falls back to an equivalent standalone FastAPI app.

## Reward Signals

Episodes are **long-horizon** (8-50+ steps depending on tier) with **sparse delayed rewards**. Flag capture is binary and only fires at the end of a successful exploit chain. Stealth and detection rewards are computed at episode end from the full action log. Intermediate steps yield only small efficiency signals -- agents must learn to plan multi-step strategies without dense per-action feedback.

All rewards are **verifiable** -- grounded in real container state, not LLM judgment. Reward ceilings **scale with environment complexity**: higher-tier snapshots (more hosts, zones, and chained vulnerabilities) offer proportionally larger maximum rewards, ensuring the training signal grows with output quality.

```mermaid
flowchart TB
    subgraph red [Red Rewards]
        RF[Flag Capture<br/>docker exec cat flag<br/>binary match]
        RE[Efficiency<br/>gamma^steps]
        RS[Stealth<br/>Did Blue detect?]
        RSE[Social Engineering<br/>NPC fell for phish/pretext]
        RH[Anti-hallucination<br/>-0.3 per fake flag]
    end

    subgraph blue [Blue Rewards]
        BD[Detection<br/>TP rate vs Red log]
        BP[Patch<br/>Golden path re-run fails]
        BA[Availability<br/>Healthcheck fraction]
        BPH[Phishing Detection<br/>social engineering caught in logs]
        BF[False Positive<br/>-0.2 per NPC flagged]
    end

    subgraph coupling [Coupling]
        RS -.-|depends on| BD
        BD -.-|depends on| RF
    end

    style red fill:#ff6b6b11,stroke:#ff6b6b
    style blue fill:#4a9eff11,stroke:#4a9eff
    style coupling fill:#ffd93d11,stroke:#ffd93d,stroke-dasharray: 5 5
```

## Validation Gate

Every candidate snapshot passes an **executable admission pipeline** before any agent touches it. The validator does not use free-form LLM prose as ground truth; it operates over the compiled `SnapshotSpec` plus rendered runtime artifacts. Mechanical checks are primary. An optional Validator LLM may review structured specs or artifacts for realism, but its feedback is secondary critique rather than ground truth.

```mermaid
flowchart LR
    S1[1. Build + boot<br/>services start and healthchecks pass] --> S2[2. Exploitability<br/>truth path or golden path works]
    S2 --> S3[3. Patchability<br/>fix or revert breaks the exploit path]
    S3 --> S4[4. Evidence sufficiency<br/>logs, files, tickets support investigation]
    S4 --> S5[5. Reward check<br/>rubrics grounded in container state]
    S5 --> S6[6. Isolation + leakage<br/>no impossible refs or answer leaks]

    S6 -->|All pass| PASS[ADMIT SNAPSHOT]
    S6 -->|Any fail| FAIL[REJECT + RETRY]

    style PASS fill:#6bcb77,color:#fff
    style FAIL fill:#ff6b6b,color:#fff
    style S3 fill:#ffd93d,color:#333
```

Inverse mutation still matters here: if reverting or patching the planted bug does not break the exploit path, the vulnerability is decorative and the snapshot should be rejected.

## Tier System

Every tier is a **complete enterprise network**. Difficulty grows by adding business units, network zones, and attack surface -- not just harder passwords.

| Tier | Hosts | Zones | Key Infrastructure | Attack Complexity |
|------|-------|-------|-------------------|-------------------|
| 1 | 6-8 | DMZ, Internal, Mgmt | Web app + DB + mail + firewall + LDAP + SIEM | Single-stage: exploit web, grab flag |
| 2 | 10-12 | + VPN, Guest | + VPN gateway, guest WiFi segment, internal APIs, certificate authority | Multi-stage: exploit + pivot one hop |
| 3 | 14-18 | + Partner, Dev | + CI/CD pipeline, container registry, partner extranet, S3-like storage | Chain 2-3 vulns across zones |
| 4 | 20-25 | + OT/SCADA, Cloud | + Industrial control sim, cloud gateway, secrets vault, service mesh | Lateral movement across trust boundaries |
| 5 | 30+ | Full enterprise | + Honeypots, deception tech, WAF, IDS/IPS, EDR, threat intel | Evade active defenses while chaining |

```mermaid
flowchart TD
    subgraph t1 [Tier 1 - Small Business]
        direction LR
        FW1[Firewall] --> W1[Web + Mail]
        W1 --> D1[DB + Files]
        D1 --> AD1[LDAP + SIEM]
    end

    subgraph t2 [Tier 2 - Mid-Market]
        direction LR
        FW2[Firewall + VPN] --> W2[Web + Mail + DNS]
        W2 --> D2[DB + APIs + Files]
        D2 --> AD2[AD + CA + SIEM]
    end

    subgraph t3 [Tier 3 - Enterprise]
        direction LR
        FW3[Firewall + WAF + IDS] --> W3[Web + Mail + DNS + CDN]
        W3 --> D3[DB + APIs + CI/CD + Registry]
        D3 --> AD3[AD + Kerberos + Vault + SIEM]
    end

    t1 -->|agent masters tier| t2
    t2 -->|agent masters tier| t3

    style t1 fill:#6bcb7722,stroke:#6bcb77
    style t2 fill:#ffd93d22,stroke:#ffd93d
    style t3 fill:#ff6b6b22,stroke:#ff6b6b
```

## Curriculum Feedback Loop

OpenRange is **self-improving**. Per-snapshot solve rates and detection rates feed back to the Builder, which adjusts the next snapshot's difficulty and vulnerability mix to target the frontier of agent capability.

```
Episode results (solve rate, detection rate, time-to-flag)
    |
    v
Curriculum tracker (per vuln class, per tier)
    |
    v
Builder receives runtime_context:
  { red_solve_rate: 0.6, blue_detect_rate: 0.4,
    previous_vuln_classes: [sqli, weak_creds],
    weak_areas: [ssrf, chained_vulns] }
    |
    v
Next snapshot targets agent weaknesses:
  - If Red solves SQLi easily → seed SSRF or chained vulns
  - If Blue misses lateral movement → add more pivot points
  - Difficulty adjusts via r_inject = 1 - (1+α)·s
```

The Builder LLM acts as a **simulated expert curriculum designer** -- it doesn't just randomize, it analyzes agent performance and generates challenges calibrated to the learning frontier. This is the same frontier-calibrating reward from Self-Play SWE-RL, adapted for cybersecurity.

## Tandem Red + Blue Training

```mermaid
sequenceDiagram
    participant Red as Red Agent
    participant Range as Enterprise Range
    participant Blue as Blue Agent

    Note over Red,Blue: Episode begins - reset() selected a frozen validated snapshot

    Red->>Range: nmap perimeter scan
    Range-->>Red: firewall: 80,443,25 open
    Note right of Range: Logged to SIEM

    Blue->>Range: check SIEM dashboard
    Range-->>Blue: NPC traffic + Red scan mixed in
    Blue->>Range: submit_finding port scan from ext IP
    Note left of Blue: True positive

    Red->>Range: enumerate web app directories
    Range-->>Red: found /admin /api /uploads
    Note right of Range: Logged to SIEM

    Red->>Range: exploit SQLi in /api/search
    Range-->>Red: DB creds leaked
    Red->>Range: pivot to internal DB with stolen creds
    Range-->>Red: connected, flag captured

    Red->>Range: submit_flag FLAG_db_compromised
    Range-->>Red: Correct, reward 1.0

    Blue->>Range: analyze SIEM for SQLi signatures
    Range-->>Blue: injection pattern in web logs
    Blue->>Range: patch /api/search, add WAF rule
    Range-->>Blue: patch applied

    Note over Range: Re-run golden path exploit
    Note over Range: Exploit FAILS, patch valid

    Note over Red,Blue: Red stealth LOW - Blue caught the attack<br/>Blue detection HIGH - found real intrusion
```

## Agents

OpenRange uses a **structural protocol** for agents -- any object with `reset(briefing, role)` and `act(observation) -> command` methods works. No base class required.

| Agent | Module | Description |
|-------|--------|-------------|
| `RangeAgent` | `agents/protocol.py` | Protocol definition (structural subtyping) |
| `LLMRangeAgent` | `agents/llm_agent.py` | LLM-powered agent via LiteLLM (any provider: Anthropic, OpenAI, Ollama, vLLM, etc.) |
| `ScriptedAgent` | `agents/scripted_agent.py` | Replays a fixed command list (for testing and demos) |
| `HumanAgent` | `agents/human_agent.py` | Interactive stdin/stdout agent for manual play |

**Bring your own agent**: implement `reset()` and `act()` and pass it to `run_episode()` or `evaluate()`.

```python
from open_range.agents.episode import run_episode
from open_range.agents.llm_agent import LLMRangeAgent
from open_range.server.environment import RangeEnvironment

env = RangeEnvironment()
red = LLMRangeAgent(model="anthropic/claude-sonnet-4-20250514")
blue = LLMRangeAgent(model="openai/gpt-4o")
result = run_episode(env, red, blue, max_steps=50)
print(result.outcome, result.metrics)
```

The `evaluate()` function in `agents/eval.py` runs N episodes and returns aggregate metrics (solve rate, detection rate, stealth, availability, false positive rate).

## Project Structure

```
open-range/
├── src/open_range/
│   ├── protocols.py        Pydantic models: SnapshotSpec, TruthGraph, Vulnerability, FlagSpec, etc.
│   ├── resolve.py          Dynamic component resolution (importlib + Protocol check)
│   ├── server/             FastAPI server (Environment, models, rewards)
│   │   ├── app.py          FastAPI app factory (OpenEnv-compatible or standalone)
│   │   ├── __main__.py     Entry point: python -m open_range.server
│   │   ├── environment.py  RangeEnvironment with reset/step/state
│   │   ├── models.py       RangeAction, RangeObservation, RangeState
│   │   └── rewards.py      Reward components (flag, stealth, detection, patch, etc.)
│   ├── builder/            Snapshot builder + renderer
│   │   ├── builder.py      LLMSnapshotBuilder, TemplateOnlyBuilder, FileBuilder
│   │   ├── renderer.py     SnapshotRenderer: Jinja2 templates -> Docker artifacts
│   │   ├── mutator.py      Vuln mutation logic (swap vulns between resets)
│   │   ├── snapshot_store.py  Snapshot storage and retrieval
│   │   ├── templates/      Jinja2 templates (docker-compose, Dockerfiles, nginx, iptables, etc.)
│   │   └── npc/            NPC traffic system
│   │       ├── npc_manager.py   NPCManager: orchestrates shell scripts + LLM agents
│   │       ├── npc_agent.py     LLMNPCAgent (Level 1), RuleBasedNPCBehavior, NullNPCBehavior
│   │       ├── persona.py       NPC persona model
│   │       └── *.sh             Level 0 traffic scripts (http, db, ssh)
│   ├── validator/          10-check admission pipeline
│   │   ├── validator.py    Pipeline orchestrator
│   │   ├── build_boot.py   Check 1: docker compose up + healthchecks
│   │   ├── exploitability.py  Check 2: golden path end-to-end
│   │   ├── patchability.py Check 3: inverse mutation test
│   │   ├── evidence.py     Check 4: logs + alerts exist
│   │   ├── reward_grounding.py  Check 5: rubrics produce valid scores
│   │   ├── isolation.py    Check 6: zones enforced, no leaks
│   │   ├── task_feasibility.py  Check 7: tasks reference real hosts/services
│   │   ├── difficulty.py   Check 8: golden path steps within tier target
│   │   ├── npc_consistency.py   Check 9: NPC persona consistency (LLM, via litellm)
│   │   └── realism_review.py    Check 10: scenario plausibility (LLM, advisory)
│   ├── agents/             Agent framework
│   │   ├── protocol.py     RangeAgent protocol + EpisodeResult + EpisodeMetrics
│   │   ├── llm_agent.py    LLMRangeAgent (litellm, any provider)
│   │   ├── scripted_agent.py  ScriptedAgent + pre-built demo scripts
│   │   ├── human_agent.py  Interactive human agent (stdin/stdout)
│   │   ├── prompts.py      Red and Blue system prompts
│   │   ├── parsing.py      Command extraction from LLM output
│   │   ├── episode.py      run_episode() orchestration loop
│   │   └── eval.py         evaluate() harness (N episodes, aggregate metrics)
│   ├── client/             Typed OpenEnv client (OpenRangeEnv)
│   └── training/           Training utilities (deferred -- env-first)
│       ├── trajectory.py   TrajectoryLogger with JSONL export for SFT
│       ├── rollout.py      Rollout function for GRPOTrainer
│       └── curriculum.py   Curriculum escalation logic
├── manifests/              YAML range definitions (tier1, tier2, tier3) + schema
├── vulns/                  Vulnerability catalog (sqli, xss, idor, ssrf, etc.)
├── examples/               Demo scripts
│   ├── demo.py             End-to-end scripted demo (no Docker, no LLM)
│   └── demo_config.yaml    Demo configuration
├── tests/                  Test suite (13 test files)
├── docs/                   Architecture docs and guides
└── pyproject.toml
```

## Trajectory Logging

The `TrajectoryLogger` records Red and Blue turns during episodes and exports them as JSONL in OpenAI chat format for supervised fine-tuning.

```python
from open_range.training.trajectory import TrajectoryLogger

logger = TrajectoryLogger()
logger.start_episode("ep-001", snapshot_id="snap-001", tier=1)
logger.log_turn(role="red", observation="Range ready...", action="nmap -sV web", reward=0.1)
logger.end_episode(outcome="flag_captured")
logger.export_jsonl("trajectories.jsonl", reward_threshold=0.5)
```

Red and Blue trajectories are written as separate JSONL lines (independent training examples). Episodes can be filtered by reward threshold.

## Running Tests

```bash
# Install dev dependencies
uv sync --all-extras

# Run all tests
uv run pytest tests/ -v --tb=short

# Run specific test files
uv run pytest tests/test_agents.py -v
uv run pytest tests/test_app.py -v
uv run pytest tests/test_validator.py -v
uv run pytest tests/test_demo.py -v
```

Test files cover: agents, app/server endpoints, builder, demo, environment, manifests, models, protocols, renderer, rewards, trajectory logging, and the validator pipeline.

## Built On

- [OpenEnv](https://github.com/meta-pytorch/OpenEnv) -- standardized agentic execution environments
- Design ideas from PAIRED / UED (generate inside a legal family), POET (mutate plus admit), [R2E-Gym](https://arxiv.org/abs/2504.07164) (executable verification), [Self-Play SWE-RL](https://arxiv.org/abs/2512.18552) (formal specs and inverse mutation testing), and [Snorkel](https://www.snorkel.ai/) (simulated domain experts for data generation)

## License

Apache 2.0
