# OpenRange

**Multi-agent cyber gymnasium with real containers, golden-path validation, and self-evolving infrastructure.**

The first cybersecurity environment in the [OpenEnv](https://github.com/meta-pytorch/OpenEnv) ecosystem.

---

## What is this?

OpenRange drops Red and Blue agents into a **real Docker network** — web apps, databases, firewalls, and all — then lets them fight. An LLM Builder generates the vulnerable infrastructure. A Validator confirms it's actually exploitable. And on every `reset()`, the Builder **mutates** the range with entirely different vulnerabilities, so agents can never memorize their way to victory.

```
You write a YAML manifest describing what you want:
  "2 hosts, DMZ network, web app with database, medium difficulty"

The Builder LLM generates it:
  Real nginx + PHP app -> Real MySQL with flags -> Real firewall rules -> Golden path

The Validator confirms it works:
  LLM review + 7 scripted checks including inverse mutation testing

Red attacks. Blue defends. Reset. New vulns. Repeat.
```

## Three Roles

| Role | What it does | Entry point |
|------|-------------|-------------|
| **Builder** | Generates and mutates vulnerable infrastructure from YAML manifests | LLM + templates |
| **Red** | Attacks live containers. Captures flags. | External -- no creds, no access |
| **Blue** | Defends via log analysis, patching, firewalling. | Internal -- monitor host |

Red and Blue operate on the **same infrastructure simultaneously**. Red's stealth reward depends on whether Blue catches them. Blue's detection reward depends on Red's actual actions in the logs.

## Architecture

```mermaid
flowchart TD
    A[YAML Manifest<br/>Human-authored topology + vuln slots] --> B[Builder LLM<br/>Generates configs, plants vulns, writes golden path]
    B --> C{Hybrid Validator}
    C -->|Phase A| D[LLM Review<br/>Exploitability, alignment, difficulty]
    C -->|Phase B| E[7-Check Scripted<br/>Services, flags, isolation,<br/>golden path, inverse mutation]
    D --> F{PASS?}
    E --> F
    F -->|Yes| G[OpenEnv Server<br/>FastAPI: /reset, /step, /state, /ws]
    F -->|No| B
    G --> H[Red Agent<br/>nmap, curl, exploit, submit_flag]
    G --> I[Blue Agent<br/>tail_log, grep, patch, iptables]
    G --> J[NPC Traffic<br/>Background noise]
    H --> K[(Docker Containers<br/>web, db, monitor)]
    I --> K
    J --> K

    style A fill:#4a9eff,color:#fff
    style B fill:#ff6b6b,color:#fff
    style C fill:#ffd93d,color:#333
    style G fill:#6bcb77,color:#fff
    style K fill:#7c73e6,color:#fff
```

## Episode Lifecycle

```mermaid
sequenceDiagram
    participant T as Training Loop
    participant E as OpenEnv Server
    participant B as Builder LLM
    participant V as Validator
    participant C as Containers
    participant R as Red Agent
    participant Bl as Blue Agent

    T->>E: reset()
    E->>B: Manifest + mutation directive
    B->>B: Generate structured JSON spec<br/>(vuln type, golden path, flags)
    B->>C: Render templates -> hot-swap configs
    C->>C: Restart affected services
    E->>V: Validate range
    V->>V: Phase A: LLM review
    V->>C: Phase B: 7 scripted checks
    V-->>E: PASS
    E-->>T: RangeObservation (challenge description)

    loop Episode Steps (alternating)
        T->>E: step(Red: nmap -sV web)
        E->>C: docker exec attacker nmap -sV web
        C-->>E: stdout: 80/tcp open http
        E-->>T: RangeObservation(stdout, reward)

        T->>E: step(Blue: tail_log access.log)
        E->>C: docker exec monitor tail access.log
        C-->>E: log entries (Red + NPC mixed)
        E-->>T: RangeObservation(stdout, reward)
    end

    Note over R,Bl: Red stealth reward coupled to Blue detection<br/>Blue detection reward coupled to Red actions
```

## Reset = Mutation

Every call to `reset()` triggers a **mutation** -- the Builder LLM swaps vulnerability classes in the running containers. The topology stays the same, but the challenge is completely different.

```mermaid
flowchart LR
    subgraph Episode 1
        A1[SQLi in search form] --> F1[Flag in DB]
    end
    subgraph Episode 2
        A2[Command injection<br/>in ping utility] --> F2[Flag on disk]
    end
    subgraph Episode 3
        A3[SSRF -> internal SQLi] --> F3[Flag in internal DB]
    end

    Episode 1 -->|reset| Episode 2
    Episode 2 -->|reset| Episode 3

    style Episode 1 fill:#ff6b6b22,stroke:#ff6b6b
    style Episode 2 fill:#ffd93d22,stroke:#ffd93d
    style Episode 3 fill:#6bcb7722,stroke:#6bcb77
```

Agents must **generalize** across vulnerability classes, not memorize exploit chains.

## Quick Start

```bash
# Install
git clone https://github.com/[team]/open-range.git
cd open-range
uv sync --all-extras

# Run the OpenEnv server locally
uv run uvicorn server.app:app --host 0.0.0.0 --port 8000

# Connect a client
python -c "
from client import OpenRangeEnv
from server.models import RangeAction

with OpenRangeEnv('http://localhost:8000').sync() as env:
    result = env.reset()
    print(result.observation.stdout)

    result = env.step(RangeAction(command='nmap -sV web', mode='red'))
    print(result.observation.stdout)
"
```

## Reward Signals

All rewards are **verifiable** -- grounded in real container state, not LLM judgment.

```mermaid
flowchart TB
    subgraph Red Rewards
        RF[Flag Capture<br/>docker exec cat flag<br/>binary match]
        RE[Efficiency<br/>gamma^steps]
        RS[Stealth<br/>Did Blue detect?]
        RH[Anti-hallucination<br/>-0.3 per fake flag]
    end

    subgraph Blue Rewards
        BD[Detection<br/>TP rate vs Red's log]
        BP[Patch<br/>Golden path re-run fails]
        BA[Availability<br/>Healthcheck fraction]
        BF[False Positive<br/>-0.2 per NPC flagged]
    end

    subgraph Coupling
        RS -.-|depends on| BD
        BD -.-|depends on| RF
    end

    style Red Rewards fill:#ff6b6b11,stroke:#ff6b6b
    style Blue Rewards fill:#4a9eff11,stroke:#4a9eff
    style Coupling fill:#ffd93d11,stroke:#ffd93d,stroke-dasharray: 5 5
```

## Golden Path Validation

Every generated range passes a **7-check validation pipeline** before any agent touches it:

```mermaid
flowchart LR
    S1[1. Services up<br/>nc -z ports] --> S2[2. Flags exist<br/>docker exec cat]
    S2 --> S3[3. Network isolation<br/>external !-> internal]
    S3 --> S4[4. Golden path<br/>execute exploit steps]
    S4 --> S5[5. Difficulty<br/>steps within 20%]
    S5 --> S6[6. No leaks<br/>grep description]
    S6 --> S7[7. Inverse mutation<br/>revert vuln -> step fails]

    S7 -->|All pass| PASS[VALID]
    S7 -->|Any fail| FAIL[RETRY<br/>Builder gets error context]

    style PASS fill:#6bcb77,color:#fff
    style FAIL fill:#ff6b6b,color:#fff
    style S7 fill:#ffd93d,color:#333
```

Check 7 is from [Self-Play SWE-RL](https://arxiv.org/abs/2512.18552): it proves each planted vulnerability actually contributes to the challenge.

## Tier System

Difficulty grows **horizontally** -- more hosts, more networks, more services. Not just harder passwords.

```mermaid
flowchart TD
    subgraph Tier 1 - Basic
        W1[web<br/>nginx + PHP] --> D1[db<br/>MySQL]
    end

    subgraph Tier 2 - Corporate
        W2[web] --> D2[db]
        W2 --> M2[mail<br/>SMTP]
        FW2[firewall<br/>iptables] --> W2
    end

    subgraph Tier 3 - Enterprise
        W3[web] --> D3[db]
        W3 --> DC3[DC<br/>LDAP/Kerberos]
        FS3[files<br/>SMB] --> DC3
    end

    style Tier 1 - Basic fill:#6bcb7722,stroke:#6bcb77
    style Tier 2 - Corporate fill:#ffd93d22,stroke:#ffd93d
    style Tier 3 - Enterprise fill:#ff6b6b22,stroke:#ff6b6b
```

| Tier | Hosts | Networks | Services | Golden Steps |
|------|-------|----------|----------|--------------|
| 1 | web + db | dmz | nginx, mysql, sshd | ~8 |
| 2 | + mail + fw | + internal | + smtp, iptables | ~15 |
| 3 | + files + DC | + mgmt | + smb, ldap, kerberos | ~25 |
| 4 | + jump + NPC | all | + bastion, cron, rsync | ~35 |
| 5 | + honeypot | + trap | + decoys, WAF, IDS | ~50 |

## Tandem Red + Blue Training

```mermaid
sequenceDiagram
    participant Red as Red Agent<br/>(attacker)
    participant Env as Range<br/>(containers)
    participant Blue as Blue Agent<br/>(defender)

    Note over Red,Blue: Episode begins -- Builder mutated range

    Red->>Env: nmap -sV web
    Env-->>Red: 80/tcp open http nginx
    Note right of Env: Action logged

    Blue->>Env: tail_log access.log
    Env-->>Blue: [NPC traffic + Red's scan mixed]
    Blue->>Env: submit_finding: port scan detected
    Note left of Blue: True positive!

    Red->>Env: curl 'web/search?q=' OR 1=1--
    Env-->>Red: Database results + flag
    Note right of Env: Action logged

    Red->>Env: submit_flag FLAG{abc123}
    Env-->>Red: Correct! reward=1.0

    Blue->>Env: grep_log "UNION|SELECT|OR 1"
    Env-->>Blue: SQLi pattern found
    Blue->>Env: patch search.php (parameterize query)
    Env-->>Blue: Patch applied

    Note over Env: Re-run golden path exploit
    Note over Env: Exploit FAILS -> patch valid

    Note over Red,Blue: Red stealth: LOW (Blue caught it)<br/>Blue detection: HIGH (found real attack)
```

## Project Structure

```
open-range/
├── manifests/          YAML range definitions (topology, vulns, golden paths)
├── vulns/              Vulnerability catalog (plantable vuln templates)
├── builder/            Builder LLM + Mutator + rendering templates
├── validator/          Hybrid validator (LLM review + 7-check scripted)
├── server/             OpenEnv server (Environment, models, rewards, app.py)
├── client/             Typed OpenEnv client
├── docs/               Architecture docs and guides
├── examples/           Demo scripts
└── tests/              Test suite
```

## Built On

- [OpenEnv](https://github.com/meta-pytorch/OpenEnv) -- standardized agentic execution environments
- Lessons from [R2E-Gym](https://arxiv.org/abs/2504.07164) (hybrid verification) and [Self-Play SWE-RL](https://arxiv.org/abs/2512.18552) (formal specs, inverse mutation testing, frontier-calibrating rewards)

## License

Apache 2.0
