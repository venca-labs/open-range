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

# Run the OpenEnv server locally
uv run uvicorn server.app:app --host 0.0.0.0 --port 8000

# Connect a client
python -c "
from client import OpenRangeEnv
from server.models import RangeAction

with OpenRangeEnv('http://localhost:8000').sync() as env:
    result = env.reset()
    print(result.observation.stdout)

    result = env.step(RangeAction(command='nmap -sV 10.0.1.0/24', mode='red'))
    print(result.observation.stdout)
"
```

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

## Project Structure

```
open-range/
├── manifests/          YAML enterprise range definitions
├── vulns/              Vulnerability catalog (plantable vuln templates)
├── builder/            Manifest compiler, mutator, templates, optional artifact generation
├── validator/          Mechanical admission checks + optional realism review
├── server/             OpenEnv server (Environment, models, rewards, snapshot runtime)
├── client/             Typed OpenEnv client
├── docs/               Architecture docs and guides
├── examples/           Demo scripts
└── tests/              Test suite
```

## Built On

- [OpenEnv](https://github.com/meta-pytorch/OpenEnv) -- standardized agentic execution environments
- Design ideas from PAIRED / UED (generate inside a legal family), POET (mutate plus admit), [R2E-Gym](https://arxiv.org/abs/2504.07164) (executable verification), [Self-Play SWE-RL](https://arxiv.org/abs/2512.18552) (formal specs and inverse mutation testing), and [Snorkel](https://www.snorkel.ai/) (simulated domain experts for data generation)

## License

Apache 2.0
