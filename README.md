# OpenRange

**Multi-agent cyber gymnasium with real enterprise networks, golden-path validation, and self-evolving infrastructure.**

The first cybersecurity environment in the [OpenEnv](https://github.com/meta-pytorch/OpenEnv) ecosystem.

---

## What is this?

OpenRange drops Red and Blue agents into a **real enterprise network** -- firewalls, web apps, databases, directory services, mail servers, VPNs, SIEM -- then lets them fight. An LLM Builder generates the vulnerable infrastructure. A Validator confirms it's actually exploitable. And on every `reset()`, the Builder **mutates** the range with entirely different vulnerabilities, so agents can never memorize their way to victory.

```
You write a YAML manifest describing what you want:
  "Corporate network: DMZ with web app + mail, internal DB + file server,
   firewall between zones, AD for auth, SIEM for monitoring"

The Builder LLM generates it:
  Real nginx reverse proxy -> PHP app -> MySQL backend -> LDAP auth
  Postfix mail -> iptables firewall rules -> Rsyslog to SIEM
  Golden path: 12 steps from external recon to domain flag

The Validator confirms it works:
  LLM review + 7 scripted checks including inverse mutation testing

Red attacks from outside. Blue defends from inside. Reset. New vulns. Repeat.
```

## Three Roles

| Role | What it does | Entry point |
|------|-------------|-------------|
| **Builder** | Generates and mutates vulnerable enterprise infrastructure from YAML manifests | LLM + templates |
| **Red** | External attacker. Recon, exploit, pivot, escalate, exfiltrate. | Outside the firewall -- no creds, no access |
| **Blue** | Internal defender. SIEM analysis, patching, firewall rules, incident response. | SOC workstation on management network |

Red and Blue operate on the **same infrastructure simultaneously**. Red's stealth reward depends on whether Blue catches them. Blue's detection reward depends on Red's actual actions in the logs.

## Architecture

```mermaid
flowchart TD
    A[YAML Manifest<br/>Enterprise topology + vuln slots] --> B[Builder LLM<br/>Generates configs, plants vulns, writes golden path]
    B --> C{Hybrid Validator}
    C -->|Phase A| D[LLM Review<br/>Exploitability, alignment, difficulty]
    C -->|Phase B| E[7-Check Scripted<br/>Services, flags, isolation,<br/>golden path, inverse mutation]
    D --> F{PASS?}
    E --> F
    F -->|Yes| G[OpenEnv Server<br/>FastAPI: /reset, /step, /state, /ws]
    F -->|No| B
    G --> H[Red Agent<br/>External attacker]
    G --> I[Blue Agent<br/>SOC defender]
    G --> J[NPC Traffic<br/>Employees, services, cron]
    H --> K[(Enterprise Range<br/>10+ containers across 4 network zones)]
    I --> K
    J --> K

    style A fill:#4a9eff,color:#fff
    style B fill:#ff6b6b,color:#fff
    style C fill:#ffd93d,color:#333
    style G fill:#6bcb77,color:#fff
    style K fill:#7c73e6,color:#fff
```

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

## Episode Lifecycle

```mermaid
sequenceDiagram
    participant T as Training Loop
    participant E as OpenEnv Server
    participant B as Builder LLM
    participant V as Validator
    participant C as Enterprise Range

    T->>E: reset()
    E->>B: Manifest + mutation directive
    B->>B: Generate structured JSON spec
    B->>C: Render templates, hot-swap configs
    C->>C: Restart affected services
    E->>V: Validate range
    V->>V: Phase A: LLM review
    V->>C: Phase B: 7 scripted checks
    V-->>E: PASS
    E-->>T: RangeObservation with challenge briefing

    rect rgb(255, 107, 107, 0.1)
        Note over T,C: Red Team Operations
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
        Note over T,C: Blue Team Operations
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

    Note over T,C: Rewards computed with coupling
```

## Reset = Mutation

Every call to `reset()` triggers a **mutation** -- the Builder LLM swaps vulnerability classes across the entire enterprise. The topology stays the same, but the attack surface is completely different.

```mermaid
flowchart LR
    subgraph ep1 [Episode 1]
        direction TB
        A1[SQLi in web search] --> B1[Pivot to internal DB]
        B1 --> C1[Exfil flag from DB]
    end
    subgraph ep2 [Episode 2]
        direction TB
        A2[SSRF in web API] --> B2[Access internal file server]
        B2 --> C2[Read flag from SMB share]
    end
    subgraph ep3 [Episode 3]
        direction TB
        A3[Phish creds via mail] --> B3[LDAP priv escalation]
        B3 --> C3[Domain admin, flag in AD]
    end

    ep1 -->|reset| ep2
    ep2 -->|reset| ep3

    style ep1 fill:#ff6b6b22,stroke:#ff6b6b
    style ep2 fill:#ffd93d22,stroke:#ffd93d
    style ep3 fill:#6bcb7722,stroke:#6bcb77
```

Agents must **generalize** across vulnerability classes, attack vectors, and pivot chains -- not memorize a single exploit.

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

All rewards are **verifiable** -- grounded in real container state, not LLM judgment.

```mermaid
flowchart TB
    subgraph red [Red Rewards]
        RF[Flag Capture<br/>docker exec cat flag<br/>binary match]
        RE[Efficiency<br/>gamma^steps]
        RS[Stealth<br/>Did Blue detect?]
        RH[Anti-hallucination<br/>-0.3 per fake flag]
    end

    subgraph blue [Blue Rewards]
        BD[Detection<br/>TP rate vs Red log]
        BP[Patch<br/>Golden path re-run fails]
        BA[Availability<br/>Healthcheck fraction]
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

## Golden Path Validation

Every generated range passes a **7-check validation pipeline** before any agent touches it:

```mermaid
flowchart LR
    S1[1. Services up<br/>nc -z ports] --> S2[2. Flags exist<br/>docker exec cat]
    S2 --> S3[3. Network isolation<br/>zones enforced]
    S3 --> S4[4. Golden path<br/>full exploit chain works]
    S4 --> S5[5. Difficulty<br/>steps within 20%]
    S5 --> S6[6. No leaks<br/>grep description]
    S6 --> S7[7. Inverse mutation<br/>revert vuln, step fails]

    S7 -->|All pass| PASS[VALID]
    S7 -->|Any fail| FAIL[RETRY<br/>Builder gets error context]

    style PASS fill:#6bcb77,color:#fff
    style FAIL fill:#ff6b6b,color:#fff
    style S7 fill:#ffd93d,color:#333
```

Check 7 is from [Self-Play SWE-RL](https://arxiv.org/abs/2512.18552): it proves each planted vulnerability actually contributes to the challenge.

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

## Tandem Red + Blue Training

```mermaid
sequenceDiagram
    participant Red as Red Agent
    participant Range as Enterprise Range
    participant Blue as Blue Agent

    Note over Red,Blue: Episode begins - Builder mutated range

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
