# Architecture

## System Overview

OpenRange is a 5-layer system. Data flows top-to-bottom during setup, loops during episodes, and feeds back up during curriculum escalation.

```
┌─────────────────────────────────────────────────┐
│                 YAML MANIFEST                   │
│  Topology, vuln slots, golden path, difficulty  │
│              (human-authored)                   │
└──────────────────────┬──────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────┐
│              BUILDER LLM                        │
│  Structured JSON spec → template rendering →    │
│  Dockerfiles, configs, vulnerable app code,     │
│  flag placement, golden path, NPC scripts       │
│  Called on every reset() to MUTATE the range    │
└──────────────────────┬──────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────┐
│           HYBRID VALIDATOR                      │
│  Phase A: LLM reviews exploitability,           │
│           alignment, difficulty                 │
│  Phase B: 7-check scripted execution            │
│           (services, flags, isolation,          │
│            golden path, difficulty,             │
│            leak check, inverse mutation)        │
│  PASS → proceed    FAIL → Builder retries       │
└──────────────────────┬──────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────┐
│           OPENENV SERVER                        │
│                                                 │
│  FastAPI: /reset, /step, /state, /ws            │
│                                                 │
│  RangeAction(command, mode) ──────────────────┐ │
│  RangeObservation(stdout, stderr, reward) ◄───┘ │
│                                                 │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐      │
│  │   RED    │  │   BLUE   │  │   NPC    │      │
│  │ External │  │ Monitor  │  │ Traffic  │      │
│  │ attacker │  │ defender │  │ noise    │      │
│  └──────────┘  └──────────┘  └──────────┘      │
└──────────────────────┬──────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────┐
│         DOCKER CONTAINERS (range)               │
│                                                 │
│  ┌────────┐    ┌────────┐    ┌────────┐         │
│  │  web   │───▶│   db   │    │monitor │         │
│  │nginx+  │    │ mysql  │    │ logs   │         │
│  │PHP app │    │ flags  │    │ Blue   │         │
│  └────────┘    └────────┘    └────────┘         │
│       DMZ          Internal       Mgmt          │
└─────────────────────────────────────────────────┘
```

## Data Flow

### Setup (once)
1. Human writes YAML manifest defining topology + vuln slots
2. Builder LLM generates initial infrastructure
3. `docker compose up` starts all containers
4. Validator confirms range is exploitable and correctly configured

### Episode Loop
1. `reset()` → Builder LLM mutates vulns (new class, new flag, new golden path)
2. Hot-swap configs into running containers, restart affected services
3. Validator confirms mutation is valid (LLM + 7 scripted checks)
4. Red and Blue agents interact via `step(RangeAction)`:
   - Red: executes commands against containers (nmap, curl, ssh, submit_flag)
   - Blue: reads logs, patches vulns, blocks IPs (tail_log, iptables, patch, submit_finding)
5. Environment computes rewards from verifiable container state
6. Episode ends when: flag captured, max steps, timeout, or all vulns patched

### Curriculum (optional, post-training)
1. Track Red solve rate and Blue detection rate
2. Builder LLM adjusts difficulty via `r_inject = 1 - (1+alpha)*s`
3. When agents plateau: horizontal growth (add hosts, networks, services)

## Builder LLM Output Format

The Builder produces **structured JSON**, not prose (lesson from Self-Play SWE-RL):

```json
{
  "vulns": [
    {
      "type": "sqli",
      "host": "web",
      "injection_point": "/search?q=",
      "vulnerable_code": "<?php $q=$_GET['q']; $r=mysql_query(\"SELECT * FROM products WHERE name LIKE '%$q%'\"); ?>",
      "flag_location": "/var/flags/flag1.txt"
    }
  ],
  "flags": [
    {"id": "flag1", "value": "FLAG{r4nd0m_v4lu3}", "path": "/var/flags/flag1.txt", "host": "web"}
  ],
  "golden_path": [
    {"step": 1, "cmd": "nmap -sV web", "expect_stdout": "80/tcp open http"},
    {"step": 2, "cmd": "curl http://web/", "expect_stdout": "search"},
    {"step": 3, "cmd": "curl 'http://web/search?q=test' UNION SELECT flag FROM flags--'", "expect_stdout": "FLAG{"},
    {"step": 4, "cmd": "submit_flag FLAG{r4nd0m_v4lu3}", "expect_stdout": "correct"}
  ],
  "challenge_description": "Target network has a web application with a database backend. Find and exploit vulnerabilities to capture the flag."
}
```

A thin template layer renders this JSON into actual config files (PHP, nginx.conf, init.sql).

## Hybrid Validation Pipeline

Two phases, both must pass:

**Phase A: LLM Review** (fast, catches design-level bugs)
- Is the vulnerability actually exploitable given these configs?
- Does the challenge description match without leaking the answer?
- Is the golden path correct for this vuln type?
- Is the difficulty right for the current tier?

**Phase B: 7-Check Scripted Execution** (ground truth, catches implementation bugs)
1. Services respond on expected ports
2. Flags exist at expected paths with correct values
3. Network isolation holds (external can't reach internal)
4. Golden path commands produce expected outputs
5. Step count within 20% of difficulty target
6. Challenge description contains no flag values or exploit details
7. Inverse mutation test: reverting each vuln breaks its golden path step

## Reward Architecture

All rewards implemented as OpenEnv `Rubric` subclasses:

```
CompositeRedReward (WeightedSum)
  ├── FlagReward          binary, docker exec verified
  ├── EfficiencyReward    gamma^steps
  ├── StealthReward       coupled to Blue's detection history
  ├── EvidenceReward      quality of submit_evidence
  └── HallucinationPenalty  -0.3 per fake flag

CompositeBlueReward (WeightedSum)
  ├── DetectionReward     TP rate vs Red's action log
  ├── PatchReward         binary, golden path re-execution
  ├── AvailabilityReward  healthcheck fraction
  └── FalsePositiveReward -0.2 per NPC traffic flagged
```

Rewards are computed from **container state and action logs**, never from LLM judgment.
