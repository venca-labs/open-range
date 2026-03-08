# Builder + Validator Design

## Overview

**LLM generates, renderer materializes, rules validate.** The builder uses LiteLLM to generate candidate snapshot specs as structured JSON. The renderer turns specs into Docker artifacts via Jinja2 templates. The validator runs a 10-check admission pipeline (8 mechanical + 2 LLM advisory) before admitting a snapshot.

Snapshot creation happens **inside a shared `ManagedSnapshotRuntime` in the server process**. That runtime preloads admitted snapshots at startup, renders each admitted `SnapshotSpec` into Docker artifacts under `snapshots/<id>/artifacts`, and can optionally refill the pool between episodes. `reset()` picks a pre-validated frozen snapshot from the `SnapshotStore`. No LLM calls in the hot path.

```mermaid
flowchart LR
    MF[Manifest<br/>legal family] --> BLD[Builder LLM<br/>via LiteLLM]
    CURR[Curriculum stats<br/>solve rates, weaknesses] --> BLD
    BLD --> SPEC[Candidate SnapshotSpec<br/>topology, truth graph,<br/>evidence, tasks]
    SPEC --> RND[SnapshotRenderer<br/>Jinja2 templates]
    RND --> ART[Docker artifacts<br/>compose, Dockerfiles,<br/>nginx, init.sql, iptables]
    ART --> VAL{Validator gate<br/>8 mechanical +<br/>2 LLM advisory}
    VAL -->|pass| STORE[SnapshotStore<br/>frozen, ready for reset]
    VAL -->|fail| BLD

    style BLD fill:#ff6b6b,color:#fff
    style RND fill:#4ecdc4,color:#fff
    style VAL fill:#ffd93d,color:#333
    style STORE fill:#6bcb77,color:#fff
```

## Builder (LLM via LiteLLM)

Three builder implementations share the same `SnapshotBuilder` protocol (`async def build(manifest, context) -> SnapshotSpec`):

| Class | Use case | LLM? |
|-------|----------|------|
| `LLMSnapshotBuilder` | Production -- generates specs via LiteLLM | Yes |
| `TemplateOnlyBuilder` | Testing -- deterministic, picks from hardcoded vuln pool by seed | No |
| `FileBuilder` | Demos -- loads a pre-built snapshot JSON from disk | No |

All three live in `src/open_range/builder/builder.py`.

The `LLMSnapshotBuilder` generates complete enterprise snapshots from YAML manifests. It runs asynchronously, producing a queue of validated snapshots that `reset()` draws from.

### Input

```yaml
# Manifest defines the legal company family
name: acme_corp
tier: 1

topology:
  hosts:
    - name: web
      zone: dmz
      services: [nginx, php, sshd]
      connects_to: [db, ldap]
    - name: mail
      zone: dmz
      services: [postfix, dovecot]
      connects_to: [ldap]
    - name: db
      zone: internal
      services: [mysql]
      connects_to: [ldap]
    - name: files
      zone: internal
      services: [samba]
      connects_to: [ldap]
    - name: ldap
      zone: management
      services: [slapd, krb5]
    - name: siem
      zone: management
      services: [rsyslog, elasticsearch]
      receives_logs_from: [web, mail, db, files, ldap, firewall]
    - name: firewall
      zone: perimeter
      services: [iptables]
    - name: attacker
      zone: external
      services: [kali-tools]
  networks:
    - name: external
    - name: dmz
      cidr: 10.0.1.0/24
    - name: internal
      cidr: 10.0.2.0/24
    - name: management
      cidr: 10.0.3.0/24
  firewall_rules:
    - allow: {from: external, to: dmz, ports: [80, 443, 25]}
    - allow: {from: dmz, to: internal, ports: [3306, 445]}
    - allow: {from: dmz, to: management, ports: [389, 636]}
    - allow: {from: internal, to: management, ports: [389]}
    - deny: {from: internal, to: external}
    - deny: {from: management, to: external}

bug_families: [sqli, xss, idor, path_traversal, command_injection, ssrf, weak_creds, broken_auth]
task_families: [exploit, investigate, patch, report]

difficulty:
  max_steps: 12
  min_vulns: 1
  max_vulns: 3

# Injected at runtime
runtime_context:
  previous_vuln_classes: [sqli, weak_creds]
  red_solve_rate: 0.6
  blue_detect_rate: 0.4
```

### Output (Candidate Snapshot)

The Builder outputs a structured JSON snapshot spec. The LLM does the creative work (designing realistic vulnerabilities, generating vulnerable code, constructing exploit chains). Templates handle mechanical file rendering.

```json
{
  "snapshot_id": "acme_v14",
  "topology": {
    "hosts": ["attacker", "firewall", "web", "mail", "db", "files", "ldap", "siem"],
    "zones": {"external": ["attacker"], "dmz": ["web", "mail"], "internal": ["db", "files"], "management": ["ldap", "siem"]},
    "users": [
      {"username": "admin", "password": "Adm1n!2024", "groups": ["admins"], "hosts": ["web", "db"]},
      {"username": "jsmith", "password": "Welcome1", "groups": ["users"], "hosts": ["web", "mail", "files"]},
      {"username": "svc_backup", "password": "backup123", "groups": ["service"], "hosts": ["db", "files"]}
    ]
  },
  "truth_graph": {
    "vulns": [
      {
        "id": "vuln1",
        "type": "idor",
        "host": "web",
        "service": "nginx+php",
        "injection_point": "/api/users/{id}/profile",
        "vulnerable_code": "<?php $id=$_GET['id']; $stmt=$conn->query(\"SELECT * FROM users WHERE id=$id\"); ?>",
        "root_cause": "No authorization check on user ID parameter",
        "blast_radius": ["user data exposure", "credential leakage"],
        "remediation": "Add session-based authorization check before query"
      },
      {
        "id": "vuln2",
        "type": "weak_creds",
        "host": "db",
        "service": "mysql",
        "injection_point": "mysql -u svc_backup -pbackup123",
        "root_cause": "Service account with weak password and excessive privileges",
        "blast_radius": ["full database access", "flag exfiltration"],
        "remediation": "Rotate password, restrict to backup-only permissions"
      }
    ],
    "exploit_chain": [
      {"step": 1, "action": "Enumerate web app via IDOR", "vuln": "vuln1", "yields": "svc_backup credentials"},
      {"step": 2, "action": "Pivot to DB with stolen creds", "vuln": "vuln2", "yields": "flag from secrets table"}
    ]
  },
  "flags": [
    {"id": "flag1", "value": "FLAG{1d0r_ch41n_2_db}", "path": "db:flags.secrets.flag", "host": "db"}
  ],
  "golden_path": [
    {"step": 1, "cmd": "nmap -sV 10.0.1.0/24", "expect_stdout": "80/tcp open http", "host": "attacker"},
    {"step": 2, "cmd": "curl http://web/api/users/1/profile", "expect_stdout": "admin", "host": "attacker"},
    {"step": 3, "cmd": "curl http://web/api/users/3/profile", "expect_stdout": "svc_backup", "host": "attacker"},
    {"step": 4, "cmd": "mysql -h db -u svc_backup -pbackup123 -e 'SELECT flag FROM flags.secrets'", "expect_stdout": "FLAG{1d0r_ch41n_2_db}", "host": "attacker"},
    {"step": 5, "cmd": "submit_flag FLAG{1d0r_ch41n_2_db}", "expect_stdout": "correct", "host": "attacker"}
  ],
  "evidence_spec": {
    "web_access_log": "IDOR requests show sequential user ID enumeration from attacker IP",
    "db_query_log": "Unexpected SELECT on flags.secrets from svc_backup account",
    "siem_alerts": ["Suspicious user enumeration pattern", "Service account accessing sensitive table"]
  },
  "npc_traffic": {
    "http_rate": 30,
    "smtp_rate": 5,
    "ldap_rate": 10,
    "smb_rate": 8
  },
  "npc_personas": [
    {
      "id": "npc_jsmith",
      "name": "Janet Smith",
      "role": "Marketing Coordinator",
      "department": "Marketing",
      "reports_to": "npc_director_marketing",
      "communication_style": "casual, responds quickly, uses exclamation marks",
      "security_awareness": 0.3,
      "susceptibility": {
        "phishing_email": 0.7,
        "credential_sharing": 0.4,
        "attachment_opening": 0.8,
        "vishing": 0.6
      },
      "relationships": ["trusts IT helpdesk", "friends with npc_bob in accounting"],
      "routine": {
        "email_check_interval_min": 15,
        "typical_actions": ["browse intranet", "send marketing reports", "LDAP lookups"]
      },
      "accounts": {"email": "jsmith@acmecorp.local", "ldap": "jsmith", "smb_shares": ["marketing", "shared"]}
    },
    {
      "id": "npc_ciso",
      "name": "David Chen",
      "role": "CISO",
      "department": "Security",
      "communication_style": "formal, suspicious of unusual requests, always verifies sender",
      "security_awareness": 0.95,
      "susceptibility": {
        "phishing_email": 0.05,
        "credential_sharing": 0.01,
        "attachment_opening": 0.1,
        "vishing": 0.05
      },
      "relationships": ["reports to CEO", "manages SOC team"],
      "routine": {
        "email_check_interval_min": 5,
        "typical_actions": ["review SIEM alerts", "approve access requests", "policy updates"]
      },
      "accounts": {"email": "dchen@acmecorp.local", "ldap": "dchen", "smb_shares": ["security", "executive"]}
    }
  ],
  "task": {
    "red_briefing": "A corporate network with web services and backend infrastructure. Investigate the environment and capture the flags.",
    "blue_briefing": "You are the SOC analyst for AcmeCorp. Monitor the SIEM for suspicious activity, investigate alerts, and respond to threats."
  }
}
```

### LiteLLM Integration

`LLMSnapshotBuilder.__init__` accepts `model`, `prompt_template`, `temperature`, and `max_retries` (default 3). On failure, it retries with the error context appended as an extra user message.

```python
# Simplified -- see builder.py for full retry + error-feedback logic
response = await litellm.acompletion(
    model=self.model,   # default: "anthropic/claude-sonnet-4-20250514"
    messages=[
        {"role": "system", "content": self.prompt_template},
        {"role": "user", "content": json.dumps({
            "manifest": manifest,
            "runtime_context": context.model_dump(),
        }, indent=2)},
    ],
    response_format={"type": "json_object"},
    temperature=self.temperature,   # default: 0.7
)
spec = _parse_llm_response(response.choices[0].message.content)
```

The internal `_parse_llm_response()` function handles schema differences between the LLM's raw JSON output and the `SnapshotSpec` Pydantic model (e.g. `expect_stdout` -> `expect_in_stdout`, dict-shaped `evidence_spec` -> `list[EvidenceItem]`).

Configure via environment:
- `OPENRANGE_BUILDER_MODEL` -- any LiteLLM-supported model string
- Model-specific keys: `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `OLLAMA_API_BASE`, etc.

### SnapshotRenderer (Template Layer)

The `SnapshotRenderer` (`src/open_range/builder/renderer.py`) takes a validated `SnapshotSpec` and renders Jinja2 templates into Docker artifacts. This separates the LLM's creative work (designing vulnerabilities, code, exploit chains) from mechanical file rendering.

```python
renderer = SnapshotRenderer()           # uses built-in template dir
output_dir = renderer.render(spec, Path("./output"))
```

`SnapshotRenderer.render(spec, output_dir)` iterates over the template map, builds a context dict from the `SnapshotSpec` (topology, zones, users, flags, vuln types, firewall rules), and writes each rendered file to `output_dir`.

| Template | Renders from | Output |
|----------|-------------|--------|
| `docker-compose.yml.j2` | topology (hosts, zones, networks, users) | Compose file with networks and services |
| `Dockerfile.web.j2` | users, app_files, flags | nginx + PHP app container |
| `Dockerfile.db.j2` | db_user, db_pass, mysql_root_password | MySQL with schema |
| `nginx.conf.j2` | vuln injection points (search/download endpoints auto-detected from vuln types) | Web server config |
| `init.sql.j2` | users, flags | Database initialization |
| `iptables.rules.j2` | firewall_rules, zone_cidrs | Firewall rule set |

The renderer auto-detects which nginx endpoint blocks to enable by inspecting vuln types and injection points (e.g. `sqli` or `q=` in injection points enables the search endpoint; `path_traversal` or `file=` enables the download endpoint).

### Mutator

The `Mutator` (`src/open_range/builder/mutator.py`) wraps any `SnapshotBuilder` and adds mutation-specific context: ensuring vuln diversity, targeting weak areas, and feeding back error context from failed validations.

```python
mutator = Mutator(builder=LLMSnapshotBuilder(), max_retries=3)
snapshot = await mutator.mutate(manifest, context=build_context, error=prev_error)
```

It tracks episode history internally:
- `previous_vuln_classes` (last 3) -- injected into `BuildContext` so the builder avoids repeats
- `recent_attack_surfaces` (last 5) -- injected so the builder varies injection points
- `episode_count` -- monotonically increasing

On each `mutate()` call, these are populated into the `BuildContext` before delegating to the underlying builder's `build()` method. If an `error` dict is provided (from a failed validation), it is attached to the context so the builder can correct the issue.

### SnapshotStore

The `SnapshotStore` (`src/open_range/builder/snapshot_store.py`) persists validated snapshots as frozen JSON under `snapshots/<id>/spec.json` with a `metadata.json` sidecar for fast listing.

| Method | Description |
|--------|-------------|
| `async store(snapshot, snapshot_id=None) -> str` | Save a validated snapshot. Auto-generates ID from vuln types + timestamp if not provided. Writes `spec.json` + `metadata.json`. |
| `async select(strategy="latest") -> SnapshotSpec` | Select a snapshot. Strategies: `"latest"` (most recent by mtime), `"random"` (uniform). |
| `async list_snapshots() -> list[dict]` | List all snapshots with metadata (vuln classes, golden path steps, flag count, NPC count, stored_at). Sorted by `stored_at` descending. |
| `async get(snapshot_id) -> SnapshotSpec` | Load a specific snapshot by ID. Raises `FileNotFoundError` if missing. |

```python
store = SnapshotStore(store_dir="snapshots")
sid = await store.store(validated_snapshot)          # -> "snap_sqli_idor_1741234567"
snap = await store.select(strategy="random")         # -> SnapshotSpec
all_meta = await store.list_snapshots()              # -> [{"snapshot_id": ..., ...}, ...]
snap = await store.get("snap_sqli_idor_1741234567")  # -> SnapshotSpec
```

### Prompts

System prompts live in `src/open_range/builder/prompts.py`:

| Constant | Used by | Purpose |
|----------|---------|---------|
| `BUILDER_SYSTEM_PROMPT` | `LLMSnapshotBuilder` | Instructs the LLM to generate structured JSON snapshot specs from manifests. Includes output schema, 10 rules (topology fidelity, vuln diversity, auth realism, golden path calibration, no flag leaks, etc.), and a worked example. |
| `REALISM_REVIEW_PROMPT` | `RealismReviewCheck` | Instructs the validator LLM to check for briefing leakage, scenario plausibility, difficulty match, and narrative coherence. Returns `{pass, issues}`. |

## Validator Gate (8 Mechanical + 2 LLM Advisory)

The `ValidatorGate` (`src/open_range/validator/validator.py`) is a **configurable pipeline of `ValidatorCheck` instances** run in sequence. Checks 1-8 are mechanical -- executable scripts against live containers, deterministic pass/fail. Checks 9-10 are LLM-based advisory checks -- they can trigger retry but never block admission on their own.

The gate uses **fail-fast** semantics: the first mechanical (non-advisory) failure stops the pipeline. Advisory checks (determined by membership in `_ADVISORY_CHECK_CLASSES = {"NPCConsistencyCheck", "RealismReviewCheck"}`) are always recorded but never prevent an overall pass.

R2E-Gym found execution-only validation plateaus at ~43% and LLM-only at ~43%. Combined: 51%. Both matter.

### Admission Pipeline

```mermaid
flowchart LR
    S1[1. Build + boot<br/>docker compose up<br/>all healthchecks pass] --> S2[2. Exploitability<br/>run golden path<br/>all steps succeed]
    S2 --> S3[3. Patchability<br/>revert each vuln<br/>golden path breaks]
    S3 --> S4[4. Evidence sufficiency<br/>logs + alerts exist<br/>for Blue investigation]
    S4 --> S5[5. Reward grounding<br/>rubrics produce<br/>valid scores]
    S5 --> S6[6. Isolation + leakage<br/>zones enforced<br/>no answer leaks]
    S6 --> S7[7. Task feasibility<br/>tasks reference real<br/>hosts, services, logs]
    S7 --> S8[8. Difficulty calibration<br/>golden path steps<br/>within tier target]
    S8 --> S9[9. NPC consistency<br/>personas respond<br/>per security_awareness]
    S9 --> S10[10. Realism review<br/>LLM advisory<br/>scenario plausibility]

    S10 -->|All pass| PASS[ADMIT SNAPSHOT]
    S10 -->|Any fail| FAIL[REJECT + RETRY]

    style PASS fill:#6bcb77,color:#fff
    style FAIL fill:#ff6b6b,color:#fff
    style S3 fill:#ffd93d,color:#333
```

### Check Details

| Check | What it does | How | Pass condition |
|-------|-------------|-----|----------------|
| **1. Build + boot** | Start all containers, verify services | `docker compose up -d` + healthchecks | All 8 containers healthy, all ports respond |
| **2. Exploitability** | Execute golden path end-to-end | Run each step from attacker container | `expect_stdout` found in each step's output |
| **3. Patchability** | Inverse mutation test | For each vuln: apply remediation, re-run its golden path step | Step MUST fail after patch |
| **4. Evidence sufficiency** | Blue has enough to investigate | Check logs exist, SIEM alerts fire, evidence files present | All evidence_spec items found |
| **5. Reward grounding** | Rubrics produce valid scores | Run CompositeRedReward and CompositeBlueReward against known scenarios | Scores in expected ranges |
| **6. Isolation + leakage** | Network segmentation holds, no answer leaks | Attacker tries to reach internal directly; grep task briefings for flag values | Connection refused; no flag strings in briefings |
| **7. Task feasibility** | Tasks are solvable given the topology | Red tasks reference reachable hosts/services; Blue tasks reference existing logs/evidence | Every task action has a target that exists and is reachable |
| **8. Difficulty calibration** | Golden path length matches tier target | Count golden path steps, compare against tier thresholds | Step count within +/-20% of tier target |
| **9. NPC consistency** (LLM, advisory) | Personas behave per security_awareness | Phase 1: mechanical persona card validation (awareness/susceptibility ranges). Phase 2: LLM sends calibrated test phishing to each NPC via `litellm.acompletion` | High-awareness (>=0.8) NPCs reject; low-awareness (<=0.3) NPCs fall for lures; susceptibility scores consistent with awareness |
| **10. Realism review** (LLM, advisory) | Scenario is realistic and non-leaking | LLM reviews redacted summary (briefings, vuln types, vuln hosts, topology hosts, golden path length, tier) via `litellm.acompletion` | No flag values in briefings, vuln plausible for host, difficulty matches tier, narrative coherent |

### Check 7: Task Feasibility

For each task in the snapshot:

1. **Red tasks**: Every golden path command references a host that exists in the topology and a service that is running. `nmap 10.0.1.0/24` only works if hosts exist in that subnet. `curl http://web/api/...` only works if web has an HTTP service.
2. **Blue tasks**: Every evidence_spec item references logs or files that are actually produced. If Blue's briefing says "check SIEM for SQLi patterns," the SIEM container must receive web access logs that contain the injection.
3. **Cross-task coherence**: Red's exploit chain and Blue's investigation path reference the same truth graph. Red's flags are in containers Blue can investigate. Blue's patches target the actual vulns Red exploits.

This is a **mechanical check** — iterate over task references, verify each target exists in the topology and is reachable from the correct zone.

### Check 8: Difficulty Calibration

Golden path length must match the tier target within tolerance:

| Tier | Target Steps | Tolerance |
|------|-------------|-----------|
| 1 | ~8 | +/-20% (6-10) |
| 2 | ~15 | +/-20% (12-18) |
| 3 | ~25 | +/-20% (20-30) |

Also checks:
- No single-step golden paths (trivial — not a real challenge)
- No golden paths with duplicate consecutive commands (builder hallucination)
- Vuln count within manifest's `min_vulns` / `max_vulns` bounds

This is a **mechanical check** — count steps, compare against thresholds.

### Check 3: Patchability (Most Important)

This is the inverse mutation test from Self-Play SWE-RL. For each planted vulnerability:

1. Apply the **remediation** from the truth graph (e.g., parameterize the SQL query)
2. Re-run the golden path step that exploits it
3. That step **MUST fail**
4. Revert the remediation (restore vulnerable code)

If patching a vuln doesn't break the golden path, the vuln is decorative -- the exploit works for a different reason. The snapshot is rejected.

### Failure Handling

```
Builder generates candidate SnapshotSpec
  -> SnapshotRenderer renders templates to Docker artifacts
  -> Validator builds + boots containers
  -> Runs 10 admission checks (8 mechanical fail-fast, 2 LLM advisory)
  -> Any mechanical fail -> Builder receives failure context, generates new snapshot
  -> Advisory fails -> logged, may trigger retry, never blocks on their own
  -> 3 consecutive failures -> Flag for human review, use last known-good snapshot
```

### Validation Metrics

Every admission decision is logged for quality monitoring:

```json
{
  "snapshot_id": "acme_v14",
  "builder_model": "anthropic/claude-sonnet-4-20250514",
  "attempt": 1,
  "checks": {
    "build_boot": {"pass": true, "time_s": 12.3},
    "exploitability": {"pass": true, "time_s": 8.1},
    "patchability": {"pass": true, "time_s": 15.2},
    "evidence_sufficiency": {"pass": true, "time_s": 2.1},
    "reward_grounding": {"pass": true, "time_s": 3.4},
    "isolation_leakage": {"pass": true, "time_s": 4.0},
    "task_feasibility": {"pass": true, "time_s": 1.2},
    "difficulty_calibration": {"pass": true, "time_s": 0.3},
    "npc_consistency": {"pass": true, "time_s": 6.1, "advisory": true},
    "realism_review": {"pass": true, "time_s": 3.8, "advisory": true}
  },
  "total_time_s": 45.1,
  "admitted": true,
  "vuln_classes": ["idor", "weak_creds"],
  "golden_path_steps": 5
}
```

### Toxic Validation Warning

R2E-Gym found ~10% of validations incorrectly favor wrong solutions. Track:
- False-positive rate (admitted broken snapshots that don't produce training signal)
- False-negative rate (rejected valid snapshots unnecessarily)
- Log every admission decision for post-hoc auditing

## LLM NPCs: Social Engineering Surface

### Why

Shell-script NPCs generate noise. LLM NPCs create an **attack surface**. Social engineering is the #1 real-world breach vector, but current cybersecurity AI training environments ignore it entirely because there's nobody to phish.

LLM NPCs let Red learn to craft phishing emails, pretext calls, and watering hole attacks. Blue simultaneously learns to detect these patterns in logs. The coupled reward creates an arms race in social engineering.

### Architecture

NPCs follow the same platform pattern: **Builder generates persona cards, Validator checks consistency, NPCs run as lightweight LLM agents during episodes.**

```mermaid
flowchart LR
    BLD[Builder LLM] --> PC[Persona Cards<br/>name, role, security_awareness,<br/>susceptibility, relationships]
    PC --> VAL{Validator<br/>NPC consistency check}
    VAL -->|pass| SNAP[Snapshot store]

    subgraph episode [During Episode]
        STIM[Stimulus<br/>email, chat, call] --> NPC[NPC LLM Agent<br/>persona + context]
        NPC --> ACT{Action}
        ACT --> CLICK[Click link]
        ACT --> REPLY[Reply with info]
        ACT --> IGNORE[Ignore]
        ACT --> REPORT[Report to IT]
    end

    SNAP --> episode

    style BLD fill:#ff6b6b,color:#fff
    style VAL fill:#ffd93d,color:#333
    style NPC fill:#7c73e6,color:#fff
```

### NPC Decision Function

Each NPC receives incoming stimuli and decides based on persona:

```
Input:  persona_card + stimulus (email body, sender, subject) + time_of_day + conversation_history
Output: action (click_link | open_attachment | reply | share_credentials | ignore | report_to_IT | forward)
```

The NPC LLM call is **not in the hot path** of `step()`. It runs asynchronously -- Red sends a phishing email in one step, the NPC processes it on its own schedule (based on `email_check_interval_min`), and Red sees the result in subsequent observations (access logs, new sessions, SIEM alerts).

### Red Social Engineering Actions

| Attack Vector | Channel | Red Action | NPC Response Based On |
|---------------|---------|------------|----------------------|
| Spearphishing | Email (Postfix) | Craft email from spoofed sender | `security_awareness` + email plausibility + sender reputation |
| Pretexting | Email/Chat | Impersonate IT, request creds | `credential_sharing` susceptibility + pretext quality |
| Watering hole | Web | Plant malicious page on compromised intranet | NPC browsing routine + link plausibility |
| Baiting | SMB | Drop malicious file on shared drive | `attachment_opening` susceptibility + file name/type |
| Vishing | Voice (stretch) | Call NPC, social-engineer credentials | `vishing` susceptibility + conversation plausibility |

### Blue Detection

Blue sees the **effects** in logs, never the NPC's internal reasoning:
- Anomalous email patterns (external sender → credential reset → new login)
- Unusual login locations (NPC account authenticates from attacker IP)
- Credential usage from wrong hosts (jsmith's creds used on DB, not marketing)

### Reward Extensions

| Signal | Agent | Source |
|--------|-------|--------|
| `r_social_engineering` | Red | NPC fell for attack (clicked link, shared creds) |
| `r_pretext_quality` | Red | Consistency of social engineering narrative |
| `r_phishing_detection` | Blue | Correctly identified phishing email in mail logs |
| `r_social_FP` | Blue | -0.2 per legitimate NPC email flagged as phishing |

### Multimodal Progression

| Level | Modality | Infrastructure | Training Signal |
|-------|----------|---------------|-----------------|
| 0 | None | Shell scripts | Noise ratio only |
| 1 | Text email | Postfix + LLM NPC agent | Social engineering + phishing detection |
| 2 | Text chat | Internal messaging service + LLM | Lateral social engineering |
| 3 | Voice | TTS/STT (Whisper + voice synthesis) | Vishing + voice phishing detection |
| 4 | Documents | Multimodal LLM (vision) | Malicious document analysis |

### Validator Check 9: NPC Consistency (`NPCConsistencyCheck`)

Fully implemented in `src/open_range/validator/npc_consistency.py` with two phases. Always advisory.

**Phase 1 -- Mechanical persona card validation** (no LLM):
- `security_awareness` must be in [0.0, 1.0]
- High-awareness (>=0.8) NPCs must have all susceptibility scores <= 0.5
- Low-awareness (<=0.3) NPCs must have at least one susceptibility score >= 0.3
- If mechanical checks fail, phase 2 is skipped

**Phase 2 -- LLM behavioral testing** (via `litellm.acompletion`):
1. For each NPC with clear high (>=0.8) or low (<0.3) awareness, send a **calibrated test phishing email** using `_PHISHING_TEMPLATE` (role-targeted urgent password reset)
2. LLM responds in character using `NPC_CONSISTENCY_PROMPT`, returning `{action, reasoning, suspicious_elements_noticed}`
3. High-awareness NPCs MUST reject (action in `{ignore, report_to_it, forward}`)
4. Low-awareness NPCs SHOULD fall for it (action in `{click_link, reply_with_credentials, open_attachment, share_credentials}`)
5. LLM failures degrade gracefully -- not counted as persona issues

If no NPC personas are configured, the check passes vacuously.

Configure model via `OPENRANGE_NPC_MODEL` env var (default: `anthropic/claude-haiku-4-5-20251001`).

### Validator Check 10: Realism Review (`RealismReviewCheck`)

Fully implemented in `src/open_range/validator/realism_review.py`. One of two LLM calls in the validator pipeline (the other is Check 9). Always advisory -- can trigger a retry but never overrides a mechanical pass. Configurable via the `ValidatorCheck` protocol; remove it from the check list to run fully mechanical.

The LLM reviews a **redacted summary** of the snapshot for issues that mechanical checks cannot catch:

1. **Briefing leakage**: Do task briefings hint at the vuln class or leak exploitation details?
2. **Scenario plausibility**: Does the vulnerability make sense for this host/service? (e.g., SQLi on a static file server is implausible)
3. **Difficulty calibration**: Is the golden path step count appropriate for the tier?
4. **Narrative coherence**: Do the hosts and services form a believable enterprise network?

The prompt is defined in `src/open_range/builder/prompts.py` as `REALISM_REVIEW_PROMPT`.

```python
class RealismReviewCheck:
    """LLM-based realism review. Always advisory."""

    def __init__(self, model: str | None = None):
        self.model = model or os.environ.get(
            "OPENRANGE_VALIDATOR_MODEL", "anthropic/claude-haiku-4-5-20251001"
        )

    async def check(self, snapshot, containers) -> CheckResult:
        # Build redacted summary -- never expose flags or golden-path commands
        summary = {
            "task_briefings": {
                "red_briefing": snapshot.task.red_briefing,
                "blue_briefing": snapshot.task.blue_briefing,
            },
            "vuln_types": [v.type for v in snapshot.truth_graph.vulns],
            "vuln_hosts": [v.host for v in snapshot.truth_graph.vulns],
            "topology_hosts": snapshot.topology.get("hosts", []),
            "golden_path_length": len(snapshot.golden_path),
            "tier": snapshot.topology.get("tier", 1),
        }
        response = await litellm.acompletion(
            model=self.model,
            messages=[
                {"role": "system", "content": REALISM_REVIEW_PROMPT},
                {"role": "user", "content": json.dumps(summary)},
            ],
            response_format={"type": "json_object"},
            temperature=0.0,
        )
        review = json.loads(response.choices[0].message.content)
        return CheckResult(
            name="realism_review",
            passed=review["pass"],
            details={"issues": review.get("issues", []), "model": self.model},
            advisory=True,  # Never overrides mechanical checks
        )
```

LLM failures degrade gracefully -- if `litellm.acompletion` raises, the check returns `passed=True` with a note, so it never blocks validation.

**Important**: The LLM never sees flag values, vulnerable code, or golden path commands. It sees only vuln types, vuln hosts, topology hosts, briefings, golden path length, and tier -- enough to judge realism, not enough to leak answers.
