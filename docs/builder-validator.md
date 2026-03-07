# Builder + Validator Design

## Builder LLM

The Builder generates vulnerable infrastructure from YAML manifests. It's called:
- Once at startup (initial range creation)
- On every `reset()` (mutation — swap vulnerability classes)

### Input

```yaml
# From the YAML manifest
topology:
  hosts:
    - name: web
      zone: dmz
      services: [nginx, php, sshd]
    - name: db
      zone: internal
      services: [mysql]
  networks: [dmz, internal]

difficulty:
  tier: 1
  max_steps: 10

# Plus runtime context
previous_vuln_classes: [sqli]  # What was planted last episode
agent_solve_rate: 0.6          # How often Red solves (for difficulty calibration)
```

### Output (Structured JSON)

The Builder outputs a **formal spec**, not prose. Lesson from Self-Play SWE-RL: natural language generation failed with a 32B model. Formal specs are reliable.

```json
{
  "vulns": [{
    "type": "idor",
    "host": "web",
    "injection_point": "/api/user/{id}",
    "vulnerable_code": "...",
    "flag_location": "/var/flags/flag1.txt"
  }],
  "flags": [{
    "id": "flag1",
    "value": "FLAG{abc123}",
    "path": "/var/flags/flag1.txt",
    "host": "web"
  }],
  "golden_path": [{
    "step": 1,
    "cmd": "nmap -sV web",
    "expect_stdout": "80/tcp open http"
  }],
  "challenge_description": "A web application with user management. Find the vulnerability."
}
```

A thin template layer (`builder/templates/`) renders the JSON into actual files.

### Mutation Strategy

On `reset()`, the Builder:
1. Picks a **different** vuln class than the previous episode
2. Generates new vulnerable code, flag values, and golden path
3. Renders config files via templates
4. Hot-swaps into running containers (`docker cp` + service restart)
5. Does NOT tear down the full stack — partial restart only

## Validator (Hybrid)

Validates that the Builder's output actually works. Two phases.

### Phase A: LLM Review

The Validator LLM reviews the Builder's structured JSON spec:

```
Given this vulnerability specification and these config files:
1. Is the vulnerability actually exploitable? (Would the golden path commands work?)
2. Does the challenge description match without revealing the exploit?
3. Is the golden path complete? (No missing steps?)
4. Is this the right difficulty for tier {N}?

Answer YES/NO with brief reasoning for each.
```

### Phase B: 7-Check Scripted Execution

Run against live containers:

| Check | Command | Pass Condition |
|-------|---------|----------------|
| 1. Services | `nc -z web 80` | All ports respond |
| 2. Flags | `docker exec web cat /var/flags/flag1.txt` | Matches spec value |
| 3. Isolation | `docker exec attacker curl http://db:3306` | Connection refused |
| 4. Golden path | Execute each step | `expect_stdout` found in output |
| 5. Difficulty | `len(golden_path)` | Within 20% of `max_steps` |
| 6. No leaks | `grep -i "FLAG{" challenge_description` | No matches |
| 7. Inverse mutation | Revert each vuln, re-run its golden path step | Step FAILS |

Check 7 (inverse mutation) is the most important. It proves each planted vulnerability is necessary. Without it, the Builder could plant a "decorative" vuln that passes validation but isn't actually the path to the flag.

### Failure Handling

```
Builder generates spec
  → Validator Phase A (LLM) → FAIL → Builder retries with feedback
  → Validator Phase B (scripted) → FAIL → Builder retries with error context
  → 3 failures → Use last known-good configuration
```

### Toxic Validation Warning

R2E-Gym found ~10% of validations incorrectly favor wrong solutions. Track:
- False-positive rate (accepted broken ranges that don't produce training signal)
- False-negative rate (rejected valid ranges unnecessarily)
- Log every validation decision for post-hoc auditing
