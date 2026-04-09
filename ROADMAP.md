# OpenRange Roadmap

OpenRange is a multi-agent cybersecurity gymnasium. You bring your own
agent, your own model, your own eval. The environment is the product.

These are the seven features that would have the biggest impact on
making OpenRange the environment people choose to train and evaluate
their cybersecurity agents against.

---

## 1. Multimodal social engineering surface

Real social engineering doesn't happen through shell commands. An
attacker crafts a convincing email with a malicious PDF attached, calls
the front desk pretending to be IT support, drops a USB stick in the
parking lot, or sends a Teams message with a link that looks like an
internal wiki page.

OpenRange NPCs currently generate HTTP and SQL traffic in a loop. The
attack surface is one-dimensional — Red types commands, Blue reads
logs. There's no channel where Red has to be *persuasive*, and no
channel where Blue has to distinguish a real document from a crafted
one.

We should support multiple interaction modalities between agents and
NPCs:

**Email with attachments** — Red composes an email with a PDF, DOCX,
or image attachment via the mail container. The NPC receives it,
"opens" the attachment (simulated via a handler that checks file type
and content), and decides whether to click, forward, report, or
ignore based on their persona. The attachment's content (text, embedded
URLs, macro indicators) factors into the decision.

**Voice/phone pretext** — Red can initiate a simulated voice call to
an NPC's extension. The NPC receives a transcript-style prompt
describing the caller's request ("Hi, this is Dave from IT, I need
you to reset your password at this link"). The NPC responds based on
their role, awareness, and whether the request follows plausible
internal procedures. Blue sees a CDR (call detail record) in the
SIEM log.

**Chat/messaging** — Internal chat messages between NPCs and
potentially from Red (if Red compromises a user's chat account).
These show up in logs. Blue has to distinguish normal office banter
from lateral phishing.

**Document sharing** — NPCs share files on the SMB server. Red can
plant a malicious document in a shared folder. An NPC who accesses
that folder might "open" the document, triggering a payload event.

The key insight from [Generative Agents](https://arxiv.org/abs/2304.03442)
is that believable NPCs need memory across these channels — an NPC
who got a suspicious call in the morning should be warier about a
follow-up email in the afternoon. The multimodal surface creates
opportunities for compound social engineering attacks that mirror
real-world campaigns.

No other cybersecurity gym has this. CybORG models actions as discrete
state transitions. CALDERA replays scripted TTP chains. OpenRange's
real containers make multimodal interaction physically possible — we
just need to wire it up.

### Done when

- Red can send an email with an attachment that an NPC processes
  and reacts to based on content + persona
- Red can initiate a voice pretext interaction with an NPC
- NPC reactions across channels are influenced by memory (previous
  interactions affect future decisions)
- All multimodal interactions generate SIEM log entries for Blue
- Blue can distinguish real internal communications from attack
  attempts
- At least one bundled manifest includes a scenario with a
  multi-channel social engineering path in the golden path

---

## 2. Tag everything with MITRE ATT&CK

Every security team in the world speaks ATT&CK. When Red runs
`nmap -sV`, that's [T1046](https://attack.mitre.org/techniques/T1046/)
(Network Service Discovery). SQL injection through a web form is
[T1190](https://attack.mitre.org/techniques/T1190/) (Exploit
Public-Facing Application). Credential extraction from a database
is [T1555](https://attack.mitre.org/techniques/T1555/) (Credentials
from Password Stores).

Right now, OpenRange actions are untagged strings. Golden path steps
have no technique IDs. Blue detections reference events, not ATT&CK
categories. This makes the environment invisible to the security
community — they can't map training outcomes to their threat models.

If someone trains an agent on OpenRange and wants to publish results,
they should be able to say "the agent learned to chain T1190 →
T1078 → T1021 → T1003 in 400 episodes" and every security
professional instantly understands what that means.

CALDERA already does this. We should too — but automatically, on
every action, not manually per playbook.

### Done when

- Every golden path step includes an `attack_technique` field
  with ATT&CK ID(s)
- Agent actions are auto-classified by technique when possible
  (regex pattern matching on common tools: nmap → T1046,
  sqlmap → T1190, hydra → T1110, etc.)
- Blue detections reference ATT&CK technique IDs
- Training data exports include technique tags per action
- The dashboard (if built) shows technique progression
- A mapping file `attack_techniques.yaml` defines the
  classification rules and is contributor-editable

---

## 3. Episode replay, comparison, and analytics dashboard

The current dashboard issue (#112) focuses on live episode viewing.
But when you bring your own agent and model, what you actually need
is the ability to:

- **Replay** a finished episode step-by-step, scrubbing forward
  and back like a video timeline
- **Compare** two agents side-by-side on the same snapshot — your
  fine-tuned model vs. the baseline, or GPT-5 vs. Claude on the
  same challenge
- **Aggregate** across episodes — success rate by vulnerability
  class, detection rate by ATT&CK technique, reward curves over
  training, time-to-first-flag distribution
- **Annotate** — mark interesting decisions for review, flag
  episodes where the agent did something unexpected

This is the interface researchers and security teams will spend the
most time in. It's not about watching a single episode — it's about
understanding agent behavior at scale.

Think of it like Weights & Biases for cyber agents. You're comparing
runs, not watching one.

### Done when

- Episode traces can be loaded from disk and replayed in the
  browser with a scrubbing timeline
- Two episodes (same or different agents, same or different
  snapshots) can be viewed side-by-side
- Aggregate view shows success rate, detection rate, and reward
  curves across a batch of episodes
- Episodes can be filtered by snapshot, agent, vulnerability
  class, ATT&CK technique, or outcome
- Works with trace files generated by any agent (BYO)
- Exports charts as PNG/SVG for papers

---

## 4. NPC orchestration and management API

NPCs are configured at build time through the manifest and
`GreenPersona` objects. Once an episode starts, there's no way to:

- See what NPCs are doing right now
- Adjust NPC behavior mid-training (increase phishing susceptibility
  to test Blue's detection, decrease it to test Red's persistence)
- Add or remove NPCs from a running episode
- Monitor NPC memory state (what have they seen? what do they
  remember?)
- Trigger specific NPC behaviors for testing ("make the sales rep
  open the next email they receive")

For BYO eval, this matters. A researcher evaluating their Blue agent
might want to script NPC behavior precisely to test specific
scenarios. A Red team trainer might want to gradually decrease NPC
susceptibility as their agent improves.

This should be a lightweight REST API that the runtime exposes:

```
GET  /npcs                    → list all NPCs and their state
GET  /npcs/{id}               → persona, memory, current plan, stats
PUT  /npcs/{id}/awareness     → adjust awareness mid-episode
POST /npcs/{id}/trigger       → force a specific behavior
GET  /npcs/{id}/memory        → view memory stream
GET  /npcs/stats              → aggregate NPC activity metrics
```

The dashboard (#112) would consume this API, but it's useful on its
own for scripted evaluation harnesses.

### Done when

- REST API exposes NPC state during running episodes
- NPC awareness and susceptibility can be adjusted mid-episode
  via API
- NPC memory stream is queryable
- Aggregate NPC stats (emails processed, links clicked, reports
  filed) are available
- API is documented with OpenAPI/Swagger
- Works with both live (Kind) and simulated runtime

---

## 5. Honeypot and decoy deployment for Blue

Blue's current action space is: read logs, flag suspicious activity,
patch services. That's defensive monitoring — important but
one-dimensional. Real defense teams deploy honeypots, canary tokens,
deceptive credentials, and fake services to detect and mislead
attackers.

CybORG CAGE 4 has a `DeployDecoy` action where Blue places a fake
service on any host. When Red interacts with it, the exploit
automatically fails and Blue gets a high-confidence alert. Red has a
counter-action `DiscoverDeception` with a 50% false negative rate.
This creates an entire strategic layer: Blue has to decide where to
place decoys, Red has to decide whether to test for deception before
committing to an exploit.

OpenRange should support:

- **Decoy services** — Blue deploys a fake SSH/HTTP/SMB endpoint.
  Red sees it in scans. Interacting with it triggers a
  high-confidence alert and yields no useful data.
- **Canary credentials** — Blue plants fake credentials in
  visible locations (database, config files). If Red uses them,
  it triggers an alert.
- **Canary tokens** — Fake files or DNS entries that alert when
  accessed.
- **Red counter-detection** — Red can probe whether a service
  is real or a decoy (with a configurable success rate).

This adds strategic depth without requiring new infrastructure —
decoys are lightweight containers or stubs that the runtime manages.

### Done when

- Blue can deploy a decoy service on any host via action
- Red interacting with a decoy triggers a high-confidence alert
  and yields no useful data
- Blue can plant canary credentials that trigger alerts when used
- Red has a `probe_decoy` action with configurable detection rate
- Decoy deployment and interactions appear in SIEM logs
- Reward system accounts for decoy interactions (Blue: bonus for
  Red hitting decoy; Red: penalty for falling for decoy)
- At least one reference trace demonstrates decoy strategy

---

## 6. Chain-of-thought reasoning in training traces

OpenRange exports training data as JSONL with actions, observations,
and outcomes. But not *reasoning*. A trace says "Red ran sqlmap" but
not "Red noticed port 80 was open, hypothesized a web application,
checked for input fields, found an unsanitized search parameter, and
chose SQLi as the most likely vulnerability class."

R2E-Gym showed that including structured reasoning traces in training
data improves downstream performance by 3.8%. The reasoning is the
part that generalizes — the specific commands are snapshot-dependent,
but the thought process transfers.

For BYO model training, this is the difference between training data
that teaches pattern-matching and training data that teaches
problem-solving.

We should generate reasoning annotations alongside each trace:

```json
{
  "tick": 3,
  "reasoning": {
    "observation": "Port 80 open, nginx detected, /search endpoint accepts query parameter",
    "hypothesis": "Unsanitized user input in search → possible SQL injection",
    "plan": "Test with sqlmap using the query parameter as injection point",
    "alternatives_considered": ["XSS via reflected input", "directory traversal on file upload"],
    "confidence": 0.7
  },
  "action": {"kind": "shell", "payload": {"command": "sqlmap -u 'http://web/search?q=test' --batch"}},
  "outcome": {"success": true, "technique": "T1190"}
}
```

The reasoning can be generated by an LLM teacher looking at the
golden path and the snapshot world model — it doesn't need to come
from the agent itself. This is offline annotation of existing traces,
not a runtime change.

### Done when

- `TraceDecisionRow` includes a `reasoning` field with
  observation, hypothesis, plan, and alternatives
- A teacher script generates reasoning annotations for existing
  trace datasets using an LLM
- SFT export includes reasoning in the assistant messages
  (chain-of-thought style)
- Reasoning references ATT&CK techniques where applicable
- At least one bundled trace dataset includes reasoning
  annotations
- Documentation explains how BYO model trainers can use the
  reasoning traces

---

## 7. Fast abstract simulation for rapid RL iteration

A full episode with Docker containers takes 35-65 seconds per reset.
That's fine for evaluation and demos, but it makes serious RL
training impractical. A GRPO batch of 8 generations sharing one
reset is still ~40 seconds of dead time per batch.

NASim and NASimEmu showed that training in fast abstract simulation
and validating on real infrastructure (sim-to-real transfer) is a
proven approach. We need a simulation mode that:

- Models the network as a state graph (hosts, services, zones,
  credentials)
- Actions are state transitions with probabilistic outcomes
  (nmap scan → reveals open ports with P=0.95)
- Episode resets are instant (microseconds, not minutes)
- Observations match the real environment's format (same
  `Observation` type, same fields)
- Can run thousands of episodes per hour on CPU

The key insight for BYO model training: researchers want to iterate
fast during development (abstract sim), then validate on real
containers (live mode). The two modes should use the same API so
switching is a config change, not a code rewrite.

`sim.py` already exists as a trace replayer. This extends it into
a standalone simulator that can generate novel episodes from the
world model without touching Docker.

### Done when

- `openrange train --mode sim` runs episodes in abstract
  simulation with instant resets
- Sim observations have the same schema as live observations
- Sim supports the same action space (shell commands mapped to
  state transitions)
- Episode throughput is > 1000 episodes/hour on a single CPU core
- A sim-trained agent can be evaluated on live containers without
  code changes
- Sim outcomes are probabilistically calibrated against live
  results (measured and documented)
- Configuration: `EpisodeConfig(backend="sim")` vs
  `EpisodeConfig(backend="live")`

---

## How these fit together

```
                    ┌─────────────────────┐
                    │   Your Agent/Model   │
                    │   (BYO — any LLM,    │
                    │    RL policy, or      │
                    │    scripted agent)    │
                    └──────────┬──────────┘
                               │
                    ┌──────────▼──────────┐
                    │   OpenRange API      │
                    │   (same interface    │
                    │    for sim + live)   │
                    └──────────┬──────────┘
                               │
            ┌──────────────────┼──────────────────┐
            │                  │                  │
    ┌───────▼───────┐  ┌──────▼──────┐  ┌───────▼───────┐
    │  Fast Sim (#7) │  │ Live Range  │  │  Replay/Eval  │
    │  1000+ ep/hr   │  │ Real Docker │  │  Compare runs │
    │  dev + train   │  │ validate    │  │  (#3)         │
    └───────────────┘  └──────┬──────┘  └───────────────┘
                              │
         ┌────────────────────┼────────────────────┐
         │                    │                    │
    ┌────▼────┐     ┌────────▼────────┐    ┌──────▼──────┐
    │ NPCs    │     │ Honeypots (#5)  │    │ ATT&CK (#2) │
    │ Multi-  │     │ Decoys, canary  │    │ Tagged       │
    │ modal   │     │ tokens, fake    │    │ actions +    │
    │ (#1)    │     │ credentials     │    │ detections   │
    └────┬────┘     └─────────────────┘    └─────────────┘
         │
    ┌────▼────────────────┐
    │ NPC Management (#4) │
    │ REST API for state, │
    │ memory, tuning      │
    └─────────────────────┘

    Training data with chain-of-thought reasoning (#6)
    flows out of every mode → your training pipeline
```

## References

- [Generative Agents](https://arxiv.org/abs/2304.03442) (Park et al.,
  UIST 2023) — memory/reflect/plan architecture for believable NPCs
- [ZeroDayBench](https://arxiv.org/abs/2603.02297) (ICLR 2026
  Workshop) — reward hacking in LLM agent benchmarks
- [OMNI-EPIC](https://arxiv.org/abs/2405.15568) (ICLR 2025) —
  open-ended environment generation, curriculum from task archives
- [R2E-Gym](https://arxiv.org/abs/2504.07164) — hybrid verification,
  reasoning traces (+3.8%), procedural environment generation
- [Self-Play SWE-RL](https://arxiv.org/abs/2512.18552) — formal specs,
  inverse mutation testing, frontier-calibrating builder reward
- [CybORG CAGE 4](https://github.com/cage-challenge/cage-challenge-4) —
  multi-agent Blue defense, honeypot/decoy mechanics
- [CALDERA](https://github.com/mitre/caldera) — ATT&CK technique
  mapping, adversary profiles, GameBoard scoring
- [NASim](https://networkattacksimulator.readthedocs.io/) — abstract
  network simulation for fast RL training
- [PentestGPT](https://arxiv.org/abs/2308.06782) — structured attack
  tree state management
