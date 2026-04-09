# Open Source Plan

Where we are, what to build, and how to make the project approachable.

## Where We Are

- 7 stars, 0 forks, 3 contributors — early days
- All 26 issues from the hackathon are closed, nothing open
- No releases, no tags, no topics on the repo
- No CONTRIBUTING.md, no issue templates, discussions off
- Labels are internal hackathon phases nobody outside the team understands
- PR #109 (v1 rewrite) is sitting in draft
- Repo description just says "Self-Evolving Cyber Range"

Bottom line: someone landing on this repo has no idea what to do with it.

## Housekeeping

**Description** — update to something that actually says what this is:
> Multi-agent cybersecurity gymnasium — LLM-generated challenges, verifiable rewards, Red vs Blue tandem RL

**Topics** — add so people can find us:
`cybersecurity`, `reinforcement-learning`, `llm`, `red-team`, `blue-team`, `ctf`, `pytorch`, `gymnasium`, `ai-safety`, `open-ended-learning`

**Labels** — replace the phase-1/2/3/4 hackathon labels with:
`area/runtime`, `area/admission`, `area/curriculum`, `area/training-data`, `area/infra`, `area/npc`, `area/ui`

**Turn on Discussions.** Turn off the wiki (nobody uses it).

**Add a short CONTRIBUTING.md**: how to install, run tests, what's worth working on.

**Tag v0.1.0 on main** so there's a baseline release before v1 lands.

## Issues

---

### 1. Run on a real Kubernetes cluster, not just Kind

Kind is fine for local development, but if someone wants to run
OpenRange in a university lab, a shared team environment, or any cloud
provider, there's no path for that today. `KindBackend` is the only
thing that implements the `LiveBackend` protocol.

The good news is the protocol is clean and the Helm chart already
produces real Kubernetes manifests. The gap is a backend that knows how
to talk to a remote cluster — handling kubeconfig contexts, namespacing
so multiple ranges don't collide, and not assuming the control plane
is a local Docker container.

This is the difference between a project only the authors can run and
one that other teams can actually deploy.

**Done when:**
- A new `K8sBackend` (or similar) implements `LiveBackend` and can
  boot a snapshot on any cluster reachable via `kubectl`
- Multiple ranges can run side-by-side in separate namespaces without
  interfering with each other
- There's a short guide: "point this at your cluster, run `openrange
  admit --backend k8s`"
- Kind stays the default for local dev — nothing breaks

`area/infra`, `enhancement`, `help wanted`

---

### 2. Make NPCs feel like real employees

Right now NPCs are shell scripts running curl and SQL queries in a
loop. It works as background noise but it doesn't look anything like
how people actually use corporate systems. A SOC analyst reviewing the
SIEM would immediately tell the difference between the synthetic
traffic and a real attacker.

[Generative Agents](https://arxiv.org/abs/2304.03442) (Park et al.)
showed that LLM-driven characters become genuinely believable when you
give them three things: a memory of what happened to them, the ability
to reflect on those memories, and a daily plan they actually follow.
25 agents in their sandbox autonomously organized a Valentine's Day
party — nobody scripted that.

We want the same idea, adapted for a corporate environment:

- **Memory** — an NPC who got a suspicious email yesterday should be
  warier today. Right now there's no memory between ticks at all.
- **Daily plans** — a sales rep checks email, opens CRM, joins a call,
  writes a proposal. Not the same three curl requests every 5 seconds.
- **Realistic reactions** — when Red sends a phishing email, the NPC's
  response should depend on their role, their security awareness, and
  what's happened to them recently. The `awareness` and
  `susceptibility` fields exist in `GreenPersona` already, but the
  live behavior doesn't use them meaningfully.
- **Inter-NPC communication** — employees talk to each other. Those
  conversations show up in logs. Blue has to figure out which messages
  are normal office chatter and which are social engineering.

We don't need the full Smallville sandbox. We need the
memory/plan/reflect loop running inside each NPC container, generating
traffic that a real defender would have trouble distinguishing from
actual employee behavior.

**Done when:**
- NPCs generate traffic that varies across the day (not a uniform loop)
- An NPC that received a phishing email in a previous tick remembers it
  and factors it into future decisions
- NPC-to-NPC messages appear in SIEM logs
- A human reviewing the SIEM output can't easily tell which log entries
  are NPC-generated vs which are Red's attack actions, without
  checking labels

`area/npc`, `enhancement`, `help wanted`

---

### 3. Episode dashboard

We deleted the old Gradio UI in the v1 rewrite and never replaced it.
Right now the only way to see what happened during an episode is to
parse JSON output or grep container logs. That's fine for automated
training but terrible for demos, debugging, or just understanding what
your agents are doing.

We need a simple web page that shows a live episode:
- What Red and Blue are doing, as it happens
- Which services are up, which are compromised
- The network topology — zones, firewall rules, what can reach what
- Running score — flags captured, detections, reward curve
- Filterable log stream — show me just Red actions, just Blue alerts,
  or just NPC background traffic

The runtime already writes events to the SIEM log via
`PodActionBackend.record_event()`. This is mostly about building a
frontend that tails that stream and makes it visual. FastAPI + HTMX,
Gradio, whatever works — it doesn't need to win design awards.

**Done when:**
- You can open a browser during a running episode and see the action
  timeline updating in real time
- Network topology is rendered as a simple graph (nodes = services,
  edges = allowed connections)
- You can filter the log view by actor (Red, Blue, NPC)
- Works with both Kind and the offline simulated runtime
- There's a screenshot in the README

`area/ui`, `enhancement`, `help wanted`

---

### 4. Let manifests define NPC profiles

The manifest specifies how many people work at the company
(`sales: 2, engineer: 1`) but has no say in how those people behave.
The compiler generates `GreenPersona` objects with awareness,
susceptibility, and routines baked in. If you want a scenario with
careless sales reps and a paranoid IT department, you have to edit
Python source.

Manifests should support optional persona templates:

```yaml
npc_profiles:
  sales_rep:
    awareness: 0.2
    susceptibility: {phishing: 0.8, pretexting: 0.6}
    routine: [email, crm, file_share]
  it_admin:
    awareness: 0.9
    susceptibility: {spear_phishing: 0.3}
    routine: [ssh, monitoring, email, tickets]
```

When the compiler creates personas for a role, it pulls from the
matching profile. If no profile is provided, use the current defaults.
This also means the Builder can vary NPC behavior across snapshots —
one episode has an easy social engineering surface, the next one
doesn't.

**Done when:**
- `npc_profiles` is a valid optional field in the manifest schema
- Compiler uses profile values when generating `GreenPersona` objects
- Omitting `npc_profiles` produces the same output as today (backwards
  compatible)
- At least one bundled manifest includes example profiles
- Manifest schema JSON is regenerated and passes validation

`area/npc`, `enhancement`

---

### 5. Catch agents gaming the reward

[ZeroDayBench](https://arxiv.org/abs/2603.02297) found that Grok
learned to run `git clone` to pull the latest upstream code, overwriting
the vulnerable version entirely. It got full credit for "patching" a
vulnerability it never actually found. 5.7% of Grok's evaluation
traces did this.

We intentionally give agents unrestricted shell access — that's a core
design choice and we're not changing it. But we're flying blind on
whether agents are actually solving challenges or just finding creative
ways around them. During a long training run, you might not notice for
hours that your agent converged on a single exploit-everything shortcut.

What we need is observability, not restriction:
- Flag suspicious patterns in the event log — `apt install`,
  `git clone`, `pip install`, overwriting service binaries
- Post-episode diversity report — are the agent's actions varying
  across episodes, or has it collapsed to one fixed sequence?
- Optional integrity check: hash the key service binaries before and
  after the episode, flag any solve where the target binary was
  replaced rather than exploited

Think of it as an anomaly detector for training runs. Researchers
reviewing results should be able to quickly see "episode 47: agent
cloned a repo instead of exploiting the vuln" without manually reading
every trace.

**Done when:**
- Configurable pattern list in `EpisodeConfig` for suspicious commands
- Event log entries include a `suspicious: true` tag when a pattern
  matches
- Episode summary includes an action diversity score (e.g. unique
  command prefixes / total commands) and a list of any flagged actions
- Optional binary integrity check that compares service checksums
  pre/post episode
- A test that runs a mock episode with a `git clone` action and
  verifies it gets flagged

`area/runtime`, `enhancement`

---

### 6. Fix the crashers in v1 before merge

PR #109 is a full rewrite and it has a handful of bugs that will blow
up the moment you try to run it against real containers. These came out
of code review and need to be fixed before the branch can merge:

- `cluster.py` uses `asyncio` everywhere but never imports it —
  NameError the first time you exec into a pod
- `PodSet` is marked as a frozen dataclass but `_resolve()` tries to
  write to `self.pod_ids` — FrozenInstanceError
- `_mail_command()` in `execution.py` puts agent-controlled strings
  (`sender`, `recipient`, `subject`) straight into a shell command
  with `.format()` and no quoting — textbook command injection
- `eval_model_rollouts.py` uses `TraceCandidate` in a type hint
  without importing it
- Several `assert` statements used for control flow in `runtime.py`
  and `execution.py` — these silently vanish if someone runs Python
  with `-O`

None of these are subtle. They're the kind of thing that works in
tests (because tests don't hit real pods) and breaks immediately in
production.

**Done when:**
- `import asyncio` is at the top of `cluster.py`
- `PodSet` either isn't frozen or doesn't mutate itself
- All user-controlled strings in `_mail_command()` go through
  `shlex.quote()`
- `TraceCandidate` is properly imported in `eval_model_rollouts.py`
- Every bare `assert` used for control flow is replaced with
  `if not x: raise RuntimeError(...)`
- All existing tests still pass

`bug`, `area/runtime`

---

### 7. A newcomer can try OpenRange in 60 seconds

If you land on the README right now, you see Kind, Helm, Docker, and
cluster setup before you see anything you can actually run. Most people
will close the tab.

The thing is, `openrange demo` already works without Docker. It builds
a snapshot offline, runs scripted Red and Blue agents in simulated
time, and prints scores. It's just buried in the docs and nobody would
know it exists.

We need the README to lead with:
```
pip install openenv-open-range
openrange demo
```

The demo output should explain what's happening in plain language as
it goes — "Loading tier 1 manifest... Compiling 8-host enterprise
network... Red agent scanning ports... Blue agent reviewing SIEM
alerts... Episode complete. Red captured 1/2 flags. Blue detected 3/4
attacks."

Then below that, a section for people who want to go deeper: "To run
live ranges against real containers, you'll need Docker and Kind."

The demo also currently imports from `_runtime_store`, a private
module. It should use the public API so it serves as a working
example people can copy.

**Done when:**
- README starts with a "Try it now" section showing `pip install` +
  `openrange demo`
- Demo output narrates each phase of the episode in readable English
- Demo only imports from the public `open_range` API
- README has a clear "Offline exploration" vs "Live ranges" split
- Someone who has never seen the project can go from zero to seeing
  output in under a minute

`documentation`, `good first issue`

---

## Community Basics

| What | Effort | Why |
|------|--------|-----|
| Enable Discussions | 1 click | Questions without filing issues |
| CONTRIBUTING.md | 10 minutes | How to install, run tests, where to start |
| Topics + description | 2 minutes | People can actually find us |
| Label a few good closed issues | 5 minutes | Shows project history |
| Issue templates | 15 minutes | Bug reports with useful info |

## Not Doing

- Discord/Slack — too early, nobody to staff it
- Formal governance — 3 contributors don't need a steering committee
- CLA — MIT license is enough
- Automated release pipelines — manual tags are fine for now

## References

- [Generative Agents](https://arxiv.org/abs/2304.03442) (Park et al.,
  UIST 2023) — 25 LLM-driven agents in a sandbox world with memory
  streams, reflection, and daily planning. Proved that the
  memory/reflect/plan loop produces believable autonomous behavior and
  emergent social dynamics. Directly inspires our NPC realism work —
  adapting their architecture from a virtual town to an enterprise
  environment where NPCs are employees and the "interesting events"
  are phishing attempts and security incidents.
- [OMNI-EPIC](https://arxiv.org/abs/2405.15568) (ICLR 2025) — open-ended
  environment generation via foundation models. Informed our curriculum
  design: task archive as stepping stones, failed tasks spawn easier
  variants, success detection separate from reward shaping.
- [ZeroDayBench](https://arxiv.org/abs/2603.02297) (ICLR 2026 Workshop) —
  LLM agents finding and patching novel vulnerabilities. Showed that agents
  learn to game benchmarks (git clone reward hack), information level is the
  main difficulty knob, and pentest-based evaluation (does the exploit fail
  after the fix?) is the right scoring method. Directly informs our inverse
  mutation testing in admission and the reward hacking telemetry issue above.
