## OpenRange V1 — implementation spec

### 1. Purpose

OpenRange V1 is a **manifest-driven enterprise cyber training environment** for **red** and **blue** agents, with **green users embedded as environment dynamics**. It is meant to be more realistic than fixed cyber benchmarks while still being mechanically validated and reproducible.

The design intentionally combines a few ideas that already exist separately: **SSR** contributes the idea of a **hidden formal oracle**, **consistency validation**, and **necessity checks**; **Worlds** contributes **manifest-first world modeling** and a **tool/event-centric state model**; **CAGE 4** is the clearest reminder that green users matter for defender realism; **Kind** is the reference live backend because it runs local Kubernetes clusters using Docker “nodes.” ([arXiv][1])

OpenRange is **not** trying to be “all cyber benchmarks in one.” **CyBench** is a professional-level CTF benchmark, **CVE-Bench** is a real-world web exploit benchmark, **XBOW** is a large web offensive validation suite, and **CTIBench** is a CTI reasoning benchmark. OpenRange V1 targets the **enterprise web / red-blue / workflow** slice that overlaps with the first three, while leaving CTI-only reasoning and non-web exploit families to later world families or sidecar tasks. ([ICLR Proceedings][2])

---

### 2. Hard design choices

These are the fixed V1 decisions.

* The **public manifest defines the business**, not the exploit script.
* The system compiles the manifest into a typed **`WorldIR`**.
* The validator creates a **private `WitnessBundle`**. Witnesses may be “golden-path-like” internally, but they are not public.
* Training runs only on **immutable admitted snapshots**.
* **Builder is not RL-trained** in V1.
* **Green is env-owned at runtime**, but tunable by the trainer at reset/curriculum time.
* **Red and blue are separate sessions with separate memory**, even if they share base weights.
* Runtime is **asynchronous, event-driven, simulated time**, not forced red/blue step alternation.
* Main reward is **terminal and validator-grounded**.
* Every non-core realism feature must be ablatable through **`BuildConfig`** or **`EpisodeConfig`**.

The main reason to replace a public golden path with a private witness bundle is to follow the same spirit as **SSR**: keep the formal task artifact hidden, validate it mechanically, and avoid training directly against an exposed oracle. That also aligns better with **CVE-Bench**, which grounds exploitability with concrete exploit scenarios rather than loose textual claims. ([arXiv][1])

---

### 3. V1 coverage target

`enterprise_saas_v1` is not a generic cyber universe. It is a bounded enterprise family.

It must cover these slices well:

* **real web exploitation**, in the spirit of **CVE-Bench**
* **web offensive validation tasks** with clear objectives, in the spirit of **XBOW**
* **tool-grounded attack tasks** similar to the web/recon slice of **CyBench**
* **enterprise defense tasks**: detect, investigate, contain, preserve service continuity
* **workflow compromise**: phishing, helpdesk abuse, approval abuse, credential misuse

It does **not** need to cover, in V1:

* CTI-only reasoning as the core runtime task
* every non-web CTF family
* arbitrary pwn/reverse/crypto/forensics style worlds

This matters because V1 should be broad enough to learn benchmark-relevant offensive skills, but not so broad that it becomes incoherent. ([ICLR Proceedings][2])

---

### 4. Security flaw model

OpenRange V1 uses a **mixed flaw library**. Not every weakness is a CVE, but some must be **exact code-level flaws** if the system is supposed to transfer to CVE-Bench/XBOW-like web exploit tasks. That is the main spec change. ([arXiv][3])

#### 4.1 Broad flaw families

V1 supports five broad families:

* `code_web`
* `config_identity`
* `secret_exposure`
* `workflow_abuse`
* `telemetry_blindspot`

#### 4.2 Concrete flaw kinds

Minimum V1 required kinds:

`code_web`

* `sql_injection`
* `broken_authorization`  # IDOR / BOLA style
* `auth_bypass`
* `path_traversal`
* `ssrf`
* `command_injection`

`config_identity`

* `weak_password`
* `default_credential`
* `overbroad_service_account`
* `admin_surface_exposed`
* `trust_edge_misconfig`

`secret_exposure`

* `env_file_leak`
* `credential_in_share`
* `backup_leak`
* `token_in_email`
* `hardcoded_app_secret`

`workflow_abuse`

* `helpdesk_reset_bypass`
* `approval_chain_bypass`
* `document_share_abuse`
* `phishing_credential_capture`
* `internal_request_impersonation`

`telemetry_blindspot`

* `missing_web_logs`
* `missing_idp_logs`
* `delayed_siem_ingest`
* `unmonitored_admin_action`
* `silent_mail_rule`

#### 4.3 Exact-code vs exact-workflow

OpenRange must support **two instantiation modes**:

* **exact code flaws** for web exploit coverage
* **exact config/workflow flaws** for enterprise realism

So yes: some V1 flaws must be actual vulnerable code or exact vulnerable app behavior. But no: not every weakness must be code. Blue realism depends just as much on identity, workflow, and observability flaws.

#### 4.4 WeaknessSpec

Every concrete weakness instance is represented as:

```python
@dataclass(frozen=True)
class WeaknessSpec:
    weakness_id: str
    family: Literal[
        "code_web",
        "config_identity",
        "secret_exposure",
        "workflow_abuse",
        "telemetry_blindspot",
    ]
    kind: str
    target_id: str                     # host/service/workflow/user
    benchmark_tags: tuple[str, ...]   # e.g. ("cve_bench", "xbow", "enterprise_blue")
    preconditions: tuple[str, ...]
    observability_surfaces: tuple[str, ...]
    remediation_id: str
    instantiation_mode: Literal["exact_code", "exact_config", "exact_workflow"]
```

#### 4.5 Manifest vs exact holes

The manifest normally defines the **space** of allowed weaknesses, not every exact hole.

Default mode:

* manifest names allowed families / budgets
* builder + weakness seeder instantiate exact flaws

Pinned mode:

* manifest optionally pins exact flaws for debugging, evaluation parity, or benchmark-mirroring

Example pinned block:

```yaml
security:
  pinned_weaknesses:
    - family: code_web
      kind: sql_injection
      target: service:web_app
    - family: workflow_abuse
      kind: helpdesk_reset_bypass
      target: workflow:helpdesk_reset
```

---

### 5. Public manifest

The manifest is the public business contract.

It defines:

* business archetype
* zones and service palette
* role counts
* workflows
* sensitive assets
* red objective predicates
* blue objective predicates
* observability requirements
* allowed weakness families and optional pinned weaknesses
* difficulty targets
* mutation bounds

It does **not** define:

* exploit commands
* `expect_in_stdout`
* public flag paths
* a public canonical exploit chain

Minimal shape:

```yaml
version: 1
world_family: enterprise_saas_v1
seed: 1337

business:
  archetype: healthcare_saas
  workflows:
    - helpdesk_ticketing
    - payroll_approval
    - document_sharing
    - internal_email

topology:
  zones: [external, dmz, corp, data, management]
  services: [web_app, email, idp, fileshare, db, siem]

users:
  roles:
    sales: 8
    engineer: 6
    finance: 2
    it_admin: 1

assets:
  - id: finance_docs
    class: crown_jewel
  - id: payroll_db
    class: crown_jewel
  - id: idp_admin_cred
    class: sensitive

objectives:
  red:
    - predicate: asset_read(finance_docs)
    - predicate: credential_obtained(idp_admin_cred)
  blue:
    - predicate: intrusion_detected(initial_access)
    - predicate: intrusion_contained(before_asset_read)
    - predicate: service_health_above(0.9)

security:
  allowed_weakness_families:
    - code_web
    - config_identity
    - secret_exposure
    - workflow_abuse
    - telemetry_blindspot
  code_flaw_kinds:
    - sql_injection
    - broken_authorization
    - auth_bypass
    - path_traversal
  phishing_surface_enabled: true
  observability:
    require_web_logs: true
    require_idp_logs: true
    require_email_logs: true
    require_siem_ingest: true

difficulty:
  target_red_path_depth: 8
  target_blue_signal_points: 4
  target_noise_density: medium

mutation_bounds:
  max_new_hosts: 2
  max_new_services: 1
  max_new_users: 5
  max_new_weaknesses: 2
  allow_patch_old_weaknesses: true
```

---

### 6. BuildConfig and EpisodeConfig

These are the only two official control surfaces for empirical ablations.

#### 6.1 BuildConfig

Controls world construction and admission.

```python
@dataclass(frozen=True)
class BuildConfig:
    world_family: str
    services_enabled: frozenset[str]
    workflows_enabled: frozenset[str]
    weakness_families_enabled: frozenset[str]
    code_flaw_kinds_enabled: frozenset[str]
    observability_surfaces_enabled: frozenset[str]
    phishing_surface_enabled: bool
    green_artifacts_enabled: bool
    topology_scale: Literal["small", "medium", "large"]
    validation_profile: Literal["full", "no_necessity", "graph_plus_live", "graph_only"]
    red_witness_count: int
    blue_witness_count: int
```

Use `BuildConfig` for:

* which services exist
* which workflows exist
* which flaw families and code flaw kinds are allowed
* whether phishing/workflow surface exists
* whether green artifacts exist at all
* how strong admission is

#### 6.2 EpisodeConfig

Controls runtime behavior for a specific admitted snapshot.

```python
@dataclass(frozen=True)
class EpisodeConfig:
    mode: Literal["red_only", "blue_only_live", "blue_only_from_prefix", "joint_pool"]
    scheduler_mode: Literal["async", "strict_turns"]  # strict_turns is only an ablation baseline

    green_enabled: bool
    green_routine_enabled: bool
    green_branch_enabled: bool
    green_profile: Literal["off", "low", "medium", "high"]
    green_branch_backend: Literal["none", "scripted", "small_llm", "workflow_orchestrator"]

    telemetry_delay_enabled: bool
    telemetry_delay_profile: Literal["none", "low", "medium", "high"]

    continuity_enforced: bool
    continuity_threshold: float

    reward_profile: Literal["terminal_only", "terminal_plus_shaping"]
    red_milestone_shaping_enabled: bool
    blue_detection_shaping_enabled: bool
    blue_containment_shaping_enabled: bool
    false_positive_penalty_enabled: bool
    hallucination_penalty_enabled: bool

    opponent_red: Literal["none", "scripted", "witness", "frozen_policy", "checkpoint_pool", "replay"]
    opponent_blue: Literal["none", "scripted", "witness", "frozen_policy", "checkpoint_pool", "replay"]

    start_state: Literal[
        "clean",
        "prefix_delivery",
        "prefix_click",
        "prefix_credential_theft",
        "prefix_foothold",
        "prefix_lateral_movement",
    ]

    episode_horizon_minutes: int
```

Rule: if a realism feature cannot be turned on/off or parameterized through `BuildConfig` or `EpisodeConfig`, it is not a V1 feature.

---

### 7. WorldIR

`WorldIR` is the canonical typed world model.

```python
@dataclass(frozen=True)
class WorldIR:
    world_id: str
    family: str
    seed: int

    zones: tuple[str, ...]
    hosts: tuple["HostSpec", ...]
    services: tuple["ServiceSpec", ...]
    users: tuple["UserSpec", ...]
    groups: tuple[str, ...]
    credentials: tuple["CredentialSpec", ...]
    assets: tuple["AssetSpec", ...]
    workflows: tuple["WorkflowSpec", ...]
    edges: tuple["EdgeSpec", ...]           # network, trust, data, workflow, telemetry
    weaknesses: tuple[WeaknessSpec, ...]
    objectives_red: tuple["ObjectiveSpec", ...]
    objectives_blue: tuple["ObjectiveSpec", ...]
    green_personas: tuple["GreenPersona", ...]
    green_workload: "GreenWorkloadSpec"
    lineage: tuple[str, ...]
```

Supporting specs:

```python
@dataclass(frozen=True)
class HostSpec:
    host_id: str
    zone: str
    os_family: str
    tags: tuple[str, ...]

@dataclass(frozen=True)
class ServiceSpec:
    service_id: str
    service_type: str
    host_id: str
    routes: tuple[str, ...]
    depends_on: tuple[str, ...]
    telemetry_sinks: tuple[str, ...]

@dataclass(frozen=True)
class UserSpec:
    user_id: str
    role: str
    groups: tuple[str, ...]
    mailbox_id: str | None
    workstation_id: str | None

@dataclass(frozen=True)
class CredentialSpec:
    credential_id: str
    principal_id: str
    kind: Literal["password", "token", "key", "cookie"]
    scope: tuple[str, ...]

@dataclass(frozen=True)
class AssetSpec:
    asset_id: str
    owner: str
    location: str
    classification: Literal["public", "internal", "sensitive", "crown_jewel"]

@dataclass(frozen=True)
class WorkflowSpec:
    workflow_id: str
    kind: str
    actors: tuple[str, ...]
    resources: tuple[str, ...]

@dataclass(frozen=True)
class EdgeSpec:
    src: str
    dst: str
    kind: Literal["network", "trust", "data", "workflow", "telemetry"]

@dataclass(frozen=True)
class ObjectiveSpec:
    objective_id: str
    predicate: str

@dataclass(frozen=True)
class GreenPersona:
    persona_id: str
    role: str
    department: str
    awareness: float
    susceptibility: float
    accounts: tuple[str, ...]
    typical_actions: tuple[str, ...]
    workstation_id: str | None
    mailbox_id: str | None

@dataclass(frozen=True)
class GreenWorkloadSpec:
    profile: Literal["off", "low", "medium", "high"]
    work_hours: tuple[int, int]
    action_rate_lambda: float
    branch_llm_enabled: bool
```

---

### 8. Build pipeline

#### 8.1 ManifestCompiler

Manifest → `WorldIR`

Responsibilities:

* schema validation
* role expansion into users/personas
* topology graph
* workflow graph
* asset placement
* observability expansion
* mutation envelope calculation

#### 8.2 WorldSynthesizer

This is the only LLM-heavy stage.

It generates bounded artifacts:

* internal docs
* seeded emails
* tickets
* helpdesk history
* business app content
* fileshare content
* persona-specific data

Important rule:

* **code flaws are not “invented from scratch” by the LLM**
* exact code flaws come from a parameterized flaw template library
* the LLM may integrate those templates into bounded service modules, but does not freely invent the vulnerability class

This is the main way OpenRange borrows the lesson from **SSR** without actually RL-training the builder: use structured artifacts and strong validation, not unconstrained generation. ([arXiv][1])

#### 8.3 WeaknessSeeder

Adds concrete weakness instances from the flaw library.

Inputs:

* `WorldIR`
* `BuildConfig`
* optional pinned weaknesses

Outputs:

* updated `WorldIR` with exact `WeaknessSpec`s

Requirements:

* every seeded weakness has remediation metadata
* every seeded weakness has benchmark tags
* every seeded weakness is compatible with at least one red witness template
* every seeded weakness exposes expected observability surfaces for blue

#### 8.4 KindRenderer

Renders the world into a live backend.

Minimum live topology:

* zone namespaces
* NetworkPolicies
* service workloads
* state seed jobs
* log routing
* red sandbox
* blue sandbox

Kind is the reference backend because it provides local Kubernetes clusters using Docker container nodes and is designed for local development/CI. ([Kind][4])

#### 8.5 Optional sim plane

The same `WorldIR` may feed a sim plane that:

* parses canonical tool calls
* emits deterministic outputs
* emits state-change events
* generates cheap bootstrap traces

This is inspired by **Worlds**, but is optional in V1. Worlds’ key lesson is that one manifest/state model can drive deterministic tool/event simulation without provisioning real hosts. ([Dreadnode][5])

---

### 9. Admission controller

The validator is the center of gravity.

A candidate becomes trainable only if admission produces:

```python
admitted = True
Snapshot
WitnessBundle
ValidatorReport
```

#### 9.1 WitnessBundle

```python
@dataclass(frozen=True)
class WitnessBundle:
    red_witnesses: tuple["WitnessTrace", ...]
    blue_witnesses: tuple["WitnessTrace", ...]
    smoke_tests: tuple["Probe", ...]
    shortcut_probes: tuple["Probe", ...]
    determinism_probes: tuple["Probe", ...]
    necessity_probes: tuple["Probe", ...]
```

A witness trace may be “golden-path-like,” but it is:

* validator-owned
* private
* not unique
* not the public env contract

#### 9.2 ValidatorReport

```python
@dataclass(frozen=True)
class ValidatorReport:
    admitted: bool
    graph_ok: bool
    boot_ok: bool
    workflow_ok: bool
    telemetry_ok: bool
    red_witness_ok: bool
    blue_witness_ok: bool
    necessity_ok: bool
    shortcut_risk: Literal["low", "medium", "high"]
    determinism_score: float
    flakiness: float
    red_path_depth: int
    red_alt_path_count: int
    blue_signal_points: int
    business_continuity_score: float
    benchmark_tags_covered: tuple[str, ...]
    rejection_reasons: tuple[str, ...]
```

#### 9.3 Required admission stages

Static:

* manifest compliance
* graph consistency
* path solvability
* topology/workflow consistency
* objective grounding

Live:

* service health
* login/workflow smoke tests
* SIEM ingest
* isolation
* difficulty envelope

Witness:

* run at least one red witness end-to-end
* run at least one blue witness end-to-end

Necessity:

* remove a claimed weakness → red witness must fail
* remove a claimed observability point → blue witness must degrade
* apply remediation → at least one remaining red path must break

Shortcuts:

* direct crown-jewel access
* direct admin access
* unintended cross-zone reachability
* leaked secrets
* unlogged critical actions

Determinism:

* replay same witness
* compare event sequence, predicates, service health, final state hash

This is the direct OpenRange translation of **SSR**’s hidden formal task, consistency validation, and inverse mutation style reasoning. ([arXiv][1])

#### 9.4 Existing validator reuse

Keep and adapt from current code:

* manifest compliance
* graph consistency
* path solvability
* build boot
* isolation
* difficulty
* patchability

Change:

* public golden-path execution → private witness checks
* literal flag grounding → objective grounding
* stdout substring checks → predicate/event checks
* patchability → runtime containment grounding and necessity validation

---

### 10. Snapshots

All training runs on immutable admitted snapshots.

```python
@dataclass(frozen=True)
class Snapshot:
    snapshot_id: str
    world_id: str
    seed: int
    artifacts_dir: str
    image_digests: dict[str, str]
    state_seed_dir: str
    witness_bundle_path: str
    validator_report_path: str
    world_hash: str
    parent_snapshot_id: str | None
```

Contains:

* rendered manifests/config
* image digests
* DB/mail/file/identity state
* validator outputs
* witness bundle
* world hash
* lineage

`reset(snapshot_id)` restores exactly that world.
Blue may patch inside an episode temporarily. Mutation may patch permanently between worlds. Reset always returns to the original snapshot.

---

### 11. Runtime model

#### 11.1 Same world, separate minds

Red and blue may act in the same episode on the same world, but they are separate sessions.

```python
red_session  = AgentSession(...)
blue_session = AgentSession(...)
```

They may share weights. They do not share:

* prompt context
* scratchpad
* tool history
* KV cache
* role identity

#### 11.2 Async simulated time

Runtime is asynchronous and event-driven.

State:

```python
@dataclass
class EpisodeState:
    sim_time: float
    done: bool
    terminal_reason: str | None
    controls_red: bool
    controls_blue: bool
```

Internal event queue contains:

* green routine actions
* green branch decisions
* telemetry arrival
* alert generation
* service health changes
* red action completion
* blue action completion
* timeouts / polling wakeups

#### 11.3 Decision API

```python
@dataclass(frozen=True)
class Decision:
    actor: Literal["red", "blue"]
    obs: "Observation"
```

The env advances internal events until the next external actor must decide:

```python
env.reset(snapshot, episode_config)

while not env.done():
    decision = env.next_decision()
    action = policy[decision.actor].act(decision.obs)
    env.act(decision.actor, action)
```

Green is not trainer-stepped in V1.

---

### 12. Green design

Green is an environment-owned process because defender realism depends on background activity, benign noise, and continuity pressure; **CAGE 4** is the clearest precedent for green users as part of scenario dynamics. ([Cage Challenge][6])

#### 12.1 Keep from current code

* persona objects
* workload config
* proactive vs reactive distinction
* manager/executor split

#### 12.2 Fix from current code

* routine work becomes mostly scripted
* branch policy only triggers on stimuli
* actions originate from the correct workstation/mailbox/account
* no hardcoded credentials
* event types become typed
* live green runtime wiring must actually start on reset

#### 12.3 Green architecture

G0: scripted scheduler

* login/logout
* email send/receive
* file access
* app browsing
* ticket ops
* cron / service jobs

G1: branch policy

* open / ignore / report suspicious email
* approve / reject workflow
* escalate to IT
* reset password
* share / refuse information

Possible backends:

* scripted
* small LLM
* workflow orchestrator

#### 12.4 Green control boundary

Trainer may tune green through `EpisodeConfig`:

* on/off
* routine on/off
* branch on/off
* workload profile
* susceptibility band
* reporting band
* workday profile
* branch backend

Trainer does **not** call `env.act("green", ...)` in V1.

---

### 13. Event, action, and observation model

#### 13.1 Events

```python
@dataclass(frozen=True)
class Event:
    event_id: str
    sim_time: float
    actor: str
    category: Literal[
        "InitialAccess",
        "CredentialObtained",
        "UnauthorizedCredentialUse",
        "PrivilegeEscalation",
        "CrossZoneTraversal",
        "SensitiveAssetRead",
        "PersistenceEstablished",
        "DetectionAlertRaised",
        "ContainmentApplied",
        "RecoveryCompleted",
        "ServiceDegraded",
        "BenignUserAction",
    ]
    src: str | None
    dst: str | None
    malicious: bool
    surfaces: tuple[str, ...]
    predicates: tuple[str, ...]
```

#### 13.2 Actions

```python
@dataclass(frozen=True)
class Action:
    actor_id: str
    role: Literal["red", "blue"]
    kind: Literal["shell", "api", "mail", "control", "submit_finding", "sleep"]
    payload: dict[str, object]
    timeout_s: int = 30
```

Notes:

* `submit_flag` is not central in V1
* `submit_evidence` does not drive RL reward
* `submit_finding` stays, but is structured and validator-grounded

#### 13.3 Observations

```python
@dataclass(frozen=True)
class Observation:
    actor_id: str
    sim_time: float
    stdout: str = ""
    stderr: str = ""
    visible_events: tuple[Event, ...] = ()
    alerts_delta: tuple[str, ...] = ()
    inbox_delta: tuple[str, ...] = ()
    service_health: dict[str, float] | None = None
    reward_delta: float = 0.0
    done: bool = False
```

Blue always acts on its own observation after red effects and telemetry have landed.

---

### 14. Rewards and terminal conditions

#### 14.1 Red

Primary:

* `+1` if red terminal predicates are satisfied
* `-1` otherwise

Optional shaping:

* one-time milestone reward on `InitialAccess`, `CredentialObtained`, `CrossZoneTraversal`, `SensitiveAssetRead`
* small time cost
* hallucination penalty for false submissions

#### 14.2 Blue

Primary:

* `+1` if blue detects and contains before red terminal success and continuity stays above threshold
* `-1` otherwise

Optional shaping:

* first valid detection of important malicious events
* first containment that breaks a remaining red path
* false-positive penalties
* continuity-loss penalties

#### 14.3 Stealth

If explicit at all:

* `t_emit(e)` = malicious event time
* `t_detect(e)` = first valid detection time

Stealth is detection latency. In V1 it should mostly be implicit.

#### 14.4 Episode termination

An episode ends on:

* red terminal success
* blue terminal success
* timeout
* environment failure

Detection alone does not end the episode.
`done` must be hard-enforced.

---

### 15. Training modes

Do not train fully joint from scratch all the time.

#### `red_only`

External:

* red

Internal:

* blue
* green

Use for full attack trajectories.

#### `blue_only_live`

External:

* blue

Internal:

* red
* green

Use for live defense.

#### `blue_only_from_prefix`

External:

* blue

Internal:

* green

Start from:

* `prefix_delivery`
* `prefix_click`
* `prefix_credential_theft`
* `prefix_foothold`
* `prefix_lateral_movement`

Use for late-stage incident response.

#### `joint_pool`

External:

* red
* blue

Internal:

* green

Use frozen opponent pools, not only the latest opponent.

Builder is not RL-trained in V1.

---

### 16. Mutation and curriculum

Mutations happen only between admitted snapshots.

Allowed V1 ops:

* add host
* add service
* add user
* add workflow branch
* add trust edge
* add noise source
* add weakness
* patch/remove weakness
* harden one route and expose another
* alter observability within bounds

Important distinction:

* **runtime patching** by blue is episode-local
* **mutation patching** creates a new world where a weakness is permanently hardened

Every child must pass full admission again.

Suggested parent preference:

* low flakiness
* high determinism
* novelty
* near skill frontier
* good blue signal
* non-trivial
* not impossible

---

### 17. Core interfaces

```python
class ManifestCompiler(Protocol):
    def compile(self, manifest: dict, build_config: BuildConfig) -> WorldIR: ...

class WorldSynthesizer(Protocol):
    def synthesize(self, world: WorldIR, outdir: str) -> "SynthArtifacts": ...

class WeaknessSeeder(Protocol):
    def apply(self, world: WorldIR, build_config: BuildConfig, seed: int) -> WorldIR: ...

class KindRenderer(Protocol):
    def render(self, world: WorldIR, synth: "SynthArtifacts", outdir: str) -> "KindArtifacts": ...

class AdmissionController(Protocol):
    def admit(
        self,
        world: WorldIR,
        artifacts: "KindArtifacts",
        build_config: BuildConfig,
    ) -> tuple[WitnessBundle, ValidatorReport]: ...

class SnapshotStore(Protocol):
    def create(self, world: WorldIR, artifacts: "KindArtifacts", wb: WitnessBundle, vr: ValidatorReport) -> Snapshot: ...
    def load(self, snapshot_id: str) -> Snapshot: ...

class GreenScheduler(Protocol):
    def reset(self, snapshot: Snapshot, episode_config: EpisodeConfig) -> None: ...
    def advance_until(self, sim_time: float) -> None: ...

class RangeRuntime(Protocol):
    def reset(self, snapshot: Snapshot, episode_config: EpisodeConfig) -> EpisodeState: ...
    def next_decision(self) -> Decision: ...
    def act(self, actor: str, action: Action) -> "ActionResult": ...
    def score(self) -> "EpisodeScore": ...
    def export_trace(self, actor: str) -> dict: ...
    def done(self) -> bool: ...
    def state(self) -> EpisodeState: ...
    def close(self) -> None: ...

class MutationPolicy(Protocol):
    def choose_parent(self, population: list["PopulationStats"]) -> str: ...
    def mutate(self, parent: WorldIR) -> WorldIR: ...
```

---

### 18. Training loop

```python
for epoch in range(num_epochs):
    snapshot = snapshot_pool.sample()

    env.reset(
        snapshot=snapshot,
        episode_config=sample_episode_config(),
    )

    sessions = {}
    if env.state().controls_red:
        sessions["red"] = red_policy.new_session(role="red")
    if env.state().controls_blue:
        sessions["blue"] = blue_policy.new_session(role="blue")

    while not env.done():
        decision = env.next_decision()     # returns only externally controlled actors
        action = sessions[decision.actor].act(decision.obs)
        env.act(decision.actor, action)

    if env.state().controls_red:
        replay_buffer_red.add(env.export_trace("red"))
        red_policy.update(replay_buffer_red)

    if env.state().controls_blue:
        replay_buffer_blue.add(env.export_trace("blue"))
        blue_policy.update(replay_buffer_blue)

    if epoch % mutation_interval == 0:
        stats = evaluate_population(snapshot_pool, red_policy, blue_policy)
        children = mutation_policy.propose(stats)
        for child_world in children:
            candidate_world = build_pipeline(manifest_for(child_world), sample_build_config())
            admitted = admit_pipeline(candidate_world)
            if admitted.ok:
                snapshot_pool.add(admitted.snapshot)
```

Bootstrap stage:

* optional witness-derived traces
* optional sim-plane traces
* structured action traces

Then:

* `red_only`
* `blue_only_live`
* `blue_only_from_prefix`
* finally `joint_pool`

---

### 19. What this changes in the previous spec

The previous spec needs two concrete additions:

1. **Explicit security flaw model**

   * exact code flaws
   * exact config/identity flaws
   * exact workflow and telemetry flaws
   * benchmark tags per weakness

2. **Explicit benchmark coverage map**

   * V1 covers the enterprise web / workflow / red-blue slice
   * V1 does not promise to subsume every cyber benchmark family

That is the missing piece that makes the builder, validator, and curriculum precise enough to implement.

---

### 20. Final definition

**OpenRange V1 is a validator-admitted enterprise cyber training system whose public manifest defines a business, whose private witness bundle defines the hidden oracle, whose flaw library mixes exact code vulnerabilities with config, workflow, and telemetry weaknesses, whose green users are env-owned but trainer-tunable, and whose immutable snapshots support red-only, blue-only, prefix-start, and joint-pool training on an asynchronous shared timeline.**

[1]: https://arxiv.org/abs/2512.18552?utm_source=chatgpt.com "Toward Training Superintelligent Software Agents through Self-Play SWE-RL"
[2]: https://proceedings.iclr.cc/paper_files/paper/2025/file/3e9412a9c1d93810ef3ef7825115016b-Paper-Conference.pdf?utm_source=chatgpt.com "CYBENCH:AFRAMEWORK FOR EVALUATING CYBER"
[3]: https://arxiv.org/pdf/2503.17332?utm_source=chatgpt.com "CVE-Bench: A Benchmark for AI Agents' Ability to Exploit ..."
[4]: https://kind.sigs.k8s.io/?utm_source=chatgpt.com "kind - Kubernetes"
[5]: https://dreadnode.io/blog/worlds-a-simulation-engine-for-agentic-pentesting?utm_source=chatgpt.com "Worlds: A Simulation Engine for Agentic Pentesting"
[6]: https://cage-challenge.github.io/cage-challenge-4/?utm_source=chatgpt.com "TTCP CAGE Challenge 4"
