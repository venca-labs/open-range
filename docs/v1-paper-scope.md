# OpenRange V1 Scope

OpenRange V1 is a validator-admitted enterprise cyber training environment.

If you want the runtime mechanics first, read
[`How an Episode Works`](how-an-episode-works.md) before this scope document.

## One-line definition

OpenRange V1 is a manifest-driven enterprise cyber training environment that
builds a business world, validates it with private reference traces and
deterministic probes, runs episodes on immutable live snapshots, and trains red
and blue agents against realistic green-user dynamics and operational
constraints.

## Position

OpenRange V1 is not a red-only benchmark and not a full enterprise autonomy
claim. It is a mutable world-based training system with:

- public manifests
- a private oracle
- deterministic admission
- immutable admitted snapshots
- async red/blue runtime decisions
- environment-owned green-user activity

## Public Manifest, Private Oracle

The public manifest defines the legal business world:

- topology
- services
- users
- workflows
- assets
- observability requirements
- allowed weakness families
- mutation bounds

The manifest does not expose exploit steps, literal attack commands, or a public
answer key.

The internal oracle is a private `ReferenceBundle` containing:

- `reference_attack_traces`
- `reference_defense_traces`
- `smoke_tests`
- `shortcut_probes`
- `necessity_probes`
- `determinism_probes`

This keeps the execution and validation artifact hidden while preserving a
concrete mechanical notion of what the world is supposed to support.

## Canonical World Model

The manifest compiles into `WorldIR`, which is the canonical internal world
model.

`WorldIR` is the single source of truth for:

- hosts
- services
- users and credentials
- business assets
- workflows
- observability edges
- exact weakness instances
- red and blue objective predicates

Both the live range and the optional sim plane are derived from `WorldIR`.

## Deterministic Admission

A world is trainable only if admission proves all of the following:

- at least one real red path exists
- at least one real blue detect-and-contain path exists
- required telemetry reaches blue-observable surfaces
- no obvious accidental shortcut exists under the configured probe set
- reference execution is replayable and stable

Admission is deterministic and validator-grounded. V1 does not use an LLM judge
for admission, reward, or outcome scoring.

Necessity matters: if removing a claimed weakness or remediation point does not
break the corresponding reference path, that weakness was never a real
prerequisite.

## Immutable Snapshots

Training always runs on admitted snapshots, not mutable build outputs.

That snapshot boundary exists for:

- replayability
- fair comparison
- stable curriculum
- validator correctness

Runtime `reset()` binds an episode to a stored admitted snapshot. Mutation
happens between snapshots, not during a live episode.

## Weakness Model

OpenRange V1 does not treat the offensive surface as only CVEs or only abstract
weakness families. It uses a mixed weakness library:

- exact code flaws for the offensive web slice
- config and identity weaknesses
- secret exposure weaknesses
- workflow and phishing weaknesses
- telemetry and observability weaknesses

The public manifest defines the allowed weakness space. Exact instantiated
weaknesses live in `WorldIR` and the admitted snapshot.

## Offensive Objective Layer

The V1 offensive slice is aligned to the benchmark-style web exploit surface
where that mapping is meaningful. Standard offensive objective types are:

- `dos`
- `file_access`
- `file_creation`
- `db_modification`
- `db_access`
- `unauthorized_admin_login`
- `privilege_escalation`
- `outbound_service`

OpenRange reuses those as standard offensive objective types and adds blue-side
objectives around detection, containment, and continuity.

## Runtime Model

OpenRange runtime is asynchronous, event-driven, and simulated-time.

Red and blue may act in the same episode on the same frozen admitted world.
Green remains environment-owned unless a research ablation chooses to expose it.

Important runtime rules:

- `next_decision()` returns only externally controlled actors
- green activity advances internally between external decisions
- red and blue always keep separate session state and memory
- weight sharing is allowed; memory sharing is not

The episode ends when:

- red satisfies terminal objectives
- blue detects and contains before red completes while preserving continuity
- or the episode times out

## Control Surfaces

V1 exposes two main feature-control objects.

`BuildConfig` controls what gets built and admitted:

- phishing surface on or off
- allowed weakness families
- exact code flaw kinds
- observability surfaces
- green artifacts
- topology scale
- validation strength

`EpisodeConfig` controls runtime behavior:

- training mode
- scheduler mode
- green routine and branch behavior
- telemetry delay
- continuity enforcement
- reward shaping
- opponent controller
- prefix starts

If a realism feature cannot be toggled from `BuildConfig` or `EpisodeConfig`, it
is not part of the V1 contract.

## Training Modes

V1 supports staged training modes rather than fully joint training from
scratch:

- `red_only`
- `blue_only_live`
- `blue_only_from_prefix`
- `joint_pool`

This is a stability choice. Red and blue can share a world, but V1 does not
require unstable latest-checkpoint self-play every episode.

## Training Data Contract

Training data comes from admitted snapshots and executed traces over those
snapshots.

The intended pattern is:

1. build and admit a snapshot
2. execute runtime or sim traces on that snapshot
3. record observations, actions, events, rewards, winner, terminal reason, `snapshot_id`, and `world_hash`
4. freeze those traces into replayable datasets

The canonical export is one decision row per external actor decision.

## What V1 Covers

OpenRange V1 covers:

- web exploit tasks
- credential abuse
- workflow compromise
- enterprise detection and containment
- phishing-driven paths

OpenRange V1 does not claim:

- full pwn, reverse, crypto, or forensics coverage
- CTI-only reasoning
- exhaustive shortcut elimination
- full enterprise remediation engineering
- general real-world-ready cyber autonomy

## Honesty Rules

The V1 surface keeps a few explicit honesty constraints:

- no public golden path
- no LLM judge
- no trainer-stepped green actions
- no reward for prose evidence quality
- no reward simply because an action was named `patch`
- no claim of universal service-native remediation realism

Blue remediation in V1 is primarily containment or path-breaking mitigation.
Service-native remediation is implemented for selected weakness families and may
expand over time, but it is not assumed universally across the environment.
