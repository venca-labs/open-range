# OpenRange Tasklist

This file tracks the branch-local rewrite against `spec_final.md`.

Rules:
- Do not edit `spec.md`, `spec_new.md`, or `spec_final.md`.
- Prefer deletion over compatibility shims when an older API conflicts with the current spec.
- Keep the branch runnable at the end of each completed phase.
- Check off only work that is implemented and verified.
- Keep [docs/v1-paper-scope.md](/home/talian/priv/open-range/docs/v1-paper-scope.md) aligned with the release and paper claim boundary.

## Phase 0 - Audit and freeze

- [x] Create standalone branch
- [x] Add tracked rewrite tasklist
- [x] Audit the inherited code against the earlier spec
- [x] Read and diff the new spec
- [x] Identify modules whose public contract now conflicts with `spec_new.md`

## Phase 1 - Freeze schemas

- [x] Keep strict manifest schema
- [x] Keep `WorldIR` as the canonical business graph
- [x] Keep `ValidatorReport` schema/model
- [x] Keep `WitnessBundle` schema/model
- [x] Add `BuildConfig`
- [x] Add `EpisodeConfig`
- [x] Add tests for config serialization and defaults

## Phase 2 - Fixed world family

- [x] Implement bounded `enterprise_saas_v1`
- [x] Keep manifest-first compilation into `WorldIR`
- [x] Keep deterministic weakness seeding
- [x] Thread `BuildConfig` through compiler decisions
- [x] Make enabled services/workflows/weakness families build-configurable

## Phase 3 - Live rendering and admission

- [x] Render live Kind artifacts from `WorldIR`
- [x] Generate private witness bundles
- [x] Keep deterministic static and live admission checks
- [x] Keep snapshot immutability
- [x] Change build/admission signatures to `build(manifest, build_config)` and `admit(candidate)`
- [x] Thread `BuildConfig` into admission strength and witness counts
- [x] Re-verify determinism under the new config surface

## Phase 4 - Runtime rewrite

- [x] Replace `tick + phase + observe()` with `sim_time + next_decision()`
- [x] Make green fully internal at runtime
- [x] Keep actor-specific observations
- [x] Enforce hard `done`
- [x] Preserve real blue terminal condition
- [x] Add `Decision`, `EpisodeHandle`, and updated `EpisodeState`
- [x] Support async scheduler mode
- [x] Keep strict-turn as an ablation via `EpisodeConfig`

## Phase 5 - Green rewrite

- [x] Change green scheduler contract to `reset(snapshot, episode_config)` and `advance_until(sim_time)`
- [x] Keep persona/workload snapshot state
- [x] Keep scripted routine traffic
- [x] Keep reactive branch hooks
- [x] Make green enablement/routine/branch/profile configurable from `EpisodeConfig`
- [x] Keep correct-origin traffic and typed events

## Phase 6 - Reward cleanup

- [x] Keep terminal-first, objective/event-grounded reward logic
- [x] Keep hallucination and false-positive penalties
- [x] Drop evidence and command-name patch rewards
- [x] Gate shaping through `EpisodeConfig`
- [x] Re-verify score and termination behavior under the new runtime API

## Phase 7 - Training/runtime modes

- [x] Support `red_only`
- [x] Support `blue_only_live`
- [x] Support `blue_only_from_prefix`
- [x] Support `joint_pool`
- [x] Add internal opponent controllers for non-external roles
- [x] Add prefix-start handling through `EpisodeConfig.start_state`

## Phase 8 - Package and surface cleanup

- [x] Delete remaining public APIs that expose `tick`, `phase`, `observe()`, or trainer-stepped green
- [x] Rewrite CLI, demo, driver, sim plane, and docs to the new contract
- [x] Rewrite runtime/service/integration tests to the new contract
- [x] Re-run the full suite

## Phase 9 - Weakness lifecycle

- [x] Add public family mode and pinned weakness mode to the manifest surface
- [x] Enrich `WeaknessSpec` with typed target, realization, and remediation fields
- [x] Realize seeded weaknesses into synthesized service payloads
- [x] Split runtime blue `patch` from blue `contain`
- [x] Use executable remediation metadata in live necessity checks
- [x] Update curriculum-added weaknesses to the richer weakness model
- [x] Add mutation operators that can persistently harden or move existing weaknesses between child worlds

## Phase 10 - Spec Final Rebase

- [x] Rebase public weakness families to `code_web`, `config_identity`, `secret_exposure`, `workflow_abuse`, and `telemetry_blindspot`
- [x] Add `code_flaw_kinds` to the public manifest and `BuildConfig`
- [x] Rebase `EpisodeConfig` enum values to the `spec_final.md` contract
- [x] Add `kind`, `benchmark_tags`, `remediation_id`, and `instantiation_mode` to `WeaknessSpec`
- [x] Move pinned weaknesses to the `family + kind + target` shape
- [x] Rework `ValidatorReport` to the summarized `spec_final.md` schema
- [x] Rework `Snapshot` to the `spec_final.md` contract
- [x] Rework `WorldIR` from split edge tuples to the unified edge model
- [x] Implement exact code flaw templates for the required `code_web` kinds
- [x] Extend curriculum with persistent `patch/remove weakness` and route-hardening operators

## Phase 11 - Paper-Readiness Hardening

- [x] Make `code_web` seeding mandatory when that family is allowed in enterprise web worlds
- [x] Ground exact web witnesses on real handler output instead of path-only matching
- [x] Add service-native route-guard remediation for exact web flaws
- [x] Add bounded file/config rewrite mitigations for representative non-code weaknesses
- [x] Expand the non-code weakness catalog so every required `config_identity`, `secret_exposure`, `workflow_abuse`, and `telemetry_blindspot` kind has a concrete realization path
- [x] Add mailbox-backed realizations for email-borne secret/workflow weaknesses
- [x] Validate pinned weakness family/kind pairs at manifest parse time
- [x] Broaden live shortcut probes beyond port reachability to include obvious web-route and public-asset exposure checks
- [x] Add artifact-side shortcut checks for public secret leakage and missing service-local telemetry on critical weakness targets
- [x] Re-verify integration coverage for live admission, runtime patching, and the demo flow

## Phase 12 - Review Fixes

- [x] Make red witnesses and necessity checks depend on exact non-code weakness realizations instead of only target overlap
- [x] Execute static witness checks in the default admission path instead of treating trace existence as success
- [x] Fix `blue_only_from_prefix` semantics so prefix states are not collapsed to generic first-step replay
- [x] Wire `false_positive_penalty_enabled` and `hallucination_penalty_enabled` into runtime reward behavior
- [x] Differentiate opponent-controller and green-branch enum modes so they are not simple boolean aliases

## Phase 13 - Tiny Training Path

- [x] Add deterministic train/validation splitting to the tiny SFT path
- [x] Add a held-out evaluation script for tiny SFT adapters
- [x] Document the tiny training and evaluation flow
- [x] Run and verify a real GPU-backed tiny SFT job on bootstrap-style data

## Phase 14 - Rollout Evaluation

- [x] Add a branch-native rollout evaluation script over admitted snapshots and mutations
- [x] Evaluate deterministic bootstrap and runtime episodes across held-out mutated worlds
- [x] Keep the rollout evaluation covered by a regression test

## Phase 15 - Model-In-Loop Rollout Probe

- [x] Add a bounded red-only model rollout probe that scores candidate runtime actions with the tiny adapter
- [x] Keep the model rollout probe covered by a helper-level regression test

## Phase 16 - Branch-Native Training Data

- [x] Add a written branch-native training-data spec separate from the frozen top-level specs
- [x] Add a first-class package trace generator for sim/runtime traces over admitted snapshots and mutations
- [x] Export canonical raw decision rows with snapshot, world, world hash, lineage, role, observation, candidate actions, chosen action, emitted events, and terminal metadata
- [x] Export branch-native decision SFT rows derived from those canonical trace rows
- [x] Keep sim traces and runtime traces explicitly labeled and separate in the exported dataset
- [x] Assign dataset splits by lineage root instead of random row
- [x] Switch the tiny training/eval default path to generated branch-native decision traces
- [x] Add CLI/script entrypoints and regression coverage for the trace-generation pipeline
- [x] Make multi-mutation trace generation robust to rejected child admissions instead of aborting the entire dataset build

## Phase 17 - Role-Correct Native Training

- [x] Make tiny SFT and held-out eval filter branch-native rows by role/source before sample caps
- [x] Default the tiny train/eval path to red-only decision data until a real blue policy-training loop exists
- [x] Add regression coverage for filtered sample limiting on mixed-role datasets
- [x] Tighten witness-step matching so extra API fields do not let probe actions count as teacher steps

## Phase 18 - Corpus Growth

- [x] Preserve lineage-aware split metadata in derived `decision_sft.jsonl` rows
- [x] Export clean role/source shard files for red, blue, runtime, and sim subsets
- [x] Document the shard outputs and runtime-first corpus workflow

## Phase 19 - Benchmark-Aligned Offensive Coverage

- [x] Add a written benchmark-aligned offensive coverage spec without editing the frozen top-level specs
- [x] Add a first-class standard attack objective library and service-native objective grader specs
- [x] Extend `WeaknessSpec` with benchmark-aligned `objective_tags`
- [x] Compile red objectives with derived offensive objective tags where possible
- [x] Require grounded red objectives to resolve to service-native graders in admission
- [x] Add `EpisodeConfig.prompt_mode` with `zero_day` and `one_day`
- [x] Expose prompt-mode-specific first-observation briefings without leaking private witnesses
- [x] Thread offensive objective tags into branch-native training-data exports

## Phase 20 - Offensive Coverage Review Fixes

- [x] Execute service-native objective graders during witness validation instead of only recording grader specs
- [x] Align objective-tag/grader semantics with runtime events for `credential_obtained` and related admin objectives
- [x] Remove hidden weakness/benchmark metadata from default decision-training prompts while keeping it in exported row metadata
- [x] Narrow `one_day` briefings to high-level risky surfaces instead of exact `family:kind@target` disclosure
- [x] Make the benchmark-aligned objective library part of the public manifest contract instead of a purely internal annotation layer

## Phase 21 - Reference Bundle Rename

- [x] Rename `WitnessBundle` to `ReferenceBundle`
- [x] Rename witness trace/action models and bundle fields to reference-oriented names
- [x] Rename snapshot/schema/resource paths from `witness_bundle` to `reference_bundle`
- [x] Rename runtime/sim helper classes and execution helpers from witness-oriented names to reference-oriented names
- [x] Regenerate checked-in schemas and re-verify the full suite

## Phase 22 - Higher-Level Review Fixes

- [x] Make multiple reference attack/defense traces meaningfully distinct and consume them across admission, runtime helpers, and trace generation instead of hardcoding the first trace
- [x] Make the default `full` admission path live-aware by auto-attaching the Kind backend when the local environment can support it, while keeping the report explicit when live checks are unavailable
- [x] Strengthen benchmark-aligned service-native objective grading by executing live grader checks during live red-reference validation instead of relying only on seeded-state proxies
- [x] Broaden native trace generation beyond pure reference imitation with additional scripted runtime traces and explicit teacher-source labeling
- [x] Finish the public rename from `witness` to `reference` in docs and user-facing config language

## Phase 23 - Architectural Review Fixes

- [x] Keep `ReferenceBundle` private by default instead of embedding it in the public `Snapshot` model
- [x] Make offline admission explicit by failing `full` admission when live Kind validation is unavailable
- [x] Narrow default decision-training prompts to the true runtime observation surface and keep evaluator metadata out of prompt text
- [x] Strengthen benchmark-aligned live objective grading for event-backed objectives beyond pure linked-event checks
- [x] Exercise multiple reference traces in the user-facing eval/demo surfaces instead of always using the first path

## Phase 25 - Contract Integrity Hardening

- [x] Keep exact world structure off the public `Snapshot` model and hydrate it only for runtime/admission code
- [x] Replace training/eval dependencies on runtime private methods with stable public runtime hooks
- [x] Make the default tiny train/eval path regenerate a fresh runtime-first corpus instead of silently reusing stale mixed-source data
- [x] Remove direct `asyncio.run(...)` call sites from sync admission/objective/live-exec code paths
- [x] Strengthen the weaker benchmark-aligned live objective graders beyond pure event proxies

## Phase 26 - Hidden Surface and Live Grader Tightening

- [x] Remove private world/reference file locations from the public `Snapshot` contract and keep runtime hydration internal to the store/service path
- [x] Stop advertising exact-world loaders as normal public store APIs; keep curriculum/runtime access on explicit internal helpers
- [x] Tighten live `unauthorized_admin_login` and `privilege_escalation` grading with realization-aware probes instead of token-based output matching
- [x] Tighten live `outbound_service` grading with stronger realized-effect checks instead of event-plus-output heuristics
- [x] Update tests and docs so the new hidden-surface boundary and stronger live graders are explicit

## Phase 27 - Private Runtime Hydration and Effect-Grader Hardening

- [x] Remove runtime/world hydration helpers from the public `FileSnapshotStore` class and keep them in an internal module
- [x] Cut service, curriculum, trace generation, demos, scripts, and tests over to the internal runtime-hydration helpers
- [x] Make live admin/privilege/egress output grading prefer weakness-specific live effect probes over generic output-token matches
- [x] Re-verify the hidden-surface boundary and stronger live graders with targeted and full tests

## Phase 24 - Codebase Simplification

- [x] Add shared build-config presets for offline structural and offline reference workflows
- [x] Centralize predicate parsing into one typed helper and remove duplicate string-splitting helpers
- [x] Extract shared decision-surface generation so trace export, scripted eval, and model probes use the same candidate logic
- [x] Split red/green event and objective-mapping logic out of `runtime.py`
- [x] Replace repeated large manifest fixtures in tests with shared support helpers
- [x] Narrow the root package surface so internal scripts/tests import from owning modules instead of one giant `__init__`
- [x] Align top-level contributor guidance with the standalone package architecture

## Audit notes

Current status against `spec_final.md`:
- public runtime now exposes `reset(..., episode_config)`, `next_decision()`, `act(...)`, `state()`, and `score()`
- green is runtime-owned and no longer trainer-stepped
- `BuildConfig` and `EpisodeConfig` are part of the public package surface
- build/admission signatures now carry `BuildConfig`
- training modes and prefix-start semantics are represented explicitly in `EpisodeConfig`
- weakness taxonomy has been rebased to the benchmark-oriented family model
- exact weakness instances now carry `kind`, `benchmark_tags`, and instantiation metadata
- exact weakness instances now also carry benchmark-aligned `objective_tags`
- the required non-code weakness kinds now realize as distinct config/file/workflow/mailbox artifacts instead of collapsing into one generic placeholder per family
- `WorldIR` now uses a canonical unified edge set with kind-filtered projections for network, trust, workflow, data, and telemetry views
- `code_web` weaknesses now render exact PHP handlers and witness routes for the required web flaw kinds
- curriculum now supports persistent weakness patch/remove behavior and route hardening with alternate-route exposure
- branch-native training data now comes from admitted-snapshot trace generation rather than the older mixed bootstrap chat file by default
- benchmark-aligned offensive coverage is now explicit through objective tags, service-native graders, and prompt-mode control

Current keep list:
- manifest-first `enterprise_saas_v1`
- deterministic weakness seeding
- private witness-driven admission
- shared predicate/objective reasoning between admission and runtime
- immutable snapshots
- live Kind backend
- objective/event-grounded rewards

Current drop list:
- explicit public `tick + phase` semantics
- trainer-stepped green actions
- stale API/documentation compatibility around the earlier runtime contract
