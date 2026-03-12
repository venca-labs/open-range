# Architecture

OpenRange is organized as a Python control plane with bundled assets.

## Layers

```text
strict manifest
  -> WorldIR compiler
  -> deterministic synth + weakness seeding
  -> Kind renderer
  -> predicate engine + probe planning
  -> deterministic admission + private witnesses
  -> immutable snapshot store
  -> explicit green/red/blue runtime
```

## Repo boundaries

- `src/open_range/`: supported importable code
- `manifests/`: checked-in example manifests for the strict public schema
- `schemas/`: generated JSON schemas
- `examples/`: runnable examples against the current package API
- `data/`, `scripts/`: repo-only operational or experimental material

## Runtime model

- one snapshot defines one admitted world
- `reset(snapshot_id, episode_config)` selects or loads a stored snapshot and binds runtime mode
- the env advances internal green activity until the next external decision point
- `next_decision()` exposes only externally controlled red/blue actors
- red and blue have separate observations and separate session state
- admission uses private witness traces rather than a public golden path
- admission is internally split into shared predicate logic, probe planning, probe execution, counterfactual remediation checks, and report scoring

## Bootstrap traces

- optional bootstrap or warm-start traces come from the sim plane, not the core runtime contract
- `WitnessSimPlane` replays private witnesses through the public decision loop to generate cheap deterministic traces
- this keeps training warmup logic separate from the environment surface while preserving the old synthetic-bootstrap idea as a tooling layer

## Training data

- branch-native training data is generated from admitted snapshots, not from hand-written transcripts
- the canonical export is one decision row per external actor decision
- each row carries snapshot id, world id, world hash, lineage, mode, role, observation, candidate actions, chosen action, emitted events, reward delta, winner, and terminal reason
- `sim` and `runtime` trace sources stay explicitly labeled and separate
- training/eval splits are assigned by lineage root, not random row

## Benchmark-aligned offensive slice

- exact `code_web` weaknesses carry benchmark tags and benchmark-aligned `objective_tags`
- red objectives compile with derived offensive objective tags where possible
- admission builds deterministic service-native grader specs for grounded red objectives
- prompt exposure is controlled by `EpisodeConfig.prompt_mode` with `zero_day` and `one_day`
- private witnesses remain the hidden oracle; prompt modes never expose exploit steps

## Non-goals

- no compatibility layer for the deleted legacy builder/server/client stack
- no repo-level OpenEnv HTTP server wrapper
- no public answer-key semantics in manifests
