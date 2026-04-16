# AGENTS.md

Guidance for coding agents working in the current OpenRange repo.
Read [`CONTRIBUTING.md`](CONTRIBUTING.md) for local setup, checks, and pull
request format.

## Repo-Specific Rules

- Keep public docs and examples on the package entry points:
  `openrange`, `openrange-demo`, and `openrange-bootstrap-demo`.
- Use `uv run -m ...` only for module-only repo commands.
- Default pull requests should target `dev`, not `main`, unless asked
  otherwise.
- Keep changes focused, and add tests when behavior changes.

## Product Boundary

- OpenRange is a manifest-first Python package, not the legacy OpenEnv
  server/client stack and not the old public golden-path architecture.
- The core contract is:

1. public manifest
2. compile to `WorldIR`
3. seed exact weaknesses
4. synthesize bounded artifacts
5. render Kind artifacts
6. admit through deterministic validation plus private references
7. freeze an immutable snapshot
8. run episodes through the decision-loop runtime

The current objective is a validator-admitted enterprise web-security training
environment that combines:

- exact code-level web flaws
- exact config, workflow, secret, and telemetry weaknesses
- private reference attack/defense traces
- green-user runtime dynamics
- immutable snapshots and mutation between worlds

The scoped claim is:

- Red: exploit-to-objective behavior on the web-first enterprise slice
- Blue: detection, containment, and continuity under green-user noise

Do not broaden the claim to:

- full enterprise remediation automation
- exhaustive shortcut elimination
- broad cyber-benchmark coverage outside the bounded slice

## Architectural Invariants

- The public manifest defines the business, not the answer key.
- `WorldIR` is the canonical typed world model.
- `ReferenceBundle` is private validator-owned oracle data.
- Public `Snapshot` objects do not carry references by default; hydrate through
  the store when references are needed.
- Training runs on immutable admitted snapshots only.
- Green is environment-owned at runtime, not trainer-stepped.
- Runtime is decision-driven via `next_decision()` and `act()`.

## Validation Rules

- `LocalAdmissionController` is an admission gate, not a loose test suite.
- It must establish that the world makes structural sense, at least one
  reference attack path works, at least one reference defense path works,
  necessity and shortcut checks pass, and the world is stable enough to train
  on.
- `validation_profile="full"` is the claim-strong path and requires live Kind
  validation on the public pipeline path.
- Offline or reduced workflows must opt into a weaker profile explicitly, such
  as `graph_only`.
- Do not silently downgrade validation strength.

## Naming And Leakage

- `ReferenceBundle`
- `reference_attack_traces`
- `reference_defense_traces`
- Do not reintroduce public golden-path semantics in the package surface.
- Do not leak hidden weakness inventory or private reference data into public
  APIs, snapshots, or prompt text.

## Snapshot Boundary

There are two conceptual snapshot layers:

- `Snapshot`: public immutable world/state/report artifact
- hydrated runtime snapshot: internal snapshot plus private references

If code only needs world/state/report metadata, it should use `Snapshot`.
If code needs reference traces, it should hydrate explicitly through the store.

## Training Data Rules

The learning system should train on branch-native traces, not generic cyber chat.

Required properties:

- admitted-snapshot grounded
- lineage-aware
- role-correct
- mode-specific
- split by lineage root, not random row
- separate `runtime` and `sim` trace sources

Default decision prompts should mirror runtime observations.
Do not leak hidden weakness inventory or reference data into prompt text.

## Package Shape

Primary modules:

- `src/open_range/manifest.py`
- `src/open_range/compiler.py`
- `src/open_range/weaknesses.py`
- `src/open_range/synth.py`
- `src/open_range/render.py`
- `src/open_range/admit.py`
- `src/open_range/store.py`
- `src/open_range/runtime.py`
- `src/open_range/tracegen.py`

Examples and scripts are secondary surfaces and must stay aligned with the core
contract, especially around:

- explicit offline validation profiles
- hydrated runtime snapshots
- multi-reference support

## Build, Test, and Dev Commands

Prefer `uv run -m ...` for Python commands in this repo.

- create or refresh the local environment with `uv sync --extra dev`
- run the main test suite with `uv run -m pytest tests -q`
- run focused tests with `uv run -m pytest tests/test_runtime.py -q`
- inspect the CLI with `uv run -m open_range.cli --help`
- do not use `source .venv/bin/activate` for normal development flows
- do not fall back to raw `python -m ...` when `uv run -m ...` is available
- if `uv` is not on `PATH`, resolve the machine's local `uv` path first instead of falling back to venv activation
- run `docker` and `kind` directly, without wrapping them in Python env activation

## PR Guidelines

- `main` is the protected user-facing branch and remains the default branch on GitHub
- default pull requests for this repo should target `dev`, not `main`, unless the user explicitly asks otherwise
- keep each PR focused on one theme
- follow `.github/PULL_REQUEST_TEMPLATE.md`
- keep the `Testing` section terse and factual
- do not list routine Ruff, formatting, or generic unit-test commands in the PR body when CI already runs them
- reserve the `Testing` section for manual verification, integration checks, Kind/admission runs, training/eval smoke tests, or anything else the workflow does not already cover
- if there was no special verification beyond CI-covered lint/unit checks, either say that plainly or leave the `Testing` section empty
- do not add meta-commentary about omitted routine checks
- do not paste long verification logs or terminal transcripts into the PR body
- include the exact verification commands used in the PR description for admission, runtime, Kind-backed, training, or other non-routine validation
- use `Review Notes` only for reviewer-relevant context such as risks, tradeoffs, or follow-up work

## Review Priorities

When reviewing or changing code, prioritize:
1. architectural drift from the current objective
2. hidden-oracle leakage
3. silent downgrade from live to offline validation
4. reward or objective mismatch between admission and runtime
5. training-data mismatch with the actual runtime surface
6. stale compatibility shims back toward the deleted architecture
