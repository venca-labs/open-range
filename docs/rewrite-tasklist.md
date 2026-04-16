# Rewrite Tasklist

This file is the durable memory for issue [#171](https://github.com/vecna-labs/open-range/issues/171).

The branch can be long-lived. The rule is simple: do not trust chat context to hold the rewrite plan. Put the plan, contracts, and parity checks in the repo.

## Guardrails

- contract first, implementation second
- move repeated world facts into `open_range.catalog` before rewriting the biggest switchboards
- add parity tests before deleting old paths
- keep public imports stable until the new package layout is ready
- do not add new top-level helper modules under `src/open_range`; new internals go under subsystem packages
- the issue comment examples still define the intended patterns:
  - admission check registry
  - objective rule registry
  - weakness family plugins
  - runtime hooks and reducers
  - extract SFT and model-facing prompt helpers out of core `src/open_range`
  - split `code_web.py` into a real subsystem instead of one flattened module

## Target Package Shape

This is the target, not the current state:

- `open_range.catalog`
- `open_range.admission`
- `open_range.runtime`
- `open_range.training`
- `open_range.world`

## Rewrite Order

### Phase 1: Contracts and parity

- [x] add a rewrite tasklist to the repo
- [x] add admission registry parity tests
- [x] add a real `open_range.catalog` package for objective and weakness rule data
- [x] make the current objective code read from catalog contracts instead of local switchboards
- [x] add parity tests that lock manifest predicate allowlists to catalog data
- [x] add parity tests that lock weakness objective tags to catalog data

### Phase 2: World facts into data

- [x] define service catalog contracts
- [x] define weakness family contracts
- [x] move weakness kind inventory into catalog and shared helpers
- [x] move weakness precondition templates into catalog
- [x] move weakness seed selection and pinned target resolution policy into catalog helpers
- [x] define objective rule contracts
- [x] define probe default contracts
- [x] define observability surface contracts
- [x] move static planner presets into catalog

### Phase 3: Subsystem rewrites

- [x] move admission onto real subsystem packages
- [x] start weakness family registry and family modules backed by catalog data
- [x] route curriculum weakness mutations through the family registry
- [x] start moving family-specific red reference planning out of `probe_planner.py`
- [x] move planner family ranking and red-side fallback policy behind catalog and family handlers
- [x] move blue-side detection and containment policy behind catalog probe helpers
- [x] move blue-side readback payload policy behind catalog probe helpers
- [x] move objective target, grader, and event resolution behind one objective registry contract
- [x] start moving family-specific realization content out of `synth.py`
- [x] finish moving family-specific realization content out of `synth.py`
- [x] start the runtime reducer split with shared continuity reducers
- [x] move red action reduction behind runtime reducers
- [x] move blue control transitions behind runtime reducers
- [x] move read-side observation state updates behind runtime reducers
- [x] centralize runtime control and finding payload parsing
- [x] move runtime event visibility and telemetry-delay policy behind runtime event helpers
- [x] move runtime event storage and visibility behind a runtime event log
- [x] move blue finding and scripted internal blue-opponent policy behind runtime reducers
- [x] move runtime audit and event side effects behind runtime hooks
- [x] move runtime reference playback behind private replay helpers
- [x] move runtime opponent mode and internal action selection behind reducers
- [x] move runtime internals under a real `open_range.runtime` package
- [x] finish the weakness subsystem move and shrink `open_range.weaknesses`
- [x] move objectives fully onto catalog-backed resolution
- [ ] move runtime onto hooks and reducers
- [x] move SFT prompt and system-prompt formatting out of core `src/open_range`
- [x] move remaining model-facing trace and action-formatting helpers out of core `src/open_range`
- [x] move trace row schemas and reference sim behind the training package
- [x] split `code_web.py` into specs, renderers, and remediation helpers
- [x] move `code_web` internals under a real `open_range.code_web` package
- [ ] move remaining code-web offline simulation semantics behind focused helpers

### Phase 4: Deletions

- [ ] remove duplicated switchboards
- [ ] remove stale compatibility helpers
- [x] add a test guardrail so new top-level helper modules fail fast
- [ ] shrink the top-level package surface
  - current branch state: root `src/open_range/*.py` files are down to `51`
  - recent cuts moved `runtime`, `code_web`, `admit`, `weaknesses`, and `tracegen` behind subsystem packages

## Immediate Next Slice

The next real win is:

1. finish the remaining `code_web` offline simulation split now that the subsystem is packaged
2. keep behavior stable with parity tests before deleting the old logic
3. collapse any remaining root-module compatibility seams that no longer buy us anything

## Next Large Targets

- `src/open_range/probe_planner.py`
  - finish any last generic fallback logic that still lives inline now that blue detection, containment, and readback payload policy are catalog-backed
  - keep the planner as orchestration over catalog policy and family-owned handlers
- `src/open_range/runtime/`
  - keep the public runtime surface stable while continuing to delete internal coordination bulk from `core.py`
  - avoid adding new runtime helpers back at the root package
- `src/open_range/code_web/`
  - keep the public facade small and move any remaining offline simulation semantics behind focused helpers
  - stop using one surface as the build, admit, synth, runtime, and live-patching switchboard for exact web flaws
- remaining rewritten root modules
  - `audit.py`, `compiler.py`, `curriculum.py`, `execution.py`, `manifest.py`, `pipeline.py`, `predicates.py`, `probe_planner.py`, `synth.py`
  - these still count against the issue target and should only stay at root if they are true entry points
