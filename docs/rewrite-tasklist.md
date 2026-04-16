# Rewrite Tasklist

This file is the durable memory for issue [#171](https://github.com/vecna-labs/open-range/issues/171).

The branch can be long-lived. The rule is simple: do not trust chat context to hold the rewrite plan. Put the plan, contracts, and parity checks in the repo.

## Guardrails

- contract first, implementation second
- move repeated world facts into `open_range.catalog` before rewriting the biggest switchboards
- add parity tests before deleting old paths
- keep public imports stable until the new package layout is ready
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

Some current private helper files are transitional seams, not the end-state package layout. They should be folded into real subsystem packages later.

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
- [x] move blue finding and scripted internal blue-opponent policy behind runtime reducers
- [x] move runtime audit and event side effects behind runtime hooks
- [x] finish the weakness subsystem move and shrink `open_range.weaknesses`
- [x] move objectives fully onto catalog-backed resolution
- [ ] move runtime onto hooks and reducers
- [x] move SFT prompt and system-prompt formatting out of core `src/open_range`
- [x] move remaining model-facing trace and action-formatting helpers out of core `src/open_range`
- [x] split `code_web.py` into specs, renderers, and remediation helpers
- [ ] move remaining code-web offline simulation semantics behind focused helpers

### Phase 4: Deletions

- [ ] remove duplicated switchboards
- [ ] remove stale compatibility helpers
- [ ] shrink the top-level package surface

## Immediate Next Slice

The next real win is:

1. keep pushing runtime state changes behind reducers and hooks
2. move the remaining runtime event-log and reference-playback policy out of `runtime.py`
3. keep pushing the `code_web` subsystem split until offline simulation and remediation semantics are no longer flattened into one surface
4. keep behavior stable with parity tests before deleting the old logic
5. collapse any remaining root-module compatibility seams that no longer buy us anything

## Next Large Targets

- `src/open_range/probe_planner.py`
  - finish any last generic fallback logic that still lives inline now that blue detection, containment, and readback payload policy are catalog-backed
  - keep the planner as orchestration over catalog policy and family-owned handlers
- `src/open_range/runtime.py`
  - keep moving action, observation, event-visibility, and blue-opponent policy behind reducers and helpers now that continuity, red action reduction, blue control transitions, blue finding, read-side observation updates, and runtime event projection already have shared seams
  - keep the decision loop and public runtime surface stable while deleting inline side-effect policy
- `src/open_range/training_data.py`
  - move the remaining model-facing action serialization and trace-formatting helpers behind the training package boundary now that SFT prompt formatting already lives in `open_range.training`
  - keep runtime types and trace rows in core, but stop leaving training-facing adapters in the root package
- `src/open_range/code_web.py`
  - keep the public facade small and move any remaining offline simulation semantics behind focused helpers
  - stop using one surface as the build, admit, synth, runtime, and live-patching switchboard for exact web flaws
