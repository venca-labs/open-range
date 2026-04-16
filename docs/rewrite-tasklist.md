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
- [x] start moving family-specific realization content out of `synth.py`
- [x] finish moving family-specific realization content out of `synth.py`
- [ ] finish the weakness subsystem move and shrink `open_range.weaknesses`
- [ ] move objectives fully onto catalog-backed resolution
- [ ] move runtime onto hooks and reducers

### Phase 4: Deletions

- [ ] remove duplicated switchboards
- [ ] remove stale compatibility helpers
- [ ] shrink the top-level package surface

## Immediate Next Slice

The next real win is:

1. finish the remaining blue-side fallback and readback policy in `probe_planner.py`
2. finish the weakness subsystem move and shrink `open_range.weaknesses`
3. move pinned target resolution and selection policy out of `open_range.weaknesses`
4. keep behavior stable with parity tests before deleting the old logic

## Next Large Targets

- `src/open_range/probe_planner.py`
  - finish the remaining blue-side fallback policy and any readback expectations that still live inline
  - keep the planner as orchestration over catalog policy and family-owned handlers
- `src/open_range/weaknesses.py`
  - finish deleting the remaining family heuristics now that the family registry owns builders, mutators, and probe/render hooks
  - keep the file focused on orchestration and public seeding entry points
- `src/open_range/compiler.py`
  - finish deleting transitional compiler helpers now that workflow templates, asset placement rules, and persona defaults live under `open_range.catalog`
  - keep the compiler focused on assembling `WorldIR` from declared contracts
