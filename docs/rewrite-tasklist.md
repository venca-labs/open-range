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
- [x] define objective rule contracts
- [ ] define probe default contracts
- [ ] define observability surface contracts

### Phase 3: Subsystem rewrites

- [ ] move admission onto real subsystem packages
- [ ] move weaknesses onto family plugins or family modules backed by catalog data
- [ ] move objectives fully onto catalog-backed resolution
- [ ] move runtime onto hooks and reducers

### Phase 4: Deletions

- [ ] remove duplicated switchboards
- [ ] remove stale compatibility helpers
- [ ] shrink the top-level package surface

## Immediate Next Slice

The next real win is not another `admit.py` split. The next win is:

1. create `open_range.catalog` contracts
2. move objective predicate rules and weakness objective tags into that package
3. make the current public objective helpers read from it
4. lock the behavior with parity tests
