# Rewrite Tasklist

This file is the durable memory for issue [#171](https://github.com/vecna-labs/open-range/issues/171).

Keep only the architecture decisions and the remaining merge gates here. Do not
turn this back into a branch diary.

## Guardrails

- contract first, implementation second
- keep repeated world facts in `open_range.catalog`, not spread across stage code
- keep new internals under real subsystem packages
- do not add new top-level helper modules under `src/open_range`
- keep public imports small and obvious
- do not add lazy export hacks, import-side-effect magic, or compatibility glue

## Target Package Shape

The package story should be obvious at the root:

- stage packages:
  - `open_range.manifest`
  - `open_range.compiler`
  - `open_range.weaknesses`
  - `open_range.objectives`
  - `open_range.synth`
  - `open_range.render`
  - `open_range.admission`
  - `open_range.store`
  - `open_range.runtime`
  - `open_range.training`
  - `open_range.catalog`
- support packages:
  - `open_range.config`
  - `open_range.contracts`
  - `open_range.support`
  - `open_range.sdk`

The root package should stay tiny. The story belongs in the stage packages, not
in a pile of shared type files.

## Merge Gates

Before merge, keep checking these:

- root package surface stays tiny
- stage package entry points stay small and intentional
- no wrapper/noise packages come back
- no new import-cycle glue or lazy export shims
- no hidden-oracle leakage across contracts, snapshots, prompts, or runtime
- no silent admission downgrade from live/full validation
- no tests whose only job is to pin internal helper layout or docs wording

## Remaining Work

- keep deleting parity-era scaffolding that no longer earns its keep
- keep shrinking `runtime/core.py` by moving pure state transitions behind
  reducers and other runtime-owned helpers
- keep `admission` thin while `checks`, `references`, `live`, and related
  helpers own the detailed behavior
- keep `weaknesses` and `synth` package internals honest; no new facade layers
- keep trimming package barrels so callers use canonical module owners
- keep the architecture contract test aligned with this document
