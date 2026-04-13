# AGENTS.md

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
- `validation_profile="full"` is the claim-strong path and requires live Kind
  validation on the public pipeline path.
- Offline or reduced workflows must opt into a weaker profile explicitly, such
  as `graph_only`.
- Do not silently downgrade validation strength.

## Naming And Leakage

- Use `ReferenceBundle`, `reference_attack_traces`, and
  `reference_defense_traces`.
- Do not reintroduce public golden-path semantics in the package surface.
- Do not leak hidden weakness inventory or private reference data into public
  APIs, snapshots, or prompt text.

## Review Priorities

1. architectural drift from the current objective
2. hidden-oracle leakage
3. silent downgrade from live to offline validation
4. reward or objective mismatch between admission and runtime
5. training-data mismatch with the actual runtime surface
6. stale compatibility shims back toward the deleted architecture
