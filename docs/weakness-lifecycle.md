# Weakness Lifecycle Spec

This document defines how OpenRange represents, realizes, validates, and
mutates security weaknesses under the OpenRange V1 contract.

## Goals

- The public manifest defines the allowed compromise space.
- The built `WorldIR` defines the exact exploitable weakness instances.
- Admission proves that at least one red path exists and that blue has enough observability and control to respond.
- Runtime blue `contain` and blue `patch` are distinct actions, even when
  exported training views may rename non-service-native patching as
  `mitigate`.
- Mutation may add, move, or remove weaknesses, but every child must still pass admission.

## Public Manifest Contract

The public manifest MUST describe the legal weakness envelope, not a public golden path.

Normal generation uses family mode:

```yaml
security:
  allowed_weakness_families:
    - code_web
    - config_identity
    - workflow_abuse
    - secret_exposure
    - telemetry_blindspot
  code_flaw_kinds:
    - sql_injection
    - broken_authorization
  phishing_surface_enabled: true
```

Controlled experiments MAY use pinned mode:

```yaml
security:
  pinned_weaknesses:
    - family: secret_exposure
      kind: credential_in_share
      target: asset:finance_docs
    - family: workflow_abuse
      kind: helpdesk_reset_bypass
      target: workflow:helpdesk_ticketing
```

Rules:

- `allowed_weakness_families` defines what kinds of weaknesses may exist.
- `code_flaw_kinds` constrains the exact code-web flaw kinds available to the seeder.
- `pinned_weaknesses` overrides family sampling and requests exact weakness placement.
- `phishing_surface_enabled` controls whether the generated business includes a mailbox/social surface for workflow and identity abuse.

## WorldIR Contract

Exact weaknesses live only in `WorldIR`.

Each `WeaknessSpec` MUST include:

- `family`: the weakness family
- `kind`: the exact flaw kind
- `target`: the service the runtime and validator reason about
- `target_kind` and `target_ref`: the exact cyber/business surface being weakened
- `benchmark_tags`: the benchmark slices this weakness is intended to cover
- `preconditions`: structural assumptions for the exploit path
- `expected_event_signatures`: runtime events expected if the weakness is exercised
- `blue_observability_surfaces`: the blue-facing surfaces that should expose the behavior
- `realization`: concrete artifacts/config/data that make the weakness visible in the rendered world
- `remediation`, `remediation_id`, `remediation_kind`, `remediation_command`: the inverse action used by live necessity checks and runtime patch actions
- `instantiation_mode`: `exact_code`, `exact_config`, or `exact_workflow`

`WeaknessSpec` is the canonical cyber object. Agents do not see it directly.

## Realization

Weaknesses are not metadata-only.

The synthesizer MUST realize every weakness into one or more concrete files or configs inside the rendered business:

- `code_web` -> exact web flaw template tied to a required `code_flaw_kind`, including concrete PHP handlers and seeded support files that the reference trace can reach through real HTTP routes
- `workflow_abuse` -> exact workflow policy/config, plus mailbox artifacts for email-borne phishing and impersonation variants
- `config_identity` -> exact identity/auth policy config with kind-specific policy deltas
- `telemetry_blindspot` -> exact telemetry routing/config with kind-specific log suppression or delay behavior
- `secret_exposure` -> exact exposed seeded material, including `.env`, backup, share, hardcoded-secret, and mailbox-token variants

The renderer MUST carry the realized weaknesses into the deployment artifacts so admission and debugging can inspect what was built.

## Admission

Admission has two levels:

- deterministic admission validates graph consistency, objective grounding, reference construction, necessity metadata, shortcuts, and determinism
- optional live admission validates boot, reference replay, SIEM ingest, necessity via remediation, and shortcut probes

Admission invariants:

- at least one seeded weakness MUST overlap the red reference path
- at least one reference-relevant weakness MUST have executable remediation for live necessity
- applying the remediation for a reference-relevant weakness MUST break the reference path in live mode
- live checks MUST run from a clean marker state between reference replays

## Runtime Semantics

Blue has two distinct control actions:

- `contain`: temporarily block future red progress through the target in the current episode
- `patch`: apply weakness-specific remediation to the target in the current episode

Rules:

- `contain` and `patch` are both episode-local; `reset()` restores the snapshot state
- `patch` emits `PatchApplied`; `contain` emits `ContainmentApplied`
- either action may satisfy blue's terminal containment objective if it breaks the remaining red path
- `recover` or `restore` clears both containment and patch markers for the target

`telemetry_blindspot` is active only while its target remains unpatched. When active, blue should not see malicious events on that target through normal observability surfaces.

## Mutation

Mutation works at the world level, not the runtime level.

Mutation MAY:

- add a new weakness
- move a weakness
- remove or harden a weakness
- add or remove a trust route
- add or remove a telemetry blind spot
- add users, hosts, services, or workflow noise

Every mutated child MUST still pass admission.

Runtime patching is temporary. Mutation-time hardening is persistent in the child snapshot.

Current V1 mutation support includes:

- persistent weakness patch/remove by dropping an inherited seeded weakness from the child world before reseeding
- route hardening that removes one direct red route and exposes an alternate route through a different service
