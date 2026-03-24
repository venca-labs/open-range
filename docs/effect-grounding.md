# Effect Grounding

This document defines the V1 grounding contract for the remaining
benchmark-aligned objective types.

## Goal

OpenRange V1 already grounds file and database effects against concrete seeded
state. The remaining objective types are grounded through equally concrete live
effects:

- `unauthorized_admin_login`
- `privilege_escalation`
- `outbound_service`

## Acceptance Bar

V1 requires:

- admin login only scores if an admin-only effect artifact is observed
- privilege escalation only scores if a privileged effect artifact is observed
- outbound service only scores if a sink-side canary is hit
- at least one service-native mitigation per objective family breaks the effect
- branch-native trace rows export those effects and mitigations explicitly

## Implementation Shape

### Admin / Privilege

These objectives are grounded by service-local effect artifacts, not by generic linked events alone.

Examples:

- admin-only effect file created after a vulnerable admin surface is abused
- privileged effect file created after a vulnerable service-account or trust policy is abused

Live grading prefers:

1. effect artifact probe
2. weakness-specific realization probe
3. only then weaker output/event proxies when no stronger effect exists

### Outbound Service

`outbound_service` is grounded by a sink-side SIEM canary hit.

The exact-code SSRF slice uses:

- a real outbound HTTP request from the vulnerable web handler
- a dedicated canary listener on `svc-siem`
- a sink-side canary log artifact

Live grading only passes when the sink-side artifact shows the canary hit.

## Mitigation Semantics

V1 uses bounded mitigation rather than full repair engineering.
But for these effect types, mitigation must break the grounded effect for the right reason:

- disable a vulnerable route or admin surface
- narrow service-account or trust scope
- prevent the outbound canary hit

Generic path-breaking remains `mitigate`.
Only truly service-native behavior changes should be described as `patch`.

## Training Data

Branch-native trace rows include:

- `grounded_effects`
- `mitigation_effects`
- post-action stdout/stderr

These are exported as metadata, not injected into the default runtime-matching prompt surface.
