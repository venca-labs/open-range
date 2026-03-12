# OpenRange V1 Paper Scope

This note freezes the intended V1 claim boundary for the branch so it does not drift after future refactors or context compaction.

## Position

OpenRange V1 is strong enough for a serious V1 and paper if it is presented as:

**a validator-admitted, mutable enterprise web-security training environment that combines exact code-level web flaws with configuration, workflow, and telemetry weaknesses, and trains red for exploit-to-objective behavior and blue for detection/containment under realistic green-user noise**

It should not be presented as full enterprise remediation automation or broad real-world cyber autonomy.

## V1 Claims

V1 should claim strength on:

- red: web exploit workflow, recon-to-objective planning, adaptation across bounded weakness families
- blue: alert triage, detection timing, containment timing, continuity tradeoffs under benign user noise
- green realism: phishing/workflow surface, normal traffic, false-positive pressure
- world quality: validator-admitted, replayable, non-trivial snapshots
- curriculum: worlds mutate across generations instead of staying static

## Non-Claims

V1 should not claim:

- full enterprise remediation engineering
- exhaustive shortcut elimination
- full SOC/IR automation depth
- all-benchmark cyber coverage
- general real-world-ready offensive or defensive autonomy

## Current Branch Status

Already in place:

- exact `code_web` flaw library with concrete handlers and witnessable routes
- exact weakness instances with `kind`, `benchmark_tags`, and instantiation metadata
- exact non-code weakness catalog coverage for the required `config_identity`, `secret_exposure`, `workflow_abuse`, and `telemetry_blindspot` kinds, with distinct config/file/workflow/mailbox realizations
- private witness bundle and validator-gated admission
- blue terminal win condition
- runtime-owned green activity
- async-capable runtime with separate red/blue session state
- `BuildConfig` and `EpisodeConfig` as the main ablation surfaces
- service-native route guards for exact web flaws, with bounded file/config mitigations for representative non-code weaknesses
- broader shortcut probes for direct reachability, obvious unguarded web routes, public asset exposure, public-surface secret leakage, and missing service-local telemetry on critical weakness targets

Still weak relative to the strongest realism claim:

- blue `patch` is still only partly service-native; it is stronger than pure marker toggles, but still not full remediation engineering
- live necessity now proves real route-guard breakage for exact web flaws, but other weakness families still lean on bounded mitigations
- shortcut and observability checks catch more obvious accidental solves and logging gaps, but they are still intentionally non-exhaustive

## Required Before Paper Freeze

These are the remaining high-value changes if the branch is going to be written up:

1. Clean up terminology around blue remediation.
   If an action is not truly service-native, describe it as `mitigate`, `contain`, or `break_path`, not full patching.

2. Extend the service-native mitigation set.
   Already landed:
   - disable a vulnerable route through a service-native guard for exact web flaws
   - rewrite representative secret/config artifacts in-place for bounded non-code mitigations

   Still desirable:
   - disable or revoke a credential or token
   - quarantine a service through policy/state change

3. Keep broadening shortcut probing enough to rule out obvious accidental solves.
   Already landed:
   - obvious unguarded web-route checks
   - public asset exposure checks on public web surfaces
   - public-surface secret leakage checks across synthesized payloads and mailboxes
   - direct reachability checks for protected services
   - service-local telemetry checks for critical weakness targets

   Still desirable:
   - seeded secret leakage checks across files, mailboxes, and configs
   - unintended trust and zone pivots beyond the current probe set
   - critical-action logging checks

4. Keep the benchmark coverage statement explicit.
   `enterprise_saas_v1` covers:
   - web exploit and web objective tasks
   - workflow compromise
   - enterprise detection and containment

   It does not cover:
   - pwn
   - reverse
   - crypto
   - CTI-only reasoning
   - all CTF families

5. Evaluate the claims against the right external slices.
   - red: at least one external held-out web/offensive slice
   - blue: held-out admitted worlds, held-out flaw mixes, held-out green profiles, prefix-start scenarios

## Recommended Paper Framing

Recommended claim sentence:

> OpenRange V1 improves training realism for enterprise web-security tasks by combining exact web flaws, workflow compromise, green-user dynamics, and validator-admitted mutable worlds.

Avoid stronger language about:

- full remediation realism
- exhaustive enterprise fidelity
- all-category cyber coverage

## V1 Release Rule

If no further realism work lands before paper freeze, the release is still valid provided the written claim stays inside the scope above.
