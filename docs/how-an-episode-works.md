# How an Episode Works

This document is the practical runtime walkthrough for OpenRange V1.

If the other docs describe the contract, this one describes the actual flow:

1. build a world
2. admit it with private references
3. freeze it as a snapshot
4. reset an episode onto that snapshot
5. let red, blue, and green interact until a terminal condition is reached
6. export one training row per external decision

## The Short Version

An OpenRange episode runs on one admitted snapshot.

That snapshot is frozen before the episode starts. The environment does not
mutate the world during `reset()` or invent a new exploit path on the fly.
Instead, it loads an already admitted world plus a private `ReferenceBundle`
that proves the world is trainable.

During the episode:

- green runs internally as background business activity
- red tries to progress toward offensive objectives
- blue tries to detect and break that path while preserving continuity

The runtime advances internal time until the next externally controlled actor
must decide. Training data is recorded from those external decisions.

## What Is Frozen

The frozen unit is the admitted snapshot.

That snapshot contains the world state, validation outputs, and private
reference material needed by runtime and admission. The public snapshot surface
keeps the private reference data hidden, but runtime hydrates it internally when
an episode starts.

What freezing means in practice:

- the world layout is fixed for the episode
- the seeded weaknesses are fixed for the episode
- the hidden reference attack and defense traces are fixed for the episode
- the validator report is fixed for the episode

What freezing does not mean:

- no events happen
- no services degrade
- no containment or mitigation occurs
- no green-user activity occurs

The episode state changes. The admitted world definition does not.

## What Admission Does Before Runtime

Before a snapshot can be used for training, admission builds a private
`ReferenceBundle`.

That bundle contains:

- `reference_attack_traces`
- `reference_defense_traces`
- `smoke_tests`
- `shortcut_probes`
- `necessity_probes`
- `determinism_probes`

Admission uses those private references to prove the world is worth training
on.

The validator is checking things like:

- a real red path exists
- a real blue detect-and-contain path exists
- required telemetry reaches blue-observable surfaces
- obvious shortcuts do not trivially bypass the intended challenge
- replay is stable

This is the private oracle. It is not a public golden path and not an LLM
judge.

## Where Red Paths Come From

Red paths come from the seeded weaknesses in `WorldIR`.

The planner looks at the active weaknesses in the world and turns one or more of
them into private reference attack traces. For the web slice, it prioritizes
exact `code_web` weaknesses when possible. For other worlds, the reference path
may use:

- exact web flaws
- config and identity weaknesses
- secret exposure
- workflow abuse or phishing
- telemetry blind spots

Those traces are not just "pop a box" scripts. They continue until the red
objective predicates are satisfied, such as:

- file or database access
- unauthorized admin login
- privilege escalation
- outbound effect

So the red-side shape is closer to exploit-to-objective behavior than to a
single-step CTF flag submission.

## Where Blue Paths Come From

Blue reference traces are built from the red traces.

The planner identifies the first red step that should be visible to blue,
constructs the observation path to it, then builds a minimal defense trace:

1. observe enough telemetry
2. submit a finding
3. contain the relevant target

This means admission is not only proving that the world is exploitable. It is
also proving that the world is defensible under its declared telemetry and
continuity constraints.

## Who Controls Red And Blue

There are always two possible controllers for red and blue:

- external: your policy controls that actor
- internal: the runtime controls that actor

"Internal" does not mean the actor disappears. It means `next_decision()` will
not hand that actor to your policy. The runtime will choose actions for that
actor itself.

## Training Modes

The mode decides which actors are external.

| Mode | Red | Blue | Typical use |
| --- | --- | --- | --- |
| `red_only` | external | internal | train the attacker |
| `blue_only_live` | internal | external | train the defender against a live attacking red |
| `blue_only_from_prefix` | prefix replay, then inactive | external | train defender recovery from a compromised state |
| `joint_pool` | external | external | train both sides against opponent pools |

Internal red is usually reference-driven or scripted.
Internal blue is usually reference-driven or a simple heuristic.

That is a training-stability choice, not a claim that the built-in opponent is
as realistic as a human or a mature learned policy.

## What "Internal" Actually Means

When the scheduler decides that an actor is due:

- if that actor is externally controlled, `next_decision()` returns a decision
  for that actor
- if that actor is internally controlled, runtime picks the action itself and
  keeps advancing

That is why a blue-only episode can still have an active red attacker. Red is
present in the same episode, but the environment is controlling it.

Likewise, in a red-only episode, blue is still present as a defender. The
environment is just handling its actions internally.

## Runtime Flow

The runtime contract is small:

```python
snapshot = build_and_admit(...)
env.reset(snapshot_id, episode_config)

while not env.state().done:
    decision = env.next_decision()
    action = policy[decision.actor].act(decision.obs)
    env.act(decision.actor, action)

score = env.score()
```

What `reset()` does:

- load a chosen or sampled admitted snapshot
- optionally boot the live Kind-backed artifacts
- hydrate the private runtime snapshot
- initialize red, blue, and green state
- apply any prefix start for `blue_only_from_prefix`
- advance time until the first external decision is due

What `next_decision()` does:

- keep advancing simulated time
- run green activity that becomes due
- let internal red or blue act when they are due
- stop only when an externally controlled actor must decide

So `next_decision()` is not a simple alternating turn API. It is the public
surface of an asynchronous event loop.

## What Red Does During The Episode

Red tries to move forward on the offensive path and satisfy terminal objectives.

If red is internal, runtime usually follows the next reference attack step.
If red is external, your policy turns observations into concrete `Action`
objects and submits them through `act()`.

Red progress is grounded by the hidden reference path and by objective/event
checks. The red side is not rewarded for nice prose or for merely naming an
attack category. It has to cause the right state changes and effects.

## What Blue Does During The Episode

Blue tries to:

- observe malicious activity
- submit valid findings
- contain or mitigate the path before red completes
- preserve service continuity

If blue is internal, runtime either follows the reference defense path or uses a
simple built-in heuristic:

- detect a malicious event
- submit a finding
- contain a remaining red target

If blue is external, your policy receives blue observations and emits concrete
runtime actions through the same `act()` surface.

## Does Blue Really Patch Things

Sometimes, but not always in the same way.

Blue runtime actions can include containment, patching, mitigation, and
recovery. The exact effect depends on the weakness family.

For exact `code_web` weaknesses, patching is relatively concrete:

- the remediation changes the live service behavior
- the vulnerable route stops acting exploitable

For config, secret, workflow, identity, and telemetry weaknesses, blue
"patching" is more often bounded path-breaking mitigation:

- rewrite a config
- revoke or replace exposed material
- disable a workflow abuse path
- restore visibility or logging

That is why V1 should treat many blue-side patch actions as mitigation or
containment unless the service behavior really changes in a service-native way.

## What Green Does

Green is environment-owned business activity.

Green is not usually a trainer-stepped policy in V1. Instead, runtime advances
green internally to create:

- benign traffic
- workflow pressure
- email and phishing surface
- continuity pressure
- background noise for detection

This is part of what makes the world feel like an enterprise range rather than
a sterile red-only benchmark.

## When The Episode Ends

The episode ends when one of three things happens:

- red satisfies its terminal objectives
- blue detects and contains before red completes, while preserving continuity if
  continuity enforcement is enabled
- the episode times out

The runtime then records:

- winner
- terminal reason
- reward totals
- objective satisfaction state
- emitted event history

## Where Training Rows Come From

The canonical training export is one row per external actor decision.

That means:

- internal actions still shape the world
- green still changes what is visible
- red and blue may both act in the same episode
- but the dataset records the moments where an external controller had to decide

Each row can include:

- observation
- chosen action
- chosen action text
- emitted events
- reward delta
- winner
- terminal reason
- snapshot metadata
- lineage metadata

This keeps the training surface aligned with the actual runtime API.

## A Concrete Episode Timeline

Here is the simplest mental model for one blue-training episode:

1. build a world with a seeded web weakness
2. admission proves a private red exploit path and a private blue defense path
3. the snapshot is frozen and stored
4. `env.reset()` loads that snapshot in `blue_only_live`
5. red is internal, so runtime starts advancing red and green automatically
6. red triggers a malicious event that reaches a blue-visible surface
7. `next_decision()` returns a blue observation
8. blue submits a finding or applies containment/mitigation
9. runtime advances again and checks whether the remaining red path is broken
10. the episode ends with `red`, `blue`, or `timeout`

The same world can instead be used for `red_only`, where blue remains present
but is internally controlled by the environment.

## What This Document Is Trying To Clarify

OpenRange V1 is easiest to understand if you keep four ideas separate:

- admission proves a world is trainable
- snapshots freeze admitted worlds between episodes
- runtime still changes episode state inside that frozen world
- internal vs external control is about who chooses an action, not whether that
  actor exists

If those four ideas are clear, most of the rest of the docs become much easier
to read.
