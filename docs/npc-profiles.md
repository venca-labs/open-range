# NPC Profile Spec

`npc_profiles` is an optional top-level manifest field for role-level green-user
behavior.

```yaml
users:
  roles:
    sales: 2
    engineer: 1
    it_admin: 1

npc_profiles:
  sales:
    awareness: 0.2
    susceptibility:
      initial_access: 0.8
      credential_obtained: 0.7
    routine:
      - check_mail
      - browse_app
      - access_fileshare
  it_admin:
    awareness: 0.9
    susceptibility:
      unauthorized_credential_use: 0.2
    routine:
      - review_idp
      - triage_alerts
      - reset_password
```

## Rules

- `npc_profiles` is optional.
- Keys must match names declared in `users.roles`.
- All fields are optional.
- Omitting `npc_profiles` or setting it to `{}` preserves the pre-existing
  compiler behavior.
- `awareness` and all `susceptibility` values must be between `0.0` and `1.0`.
- Profiles apply per role, not per individual user.

## Fields

### `awareness`

Normalized caution score.

- `0.0` = minimally aware
- `1.0` = maximally aware

Current V1 use:

- Used by the `small_llm` green backend when choosing who reacts to a malicious
  event.
- Higher awareness also makes recovery actions more likely after detection.

### `susceptibility`

Map from label to score.

- Keys are free-form strings at the schema level.
- `0.0` = minimally susceptible
- `1.0` = maximally susceptible

Recommended V1 keys:

- `initial_access`
- `credential_obtained`
- `unauthorized_credential_use`

Current V1 use:

- The `small_llm` green backend looks up the event-style key first.
- If that key is missing, it falls back to the maximum value in the map.

### `routine`

Ordered list of benign activities for the role.

Recommended V1 tokens:

- `check_mail`
- `browse_app`
- `access_fileshare`
- `open_payroll_dashboard`
- `review_idp`
- `triage_alerts`
- `reset_password`

Current service mapping:

- tokens containing `mail` -> email
- tokens containing `file` or `share` -> fileshare
- tokens containing `idp` or `password` -> IDP
- tokens containing `alert` or `triage` -> SIEM
- tokens containing `payroll` -> database
- everything else -> web app

## Current Scope

This feature provides role-level routine and reaction shaping. It does not yet
add per-user overrides, NPC memory, daily planning, or a richer social model.
