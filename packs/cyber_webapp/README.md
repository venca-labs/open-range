# cyber_webapp

OpenRange pack: procedural multi-service web targets with HTTP-shaped
vulnerabilities (SQLi, SSRF, broken-authz, …) plus a curriculum-aware
mutation step.

This pack is published as `openrange-cyber-webapp` and discovered by
OpenRange via the `openrange.packs` entry-point group. It depends on
`openrange` (the core) and is structured as a separate distributable
so future packs can ship independently — by another team, in another
repo, or installed at runtime.

See the top-level project README for OpenRange usage. Pack-level
internals live in [cyber_webapp/](cyber_webapp/) — `ontology.py`,
`builder.py`, `codegen/`, `npcs/`, and `vulnerabilities/`.
