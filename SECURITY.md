# Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| dev     | ✅ Active development |
| v1      | ✅ Supported        |
| main    | ⚠️ Legacy only      |

## Reporting a Vulnerability

If you discover a security vulnerability in OpenRange, **please do not open a
public issue.** Instead:

1. Email **security@venca-labs.dev** with a description of the vulnerability
2. Include steps to reproduce if possible
3. We will acknowledge receipt within 48 hours
4. We aim to provide a fix or mitigation within 7 days for critical issues

## Scope

OpenRange is a training environment that intentionally contains seeded
vulnerabilities for red/blue agent evaluation. Reports about **intentionally
seeded weaknesses** inside admitted snapshots are out of scope.

In-scope reports include:

- Vulnerabilities in the OpenRange package itself (CLI, runtime, pipeline)
- Admission bypass that allows unadmitted worlds to run
- Reference/oracle data leaking into public snapshot surfaces
- Container escape or host-level exposure from the Kind backend
- Credential or secret exposure in the repository or CI pipeline
