# Security Policy

## Reporting a vulnerability

Please do not publish exploit details for an unpatched RepoGuard vulnerability in a public issue.

Send a concise report to the maintainer with:

- affected version or commit
- reproduction steps
- expected versus actual behavior
- security impact
- suggested mitigation, if known

Please avoid including real credentials or third-party secrets in reports. Use synthetic test values whenever possible.

## Scope

RepoGuard is a local static hygiene scanner. Findings are heuristic and may include false positives or miss vulnerabilities. A clean RepoGuard result must not be treated as proof that a repository is secure.
