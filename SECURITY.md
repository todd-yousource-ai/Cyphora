# Security Policy

## Supported versions

Cyphora is in **public beta**. Security fixes are applied to the current
`main` branch and the most recent tagged beta release.

| Version | Supported |
|---------|-----------|
| Cyphora-S1 v2.6 / ACDA-SDK v1.1 (current beta) | ✅ |
| Earlier pre-release builds | ❌ |

## Reporting a vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

Report suspected vulnerabilities privately by email to **john@yousource.ai**
with the subject line:

```
Security Disclosure — [brief description]
```

Please include, where possible:

- A description of the vulnerability and its impact.
- The affected component (e.g. `acda/runtime/consensus_validator.py`,
  a specific SIEM connector, an ingest parser).
- Steps to reproduce, or a proof-of-concept.
- Any suggested remediation.

### What to expect

- **Acknowledgement** within 3 business days.
- A coordinated disclosure timeline agreed with you before any public write-up.
- Credit in the release notes for the fix, unless you prefer to remain anonymous.

## Scope and safety-critical areas

The following areas are safety-critical; vulnerabilities here are treated as
highest priority:

- **Consensus validation** (`acda/runtime/consensus_validator.py`) — any path
  that would allow an action to fire below the configured threshold, or that
  bypasses the `min_models_required` floor or validation timeout.
- **Approval gating** (`acda/runtime/action_executor.py`) — any path that would
  execute a high-risk containment action without the required analyst approval.
- **Authentication** (`cyphora_s1/auth/`) — JWT, SAML, and OIDC handling.
- **Credential handling** — anything that could log, leak, or persist secrets
  or API keys (see also `.gitignore` and the configuration guidance in the README).

## Handling of secrets

Cyphora reads all credentials from environment variables or a secrets manager
at runtime. Never commit a populated `.env`, and never place real credentials
in `k8s/deployment.yaml` or a ConfigMap — use Kubernetes Secrets, HashiCorp
Vault, or AWS Secrets Manager.
