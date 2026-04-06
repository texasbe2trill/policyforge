# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.3.x   | ✅         |
| < 0.3   | ❌         |

## Reporting a Vulnerability

If you discover a security vulnerability in PolicyForge, **please do not open a public issue**.

Message via BlueSky: @texasbe2trill.bsky.social

Include:
- Description of the vulnerability
- Steps to reproduce
- Impact assessment
- Suggested fix (if any)

You should receive an acknowledgment within 48 hours. We will work with you to understand the issue and coordinate a fix before any public disclosure.

## Security Design

PolicyForge is built with the following security properties:

- **Deny by default** — Unknown roles, resources, actions, and tiers are denied.
- **Identity override** — When auth is enabled, request body identity fields are always overridden by the authenticated token. This prevents privilege escalation.
- **Tamper-evident audit log** — Each audit record contains a SHA-256 hash of its key fields and a reference to the previous record's hash, forming a chain.
- **Agent session TTL** — Agent sessions expire after a configurable time window. Expired sessions are denied before engine evaluation.
- **No secret storage** — Tokens are loaded from a YAML file at startup. PolicyForge does not persist secrets.

## Scope

The following components are in scope for security reports:

- Policy evaluation engine (`internal/policy`)
- Authentication middleware (`internal/auth`)
- Session management (`internal/session`)
- Audit log integrity (`internal/audit`)
- Approval workflow (`internal/approval`)

## Out of Scope

- The debug OIDC stub (`POLICYFORGE_ENABLE_DEBUG_OIDC`) — this is explicitly documented as unsafe for production.
- Denial of service via large input files — PolicyForge is designed for trusted operator use.
