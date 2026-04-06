# Roadmap

Current version: **v0.3.0**

## Completed

### v0.1.0 — Core Engine
- [x] YAML-based policy definition (roles, resources, safety tiers)
- [x] Deterministic evaluation engine with structured reasons
- [x] Agent policy envelopes with wildcard resource matching
- [x] Append-only audit log with SHA-256 hash chaining
- [x] Evidence bundle generation with CSV index
- [x] Compliance control mapping (PCI-DSS)
- [x] CLI with flag and JSON input modes
- [x] REST API with identical evaluation behavior

### v0.2.0 — Control Assurance
- [x] Drift detection (re-evaluate audit log against current policy)
- [x] Approval persistence (create, approve, reject)
- [x] Richer evidence bundles (approval status, audit hashes)
- [x] CLI approval management commands

### v0.3.0 — Identity & Sessions + OSS Polish
- [x] Session-backed identity model
- [x] Bearer token authentication
- [x] OIDC stub for local development
- [x] Agent session TTL enforcement
- [x] API auth middleware with context-based identity
- [x] Session management (list, revoke) via CLI and API
- [x] `--version` flag
- [x] Architecture documentation
- [x] Policy pack examples
- [x] Demo scripts

## Planned

### v0.4.0 — Observability & Integration
- [ ] Structured JSON logging with configurable log levels
- [ ] Prometheus metrics endpoint (`/metrics`)
- [ ] Webhook notifications on deny/approval decisions
- [ ] Policy reload without server restart (SIGHUP or `/reload` endpoint)
- [ ] OpenTelemetry trace context propagation

### v0.5.0 — Policy Extensions
- [ ] Conditional rules (time-of-day, IP range, environment tags)
- [ ] Policy composition (import/merge multiple YAML files)
- [ ] Custom control framework definitions (SOC 2, HIPAA mappings)
- [ ] Policy validation command (`--validate`)

### Future
- [ ] Real OIDC/OAuth2 integration (replace debug stub)
- [ ] Database-backed stores (replace JSON files)
- [ ] Multi-tenant policy isolation
- [ ] Rego/OPA policy adapter
- [ ] Kubernetes admission controller mode
- [ ] Web dashboard for approval workflows

## Design Principles

These guide what gets built and how:

1. **Correctness over features** — Every decision must be deterministic and auditable.
2. **Zero external dependencies for core** — The evaluation engine has no runtime deps beyond the Go stdlib and YAML parser.
3. **CLI/API parity** — Both interfaces produce identical decisions, audit records, and evidence bundles.
4. **Append-only audit** — The log is never overwritten. Hash chaining provides tamper evidence.
5. **Deny by default** — Unknown roles, resources, actions, or tiers are denied.
