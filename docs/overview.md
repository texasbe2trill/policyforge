# PolicyForge Overview

PolicyForge is a policy-as-code engine for infrastructure access control, written in Go. It evaluates whether an identity can perform an action on a resource at a given automation tier, and produces a compliance-ready evidence trail for every decision.

## What It Does

Given a request like:

```json
{
  "subject": "chris",
  "role": "operator",
  "resource": "prod/payment-service",
  "action": "restart",
  "requested_tier": "supervised_write"
}
```

PolicyForge returns one of three decisions:

| Decision | Meaning |
|---|---|
| `allow` | All policy checks passed |
| `deny` | A rule was violated |
| `require_approval` | Checks passed but human sign-off is needed |

Every evaluation also produces:
- A hash-chained audit log entry
- A compliance evidence bundle (with PCI-DSS control mapping)
- An approval record (when applicable)

## Core Concepts

**Safety Tiers** — Three levels of automation (`read_only`, `supervised_write`, `autonomous_write`). Each tier can require approval. Roles have a `max_tier` cap.

**Agent Envelopes** — Non-human identities (bots, CI pipelines) operate inside envelopes that restrict their scope on top of RBAC. Envelopes have their own resource patterns, action lists, and session TTLs.

**Drift Detection** — Re-evaluates the entire audit log against the current policy to find decisions that would now produce a different (stricter) outcome.

**Sessions** — Every authenticated API request is backed by a session with TTL enforcement. Agent sessions that exceed their TTL are denied before evaluation.

## Interfaces

| Interface | Binary | Usage |
|---|---|---|
| CLI | `cmd/policyforge` | Flags or JSON input, stdout output |
| REST API | `cmd/policyforge-api` | HTTP POST with JSON body, optional bearer auth |

Both use the same evaluation pipeline (`internal/service.Evaluate`) and produce identical outputs.

## Further Reading

- [Architecture](architecture.md) — System diagram, package responsibilities, data flow
- [README](../README.md) — Full reference (CLI flags, API endpoints, policy configuration)
- [Policy Packs](../examples/policy-packs/) — Ready-to-use policy configurations
- [ROADMAP](../ROADMAP.md) — What's built and what's planned
- [Sample Outputs](samples/) — Static examples of every response type
