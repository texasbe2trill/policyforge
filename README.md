# PolicyForge

[![CI](https://img.shields.io/github/actions/workflow/status/texasbe2trill/policyforge/ci.yml?branch=main&label=CI)](https://github.com/texasbe2trill/policyforge/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/texasbe2trill/policyforge)](https://goreportcard.com/report/github.com/texasbe2trill/policyforge)
[![Go Reference](https://pkg.go.dev/badge/github.com/texasbe2trill/policyforge.svg)](https://pkg.go.dev/github.com/texasbe2trill/policyforge)
[![Go Version](https://img.shields.io/badge/go-1.21%2B-00ADD8?logo=go)](https://go.dev/)
[![License: MIT](https://img.shields.io/badge/license-MIT-yellow.svg)](LICENSE)

**PolicyForge** is a lightweight Go tool for enforcing access policies in infrastructure workflows. You define your roles, resources, and safety tiers in YAML. PolicyForge takes a request, checks it against those rules, and tells you whether to `allow` it, `deny` it, or `require_approval`.

Every decision is logged to an append-only audit file — no setup required.

---

![PolicyForge demo](demo.gif)

**Approval workflow + drift detection:**

![PolicyForge approval workflow demo](artifacts/demo-approvals.gif)

---

## Table of Contents

- [How It Works](#how-it-works)
- [Quick Start (5 Minutes)](#quick-start-5-minutes)
- [Bring Your Own Policy](#bring-your-own-policy)
- [CLI Reference](#cli-reference)
- [Agent Policy Envelopes](#agent-policy-envelopes)
- [REST API](#rest-api)
- [Policy Configuration](#policy-configuration)
- [Decision Logic](#decision-logic)
- [Decision Response Schema](#decision-response-schema)
- [Audit Logging](#audit-logging)
- [Evidence Bundles](#evidence-bundles)
- [Approval Flow](#approval-flow)
- [Approval Persistence](#approval-persistence)
- [Drift Detection](#drift-detection)
- [Project Structure](#project-structure)
- [Development](#development)

---

## How It Works

A **decision request** describes an action a subject wants to take:

| Field            | Description                                      | Example                   |
|------------------|--------------------------------------------------|---------------------------|
| `subject`        | The identity making the request                  | `chris`                   |
| `role`           | The role assigned to the subject                 | `operator`                |
| `resource`       | The infrastructure resource being accessed       | `prod/payment-service`    |
| `action`         | The operation being performed                    | `restart`                 |
| `requested_tier` | The automation tier requested (`read_only`, `supervised_write`, `autonomous_write`) | `supervised_write` |

The engine evaluates the request against your policy and returns a **decision**:

| Decision           | Meaning                                                      |
|--------------------|--------------------------------------------------------------|
| `allow`            | All checks passed. The action is permitted.                  |
| `deny`             | A hard rule was violated. The action is blocked.             |
| `require_approval` | Checks passed but the resource or tier requires human sign-off. |

---

## Quick Start (5 Minutes)

### 1. Prerequisites

- Go 1.26 or later installed ([go.dev/dl](https://go.dev/dl/))
- This repository cloned locally

### 2. Clone and run your first evaluation

```bash
git clone https://github.com/texasbe2trill/policyforge.git
cd policyforge
```

Run three built-in scenarios back to back:

```bash
# Scenario A — allow: read-only viewer reads staging service
go run ./cmd/policyforge --policy ./configs/policy.yaml --input ./examples/request-allow.json

# Scenario B — deny: viewer attempts restart (not in their allowed actions)
go run ./cmd/policyforge --policy ./configs/policy.yaml --input ./examples/request-deny-action.json

# Scenario C — require_approval: operator restarts prod (protected resource + supervised tier)
go run ./cmd/policyforge --policy ./configs/policy.yaml --input ./examples/request-require-approval.json
```

### 3. Auto-approve the approval scenario

```bash
go run ./cmd/policyforge \
  --policy ./configs/policy.yaml \
  --input ./examples/request-require-approval.json \
  --auto-approve
```

### 4. Inspect the audit log

Every command above appended a record to the audit log:

```bash
tail -n 3 artifacts/audit.jsonl
```

---

## Bring Your Own Policy

The examples use a pre-built policy. To enforce your own rules, you only need to edit one file.

### 1. Copy the example policy

```bash
cp configs/policy.yaml configs/my-policy.yaml
```

### 2. Define your resources

Add every infrastructure target you want to protect:

```yaml
resources:
  - name: "prod/database"
    requires_approval: true
  - name: "staging/database"
    requires_approval: false
  - name: "prod/api"
    requires_approval: true
```

### 3. Define your roles

Map your team roles to allowed actions, tiers, and resources:

```yaml
roles:
  - name: "developer"
    allowed_actions: ["read", "deploy"]
    allowed_tiers:   ["read_only", "supervised_write"]
    max_tier:        "supervised_write"
    allowed_resources:
      - "staging/database"

  - name: "sre"
    allowed_actions: ["read", "deploy", "restart", "scale"]
    allowed_tiers:   ["read_only", "supervised_write", "autonomous_write"]
    max_tier:        "autonomous_write"
    allowed_resources:
      - "prod/database"
      - "prod/api"
      - "staging/database"
```

### 4. Evaluate requests

Pass your policy path to any command:

```bash
# via flags
go run ./cmd/policyforge \
  --policy configs/my-policy.yaml \
  --subject alice \
  --role developer \
  --resource staging/database \
  --action deploy \
  --tier supervised_write

# via a JSON file
go run ./cmd/policyforge --policy configs/my-policy.yaml --input my-request.json

# via the API
go run ./cmd/policyforge-api --policy configs/my-policy.yaml
```

Audit records and evidence bundles are written automatically to `artifacts/` for every evaluation.

> **Tip:** Start with `requires_approval: true` on all production resources until you've validated your role definitions. You can always loosen the policy once you've reviewed a few audit log entries.

---

## CLI Reference

```
go run ./cmd/policyforge [flags]
```

| Flag            | Default                    | Description                                                             |
|-----------------|----------------------------|-------------------------------------------------------------------------|
| `--policy`      | `configs/policy.yaml`      | Path to the policy YAML file                                            |
| `--input`       | *(none)*                   | Path to a JSON request file. Overrides all individual request flags.    |
| `--subject`     | *(required if no --input)* | Identity making the request                                             |
| `--role`        | *(required if no --input)* | Role assigned to the subject                                            |
| `--resource`    | *(required if no --input)* | Resource being accessed                                                 |
| `--action`      | *(required if no --input)* | Action being performed                                                  |
| `--tier`        | *(required if no --input)* | Requested safety tier                                                   |
| `--auto-approve`| `false`                    | Converts a `require_approval` decision to `allow`                       |
| `--agent`       | *(none)*                   | Agent envelope name to apply on top of RBAC                             |

### Using flags directly

```bash
go run ./cmd/policyforge \
  --policy ./configs/policy.yaml \
  --subject alice \
  --role auditor \
  --resource prod/api-gateway \
  --action read \
  --tier read_only
```

### Using a JSON input file (recommended for scripting)

```bash
go run ./cmd/policyforge --policy ./configs/policy.yaml --input ./examples/request.json
```

### When required fields are missing

```
2026/04/04 18:31:31 invalid CLI request: missing required request fields: subject, resource, action, requested_tier
```

---

## Agent Policy Envelopes

An **agent** is a non-human identity — a remediation bot, CI pipeline, AI system, or any automated workflow. Because agents act autonomously, they operate inside a **policy envelope** that further restricts what they may do, on top of normal RBAC.

If a request includes an `agent` field, **both** the role-based checks and the envelope checks must pass. Failing either returns a `deny` or `require_approval`.

### Envelope definition

Envelopes live in `configs/policy.yaml` under `agent_envelopes`:

```yaml
agent_envelopes:
  - name: "remediation-bot"
    allowed_resources:
      - "staging/*"          # wildcard: matches any staging/ resource
    allowed_actions:
      - "read"
      - "restart"
    max_tier: "autonomous_write"
    session_ttl_minutes: 30

  - name: "prod-operator-bot"
    allowed_resources:
      - "prod/payment-service"
    allowed_actions:
      - "read"
    max_tier: "read_only"
    session_ttl_minutes: 15
```

`allowed_resources` supports `prefix/*` wildcard patterns. `max_tier` caps the envelope independently of the role's own cap.

### CLI usage

```bash
# allow: remediation-bot restarts staging resource within its envelope
go run ./cmd/policyforge \
  --policy ./configs/policy.yaml \
  --subject bot \
  --role operator \
  --resource staging/payment-service \
  --action restart \
  --tier read_only \
  --agent remediation-bot
```

```json
{
  "decision": "allow",
  "reasons": ["allow: all policy checks passed"],
  "timestamp": "2026-04-05T00:25:51Z",
  "request_id": "req-1775348751231064000",
  "matched_resource": "staging/payment-service",
  "evaluated_role": "operator"
}
```

```bash
# deny: remediation-bot tries to access a prod resource (outside its staging/* envelope)
go run ./cmd/policyforge \
  --policy ./configs/policy.yaml \
  --subject bot \
  --role operator \
  --resource prod/payment-service \
  --action read \
  --tier read_only \
  --agent remediation-bot
```

```json
{
  "decision": "deny",
  "reasons": ["deny: agent 'remediation-bot' is not allowed to access resource 'prod/payment-service'"],
  "timestamp": "2026-04-05T00:25:51Z",
  "request_id": "req-1775348751288228000",
  "matched_resource": "prod/payment-service",
  "evaluated_role": "operator"
}
```

```bash
# deny: prod-operator-bot tries to restart (only 'read' is in its envelope)
go run ./cmd/policyforge \
  --policy ./configs/policy.yaml \
  --subject bot \
  --role operator \
  --resource prod/payment-service \
  --action restart \
  --tier read_only \
  --agent prod-operator-bot
```

```json
{
  "decision": "deny",
  "reasons": ["deny: agent 'prod-operator-bot' cannot perform action 'restart'"],
  "timestamp": "2026-04-05T00:26:04Z",
  "request_id": "req-1775348764835152000",
  "matched_resource": "prod/payment-service",
  "evaluated_role": "operator"
}
```

### API usage

Include `agent` in the JSON body:

```bash
curl -X POST http://localhost:8080/evaluate \
  -H "Content-Type: application/json" \
  -d '{
    "subject": "bot",
    "role": "operator",
    "resource": "staging/payment-service",
    "action": "restart",
    "requested_tier": "read_only",
    "agent": "remediation-bot"
  }'
```

### Using a JSON input file

```bash
go run ./cmd/policyforge --policy ./configs/policy.yaml --input ./examples/request-agent.json
```

---

## REST API

PolicyForge ships a second entrypoint, `cmd/policyforge-api`, that exposes the same evaluation logic over HTTP.

### Start the server

```bash
go run ./cmd/policyforge-api --policy ./configs/policy.yaml
# 2026/04/05 00:06:36 policyforge-api listening on :8080
```

Or with a custom address:

```bash
go run ./cmd/policyforge-api --addr :9090
```

### Endpoints

| Method | Path        | Description                              |
|--------|-------------|------------------------------------------|
| `GET`  | `/health`   | Returns `{"status":"ok"}` when ready     |
| `POST` | `/evaluate` | Evaluates a decision request             |

### POST /evaluate

Request body is the same schema as a JSON input file:

```bash
curl -X POST http://localhost:8080/evaluate \
  -H "Content-Type: application/json" \
  -d '{
    "subject": "chris",
    "role": "operator",
    "resource": "prod/payment-service",
    "action": "restart",
    "requested_tier": "supervised_write"
  }'
```

```json
{
  "decision": "require_approval",
  "reasons": [
    "approval: resource 'prod/payment-service' requires approval",
    "approval: tier 'supervised_write' requires approval"
  ],
  "timestamp": "2026-04-05T00:06:38Z",
  "request_id": "req-1775347598162694000",
  "matched_resource": "prod/payment-service",
  "evaluated_role": "operator"
}
```

Pass `?auto_approve=true` to convert a `require_approval` decision to `allow`:

```bash
curl -X POST "http://localhost:8080/evaluate?auto_approve=true" \
  -H "Content-Type: application/json" \
  -d '{"subject":"chris","role":"operator","resource":"prod/payment-service","action":"restart","requested_tier":"supervised_write"}'
```

Every API request produces an audit log entry and evidence bundle, identical to the CLI.

---

## Policy Configuration

Policies are defined in `configs/policy.yaml`. The file has three sections.

### Safety Tiers

Tiers define the level of automation. Each tier can optionally require approval.

```yaml
safety_tiers:
  - name: "read_only"
    requires_approval: false   # read operations, no approval needed
  - name: "supervised_write"
    requires_approval: true    # writes require human sign-off
  - name: "autonomous_write"
    requires_approval: false   # fully automated, granted to admins only
```

### Roles

Each role defines what actions, tiers, and resources it can access. `max_tier` caps the automation level a role can use autonomously — requesting above it triggers `require_approval` regardless of other tier settings.

```yaml
roles:
  - name: "admin"
    allowed_actions: ["read", "write", "restart", "scale"]
    allowed_tiers:   ["read_only", "supervised_write", "autonomous_write"]
    max_tier:        "autonomous_write"
    allowed_resources:
      - "prod/payment-service"
      - "prod/api-gateway"
      - "staging/payment-service"

  - name: "operator"
    allowed_actions: ["read", "restart", "scale"]
    allowed_tiers:   ["read_only", "supervised_write"]
    max_tier:        "supervised_write"
    allowed_resources:
      - "prod/payment-service"
      - "staging/payment-service"

  - name: "auditor"
    allowed_actions: ["read"]
    allowed_tiers:   ["read_only"]
    max_tier:        "read_only"
    allowed_resources:
      - "prod/payment-service"
      - "prod/api-gateway"
      - "staging/payment-service"

  - name: "viewer"
    allowed_actions: ["read"]
    allowed_tiers:   ["read_only"]
    max_tier:        "read_only"
    allowed_resources:
      - "staging/payment-service"
```

### Resources

Resources declare which infrastructure targets exist, and whether accessing them inherently requires approval.

```yaml
resources:
  - name: "prod/payment-service"
    requires_approval: true    # production — always require approval
  - name: "prod/api-gateway"
    requires_approval: true    # production — always require approval
  - name: "staging/payment-service"
    requires_approval: false   # staging — safe to allow directly
```

---

## Decision Logic

The engine evaluates every request against the same deterministic sequence of checks. The first failing check stops evaluation and returns immediately.

| # | Check | Failing outcome |
|---|-------|-----------------|
| 1 | Role exists in policy | `deny` |
| 2 | Action is in role's `allowed_actions` | `deny` |
| 3 | Resource exists in policy | `deny` |
| 4 | Resource is in role's `allowed_resources` | `deny` |
| 5 | Requested tier exists in policy | `deny` |
| 6 | Requested tier is in role's `allowed_tiers` | `deny` |
| 7 | Requested tier does not exceed role's `max_tier` | `require_approval` |
| 8 | Agent envelope: exists, resource allowed, action allowed, tier ≤ max | `deny` / `require_approval` |
| 9 | Resource `requires_approval: false` and tier `requires_approval: false` | `require_approval` |
| — | All checks pass | `allow` |

**Reason messages are structured** so they are easy to parse:
- `deny: ...` for hard failures
- `approval: ...` for soft gates
- `allow: ...` for clean passes

---

## Decision Response Schema

Every response is a JSON object printed to stdout:

```json
{
  "decision": "allow | deny | require_approval",
  "reasons": ["structured reason message"],
  "timestamp": "2026-04-04T23:41:52Z",
  "request_id": "req-1775346112600030000",
  "matched_resource": "staging/payment-service",
  "evaluated_role": "viewer"
}
```

| Field              | Description                                      |
|--------------------|--------------------------------------------------|
| `decision`         | Outcome: `allow`, `deny`, or `require_approval`  |
| `reasons`          | Ordered list explaining the decision             |
| `timestamp`        | RFC3339 UTC time the decision was made           |
| `request_id`       | Unique ID for this evaluation (also in audit log)|
| `matched_resource` | Resource name resolved from policy               |
| `evaluated_role`   | Role name resolved from policy                   |

### Scenario outputs

**Scenario A — allow** (`examples/request-allow.json`):
Viewer reads staging payment service with `read_only` tier.

```json
{
  "decision": "allow",
  "reasons": [
    "allow: all policy checks passed"
  ],
  "timestamp": "2026-04-04T23:41:52Z",
  "request_id": "req-1775346112600030000",
  "matched_resource": "staging/payment-service",
  "evaluated_role": "viewer"
}
```

**Scenario B — deny** (`examples/request-deny-action.json`):
Viewer attempts restart, which is not in their `allowed_actions`.

```json
{
  "decision": "deny",
  "reasons": [
    "deny: action 'restart' is not allowed for role 'viewer'"
  ],
  "timestamp": "2026-04-04T23:41:52Z",
  "request_id": "req-1775346112640457000",
  "matched_resource": "staging/payment-service",
  "evaluated_role": "viewer"
}
```

**Scenario C — require_approval + auto-approve** (`examples/request-require-approval.json` with `--auto-approve`):
Operator restarts prod payment service via `supervised_write`. Both resource and tier require approval. `--auto-approve` converts the decision to `allow`.

```json
{
  "decision": "allow",
  "reasons": [
    "approval: resource 'prod/payment-service' requires approval",
    "approval: tier 'supervised_write' requires approval",
    "auto-approved via CLI flag"
  ],
  "timestamp": "2026-04-04T23:41:52Z",
  "request_id": "req-1775346112679835000",
  "matched_resource": "prod/payment-service",
  "evaluated_role": "operator"
}
```

---

## Audit Logging

Every evaluation — regardless of outcome — is appended to `artifacts/audit.jsonl` in [JSON Lines](https://jsonlines.org/) format. The directory is created automatically.

Each line is a single JSON object:

```jsonl
{"request_id":"req-1775346112600030000","timestamp":"2026-04-04T23:41:52Z","subject":"alex","role":"viewer","resource":"staging/payment-service","action":"read","decision":"allow","reasons":["allow: all policy checks passed"]}
{"request_id":"req-1775346112640457000","timestamp":"2026-04-04T23:41:52Z","subject":"pat","role":"viewer","resource":"staging/payment-service","action":"restart","decision":"deny","reasons":["deny: action 'restart' is not allowed for role 'viewer'"]}
```

Each record includes a `hash` (SHA-256 of the key fields) and a `previous_hash` that chains each entry to the one before it. This makes undetected modification of the log difficult — any change to a record invalidates its hash and breaks the chain.

The audit log is append-only. It is never overwritten by the CLI or API. To query it:

```bash
# view the last 10 decisions
tail -n 10 artifacts/audit.jsonl

# filter for denials only
grep '"decision":"deny"' artifacts/audit.jsonl

# filter for a specific subject
grep '"subject":"chris"' artifacts/audit.jsonl

# pretty-print a single entry
tail -n 1 artifacts/audit.jsonl | jq .
```

---

## Evidence Bundles

Every evaluation — CLI or API — writes a compliance-ready JSON file to `artifacts/evidence/<bundle_id>.json`. The directory is created automatically.

Each bundle captures the full context of the decision:

```json
{
  "bundle_id": "ev_1775347598163202000_97651",
  "request_id": "req-1775347598162694000",
  "timestamp": "2026-04-05T00:06:38Z",
  "decision": "require_approval",
  "subject": "chris",
  "role": "operator",
  "resource": "prod/payment-service",
  "action": "restart",
  "requested_tier": "supervised_write",
  "reasons": [
    "approval: resource 'prod/payment-service' requires approval",
    "approval: tier 'supervised_write' requires approval"
  ],
  "controls": [
    "PCI-DSS-7.2",
    "PCI-DSS-10.2"
  ]
}
```

### Compliance controls

Controls are mapped automatically from the request context:

| Condition | Control |
|---|---|
| Resource path contains `prod` | `PCI-DSS-7.2` |
| Action is `restart`, `write`, or `scale` | `PCI-DSS-10.2` |
| Decision is `deny` | `SECURITY-ENFORCEMENT` |

---

## Approval Persistence

When a request evaluates to `require_approval`, PolicyForge now creates a persisted approval record in `artifacts/approvals.json`. This turns the soft gate into a real workflow — you can list pending approvals, approve them, or reject them.

### How it works

1. A `require_approval` decision creates a record with `status: pending`
2. `--auto-approve` creates the record with `status: approved` immediately
3. A human reviewer uses `--approve-id` or `--reject-id` to resolve it

### Submit a request that requires approval

```bash
go run ./cmd/policyforge \
  --policy ./configs/policy.yaml \
  --input ./examples/request-require-approval.json
```

```
Approval required — approval ID: apr-1775349830126355000
{
  "decision": "require_approval",
  ...
}
```

### List pending approvals

```bash
go run ./cmd/policyforge --list-approvals
# or:
make approvals
```

```json
[
  {
    "approval_id": "apr-1775349830126355000",
    "request_id": "req-1775349830121985000",
    "status": "pending",
    "subject": "chris",
    "role": "operator",
    "resource": "prod/payment-service",
    "action": "restart",
    "requested_tier": "supervised_write",
    "reasons": ["approval: resource 'prod/payment-service' requires approval"],
    "requested_at": "2026-04-05T00:06:38Z"
  }
]
```

### Approve a request

```bash
go run ./cmd/policyforge \
  --approve-id apr-1775349830126355000 \
  --decided-by chris \
  --decision-note "approved for emergency maintenance"
```

```json
{"approved": "apr-1775349830126355000", "decided_by": "chris"}
```

### Reject a request

```bash
go run ./cmd/policyforge \
  --reject-id apr-1775349830126355000 \
  --decided-by security-team \
  --decision-note "insufficient justification"
```

Approval records are stored in `artifacts/approvals.json` and are linked to their evidence bundles via `approval_id`.

---

## Drift Detection

Drift detection re-evaluates every record in the audit log against the **current** policy. If a request was previously `allow`ed but today's policy would `deny` or `require_approval` it, that's a finding.

This answers the question: *"Has our policy tightened since these decisions were made? Are there any past actions that would no longer be permitted?"*

### Run drift detection

```bash
go run ./cmd/policyforge \
  --policy ./configs/policy.yaml \
  --drift-check
# or:
make drift
```

Findings are written to `artifacts/drift/findings.json` and printed to stdout.

### No drift found

```json
{"findings": [], "summary": "no drift detected"}
```

### Drift findings example

```json
[
  {
    "finding_id": "drift-1775349830126355000",
    "timestamp": "2026-04-05T01:00:00Z",
    "request_id": "req-1775346112600030000",
    "subject": "alice",
    "role": "viewer",
    "resource": "staging/payment-service",
    "action": "restart",
    "requested_tier": "read_only",
    "observed_decision": "allow",
    "expected_decision": "deny",
    "severity": "high",
    "drift_type": "unauthorized_action",
    "message": "request was allowed but current policy would deny: deny: action 'restart' is not allowed for role 'viewer'"
  }
]
```

### Drift types

| `drift_type` | Meaning |
|---|---|
| `decision_mismatch` | Policy outcome changed but no specific violation |
| `unauthorized_resource_access` | Role no longer allowed to access this resource |
| `unauthorized_action` | Action no longer in role's `allowed_actions` |
| `agent_envelope_violation` | Agent envelope no longer permits the action/resource |
| `tier_exceeded` | Tier request exceeds current role `max_tier` |

### Severity

| Severity | Condition |
|---|---|
| `high` | Was `allow`, current policy would `deny` |
| `medium` | Was `allow`, current policy would `require_approval` |
| `low` | Any other mismatch |

---

## Approval Flow

When a decision is `require_approval` the CLI prints a notification line before the JSON:

```
Approval required
{ ... }
```

Pass `--auto-approve` to immediately convert the decision to `allow` and append the reason `auto-approved via CLI flag` to the response. The audit log records the final outcome (`allow`), preserving all original approval reasons alongside it.

```bash
go run ./cmd/policyforge \
  --policy ./configs/policy.yaml \
  --input ./examples/request-require-approval.json \
  --auto-approve
```

---

## Project Structure

```
policyforge/
├── cmd/
│   ├── policyforge/
│   │   └── main.go             # CLI entry point
│   └── policyforge-api/
│       ├── main.go             # HTTP API entry point
│       └── handler_test.go     # API handler tests
├── internal/
│   ├── approval/
│   │   ├── types.go            # Approval status constants and Record struct
│   │   ├── store.go            # JSON-backed approval CRUD with atomic writes
│   │   └── store_test.go       # Approval store tests
│   ├── audit/
│   │   └── logger.go           # Append-only JSONL audit writer with hash chain
│   ├── compliance/
│   │   └── mapping.go          # Compliance control mapping (PCI-DSS etc.)
│   ├── config/
│   │   ├── load.go             # YAML policy loader with validation
│   │   ├── request.go          # JSON request loader with field validation
│   │   └── request_test.go     # Request loader tests
│   ├── drift/
│   │   ├── types.go            # DriftType, Severity constants and Finding struct
│   │   ├── detector.go         # Re-evaluate audit log and detect policy drift
│   │   └── detector_test.go    # Drift detector tests
│   ├── evidence/
│   │   ├── bundle.go           # Evidence bundle generation with CSV index
│   │   └── bundle_test.go      # Evidence bundle tests
│   ├── policy/
│   │   ├── engine.go           # Deterministic evaluation engine
│   │   └── engine_test.go      # Table-driven engine tests
│   ├── service/
│   │   └── evaluator.go        # Shared evaluation pipeline (CLI + API parity)
│   └── types/
│       └── types.go            # Shared domain types
├── configs/
│   └── policy.yaml             # Default policy definition
├── examples/
│   ├── request.json
│   ├── request-allow.json
│   ├── request-deny-action.json
│   ├── request-require-approval.json
│   └── request-agent.json               # Scenario: agent envelope
├── artifacts/
│   ├── audit.jsonl             # Decision audit log (auto-created, gitignored)
│   ├── approvals.json          # Pending/decided approvals (auto-created, gitignored)
│   ├── drift/
│   │   └── findings.json       # Drift findings from last run (auto-created, gitignored)
│   └── evidence/               # Evidence bundles (auto-created, gitignored)
│       └── index.csv           # CSV index of all evidence bundles
├── Makefile
├── go.mod
├── go.sum
├── demo.tape                   # VHS tape — core evaluation demo
├── demo-approvals.tape         # VHS tape — approval workflow + drift demo
├── demo.gif                    # Animated terminal demo
├── LICENSE
└── README.md
```

---

## Development

### Run tests

```bash
go test ./...          # all packages
go test ./... -v       # verbose output
go test -cover ./...   # with coverage
```

### Start the API server

```bash
make api
# go run ./cmd/policyforge-api
```

### Build binaries

```bash
make build
# produces bin/policyforge and bin/policyforge-api
```

Or directly:

```bash
go build -o bin/policyforge ./cmd/policyforge
go build -o bin/policyforge-api ./cmd/policyforge-api
```

### Format and vet

```bash
go fmt ./...
go vet ./...
```

### Re-record the demos

Requires [VHS](https://github.com/charmbracelet/vhs) (`brew install vhs`):

```bash
make demo             # vhs demo.tape            → artifacts/demo.gif
make demo-approvals   # vhs demo-approvals.tape  → artifacts/demo-approvals.gif
```

| Tape | What it shows |
|------|--------------|
| `demo.tape` | Core evaluation: allow, deny, require\_approval (auto), agent deny, audit log, evidence bundle |
| `demo-approvals.tape` | Approval workflow + drift detection: submit → list → approve → drift check |

### Testing strategy

All logic is covered by table-driven tests in `internal/policy/engine_test.go` and `internal/config/request_test.go`. When adding new engine checks or policy fields, add a corresponding test case before committing.

---

## Dependencies

- [`gopkg.in/yaml.v3`](https://pkg.go.dev/gopkg.in/yaml.v3) — YAML parsing

---

## License

MIT License. See [LICENSE](LICENSE).
