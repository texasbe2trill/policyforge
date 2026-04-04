# PolicyForge

[![Go Version](https://img.shields.io/badge/go-1.26%2B-00ADD8?logo=go)](https://go.dev/)
[![Tests](https://img.shields.io/badge/tests-go%20test%20.%2F...-0A7BBB)](#running-tests)
[![License: MIT](https://img.shields.io/badge/license-MIT-yellow.svg)](LICENSE)

PolicyForge is a Go-based policy enforcement and compliance evidence engine for infrastructure workflows. It evaluates requests against YAML-defined policy rules and returns decisions (allow, deny, or require_approval).

## Overview

PolicyForge enables infrastructure teams to:
- Define flexible, role-based access policies in YAML
- Enforce safety tiers (read_only, supervised_write, autonomous_write) for actions
- Return clear, auditable decision reasons for every request
- Integrate policy evaluation into deployment and operational workflows

## Architecture

The project is organized into clean, focused packages:

- **cmd/policyforge**: CLI entry point that loads policies and evaluates requests
- **internal/types**: Core domain types (Policy, Role, Resource, SafetyTier, Decision, etc.)
- **internal/config**: Policy loading and parsing from YAML files
- **internal/policy**: Policy evaluation engine with deterministic decision logic

## Project Structure

```
policyforge/
├── cmd/policyforge/        # CLI binary
├── internal/
│   ├── config/             # YAML config loading
│   ├── policy/             # Decision engine & tests
│   └── types/              # Domain types
├── configs/                # Policy configuration files
├── examples/               # Example requests
├── artifacts/              # Build outputs (gitignored)
├── Makefile                # Build automation
├── go.mod / go.sum         # Dependency management
└── README.md               # This file
```

## Quick Start

### Prerequisites

- Go 1.26 or later
- Make (optional, but recommended)

### Running the CLI

Evaluate a request against the policy:

```bash
go run ./cmd/policyforge
```

With custom policy and request files:

```bash
go run ./cmd/policyforge -policy ./configs/policy.yaml -request ./examples/request.json
```

If the request file is missing, the CLI falls back to a built-in sample request.

### Running Tests

Run all unit tests:

```bash
go test ./...
```

Run with verbose output:

```bash
go test ./... -v
```

Run with coverage:

```bash
go test -cover ./...
```

### Building

Build the binary:

```bash
make build
```

Or using go directly:

```bash
go build -o artifacts/policyforge ./cmd/policyforge
```

## Policy Configuration

Policies are defined in YAML with three main sections:

### Safety Tiers

Define the automation levels available:

```yaml
safety_tiers:
  - name: "read_only"
    requires_approval: false
  - name: "supervised_write"
    requires_approval: true
  - name: "autonomous_write"
    requires_approval: false
```

### Roles

Define user roles with their capabilities:

```yaml
roles:
  - name: "operator"
    allowed_actions:
      - "read"
      - "restart"
    allowed_tiers:
      - "read_only"
      - "supervised_write"
    allowed_resources:
      - "prod/payment-service"
```

### Resources

Define infrastructure resources and their policies:

```yaml
resources:
  - name: "prod/payment-service"
    requires_approval: true
```

## Decision Logic

The engine evaluates requests deterministically in this order:

1. **Role exists**: Deny if role not found in policy
2. **Action allowed**: Deny if action not in role's allowed_actions
3. **Resource exists**: Deny if resource not found in policy
4. **Role allowed for resource**: Deny if resource not in role's allowed_resources
5. **Tier exists**: Deny if tier not found in policy
6. **Tier allowed for role**: Deny if tier not in role's allowed_tiers
7. **Approval requirements**: Require approval if resource or tier requires it
8. **Allow**: Allow if all checks pass and no approval is required

## Decision Response

Decisions include a decision status and reasons:

```json
{
  "decision": "allow|deny|require_approval",
  "reasons": ["reason 1", "reason 2"]
}
```

## Example Usage

### Input Request (examples/request.json)

```json
{
  "subject": "chris",
  "role": "operator",
  "resource": "prod/payment-service",
  "action": "restart",
  "requested_tier": "supervised_write"
}
```

### Output Decision

```json
{
  "decision": "require_approval",
  "reasons": [
    "resource 'prod/payment-service' requires approval",
    "tier 'supervised_write' requires approval"
  ]
}
```

## Development

### Code Style

- Idiomatic Go style
- Small, focused functions
- Explicit error handling
- No global state

### Testing Strategy

All logic changes should include unit tests using table-driven test patterns:

```bash
go test ./... -v
```

## Dependencies

- `gopkg.in/yaml.v3`: YAML parsing library

## License

MIT License. See [LICENSE](LICENSE).
