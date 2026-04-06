# Contributing to PolicyForge

Thanks for your interest in contributing. PolicyForge is a security-focused policy engine — contributions that improve correctness, clarity, and auditability are especially welcome.

## Getting Started

```bash
git clone https://github.com/texasbe2trill/policyforge.git
cd policyforge
go test ./...
```

Requires Go 1.26+.

## Development Workflow

1. Fork the repository and create a feature branch from `main`.
2. Make your changes in small, focused commits.
3. Run `make lint` and `make test` before pushing.
4. Open a pull request against `main`.

## Code Style

- Follow standard Go conventions (`gofmt`, `go vet`).
- Keep packages small and focused — one responsibility per package.
- Use table-driven tests.
- Structured reason messages: `deny: ...`, `approval: ...`, `allow: ...`.

## Testing

All changes must pass existing tests and include tests for new functionality:

```bash
go test ./...          # run all tests
go test -cover ./...   # with coverage
make lint              # vet + format check
```

## What to Contribute

- Bug fixes with a failing test case
- New compliance control mappings in `internal/compliance/mapping.go`
- Additional policy pack examples in `examples/policy-packs/`
- Documentation improvements
- Security hardening

## What to Avoid

- Introducing external dependencies without discussion
- Breaking changes to the decision response schema
- Removing or weakening audit log integrity (hash chaining)
- Adding features that bypass policy evaluation

## Security Issues

If you discover a security vulnerability, **do not open a public issue**. See [SECURITY.md](SECURITY.md) for responsible disclosure instructions.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
