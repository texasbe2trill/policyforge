.PHONY: build run test test-verbose test-coverage clean help

# Build the CLI binary
build:
	@mkdir -p artifacts
	go build -o artifacts/policyforge ./cmd/policyforge
	@echo "Binary built: artifacts/policyforge"

# Run the CLI with default policy and request
run:
	go run ./cmd/policyforge

# Run with custom policy and request
run-custom:
	go run ./cmd/policyforge -policy $(POLICY) -request $(REQUEST)

# Run all tests
test:
	go test ./...

# Run tests with verbose output
test-verbose:
	go test ./... -v

# Run tests with coverage report
test-coverage:
	go test -cover ./...

# Run tests and generate coverage HTML report
test-coverage-html:
	go test -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"

# Format code
fmt:
	go fmt ./...

# Run go vet for static analysis
vet:
	go vet ./...

# Lint code (requires golangci-lint)
lint:
	golangci-lint run ./...

# Clean build artifacts
clean:
	rm -f artifacts/policyforge
	rm -f coverage.out coverage.html
	go clean

# Display help
help:
	@echo "Available targets:"
	@echo "  make build              - Build the policyforge binary"
	@echo "  make run                - Run policyforge with default config"
	@echo "  make run-custom          - Run with POLICY and REQUEST env vars"
	@echo "  make test               - Run all tests"
	@echo "  make test-verbose       - Run tests with verbose output"
	@echo "  make test-coverage      - Run tests with coverage report"
	@echo "  make test-coverage-html - Generate HTML coverage report"
	@echo "  make fmt                - Format code"
	@echo "  make vet                - Run go vet"
	@echo "  make lint               - Run golangci-lint (if installed)"
	@echo "  make clean              - Remove build artifacts"
	@echo "  make help               - Display this message"
