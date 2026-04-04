.PHONY: run test build lint

run:
	go run ./cmd/policyforge

test:
	go test ./...

build:
	@mkdir -p bin
	go build -o bin/policyforge ./cmd/policyforge

lint:
	@echo "lint target placeholder"
