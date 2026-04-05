.PHONY: run api test build lint demo

run:
	go run ./cmd/policyforge

api:
	go run ./cmd/policyforge-api

test:
	go test ./...

build:
	@mkdir -p bin
	go build -o bin/policyforge ./cmd/policyforge
	go build -o bin/policyforge-api ./cmd/policyforge-api

demo:
	go build -o bin/policyforge ./cmd/policyforge
	vhs demo.tape

lint:
	@echo "lint target placeholder"
