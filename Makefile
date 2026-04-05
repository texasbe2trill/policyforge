.PHONY: run api test build lint demo drift approvals

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
	vhs demo.tape

lint:
	go vet ./...
	gofmt -l . | (! grep .)

drift:
	go run ./cmd/policyforge --policy ./configs/policy.yaml --drift-check

approvals:
	go run ./cmd/policyforge --list-approvals
