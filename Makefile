.PHONY: run api api-auth run-api-debug-oidc test build lint demo demo-approvals demo-auth demo-cli demo-api drift approvals sessions version fmt vet

run:
	go run ./cmd/policyforge

api:
	go run ./cmd/policyforge-api --policy ./configs/policy.yaml

api-auth:
	go run ./cmd/policyforge-api --policy ./configs/policy.yaml --tokens ./configs/tokens.yaml

run-api-debug-oidc:
	POLICYFORGE_ENABLE_DEBUG_OIDC=true go run ./cmd/policyforge-api --policy ./configs/policy.yaml --tokens ./configs/tokens.yaml

test:
	go test ./...

build:
	@mkdir -p bin
	go build -o bin/policyforge ./cmd/policyforge
	go build -o bin/policyforge-api ./cmd/policyforge-api

demo:
	vhs demo.tape

demo-approvals:
	vhs demo-approvals.tape

demo-auth:
	vhs demo-auth.tape

lint:
	go vet ./...
	gofmt -l . | (! grep .)

drift:
	go run ./cmd/policyforge --policy ./configs/policy.yaml --drift-check

approvals:
	go run ./cmd/policyforge --list-approvals

sessions:
	go run ./cmd/policyforge --list-sessions

demo-cli:
	bash scripts/demo.sh

demo-api:
	bash scripts/demo-api.sh

version:
	@go run ./cmd/policyforge --version

fmt:
	gofmt -w .

vet:
	go vet ./...
