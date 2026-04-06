#!/usr/bin/env bash
set -euo pipefail

# PolicyForge API Demo Script
# Starts the API server, runs evaluation scenarios, then shuts down.

command -v jq >/dev/null 2>&1 || { echo "Error: jq is required but not installed. Install with: brew install jq" >&2; exit 1; }

POLICY="./configs/policy.yaml"
TOKENS="./configs/tokens.yaml"
ADDR="127.0.0.1:18080"
API_URL="http://${ADDR}"

section() {
  echo ""
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo "  $1"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo ""
}

# ── Clean artifacts for a fresh run ─────────────────────────────────────────
rm -f artifacts/audit.jsonl artifacts/approvals.json artifacts/sessions.json
rm -rf artifacts/evidence artifacts/drift

# ── Build and start server ──────────────────────────────────────────────────
section "Starting API server"
go build -o /tmp/policyforge-api-demo ./cmd/policyforge-api
/tmp/policyforge-api-demo --policy "$POLICY" --tokens "$TOKENS" --addr "$ADDR" &
API_PID=$!
trap "kill $API_PID 2>/dev/null; rm -f /tmp/policyforge-api-demo" EXIT

# Wait for server to be ready
for i in $(seq 1 30); do
  if curl -sf "${API_URL}/health" > /dev/null 2>&1; then
    echo "Server ready on ${ADDR}"
    break
  fi
  if [ "$i" -eq 30 ]; then
    echo "Server failed to start" >&2
    exit 1
  fi
  sleep 0.2
done

# ── Health check ───────────────────────────────────────────────────────────
section "Health Check"
curl -sf "${API_URL}/health" | jq .

# ── Unauthenticated request (should fail) ─────────────────────────────────
section "Unauthenticated Request (401 expected)"
curl -sf -w "\nHTTP %{http_code}\n" "${API_URL}/evaluate" \
  -H "Content-Type: application/json" \
  -d '{"resource":"staging/payment-service","action":"read","requested_tier":"read_only"}' \
  || true

# ── Authenticated allow ───────────────────────────────────────────────────
section "Authenticated Allow — admin reads staging"
curl -sf "${API_URL}/evaluate" \
  -H "Authorization: Bearer dev-admin-token" \
  -H "Content-Type: application/json" \
  -d '{"resource":"staging/payment-service","action":"read","requested_tier":"read_only"}' \
  | jq .

# ── Authenticated require_approval ────────────────────────────────────────
section "Require Approval — operator restarts prod"
curl -sf "${API_URL}/evaluate" \
  -H "Authorization: Bearer operator-token" \
  -H "Content-Type: application/json" \
  -d '{"resource":"prod/payment-service","action":"restart","requested_tier":"supervised_write"}' \
  | jq .

# ── Auto-approve via query param ──────────────────────────────────────────
section "Auto-Approve via Query Param"
curl -sf "${API_URL}/evaluate?auto_approve=true" \
  -H "Authorization: Bearer operator-token" \
  -H "Content-Type: application/json" \
  -d '{"resource":"prod/payment-service","action":"restart","requested_tier":"supervised_write"}' \
  | jq .

# ── Agent envelope ────────────────────────────────────────────────────────
section "Agent Envelope — remediation-bot via token"
curl -sf "${API_URL}/evaluate" \
  -H "Authorization: Bearer agent-remediation-token" \
  -H "Content-Type: application/json" \
  -d '{"resource":"staging/payment-service","action":"restart","requested_tier":"read_only"}' \
  | jq .

# ── Session list ──────────────────────────────────────────────────────────
section "Session List (admin only)"
curl -sf "${API_URL}/sessions" \
  -H "Authorization: Bearer dev-admin-token" \
  | jq .

# ── Done ──────────────────────────────────────────────────────────────────
section "Demo complete"
echo "Server PID: ${API_PID}"
echo "Artifacts written to artifacts/"
echo "Shutting down..."
